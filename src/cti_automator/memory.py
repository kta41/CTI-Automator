"""Historical intelligence memory with an injectable Qdrant vector store."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

import requests
from pydantic import BaseModel, ConfigDict, Field

from cti_automator.config import Settings
from cti_automator.exceptions import MemoryStoreError
from cti_automator.models import PDFAnalysis
from cti_automator.observability import observe
from cti_automator.sanitizer import Sanitizer

_MEMORY_NAMESPACE = "cti-automator memory v1"


class EmbeddingClient(Protocol):
    """Contract for local or explicitly authorized remote embeddings."""

    def embed(self, text: str) -> list[float]:
        """Return one embedding vector for a text chunk."""


class VectorStore(Protocol):
    """Contract implemented by the Qdrant REST adapter and test doubles."""

    def upsert(self, collection: str, points: Sequence[VectorPoint]) -> None: ...

    def search(
        self,
        collection: str,
        vector: Sequence[float],
        *,
        limit: int,
        tenant: str,
    ) -> tuple[VectorMatch, ...]: ...

    def delete_older(self, collection: str, tenant: str, before: datetime) -> int: ...


class VectorPoint(BaseModel):
    """One stored memory point; payload only carries sanitized content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    vector: tuple[float, ...]
    payload: dict[str, object]


class VectorMatch(BaseModel):
    """One retrieval hit; its text is untrusted data for consumers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    score: float = Field(ge=0)
    payload: dict[str, object]


class OllamaEmbeddingClient:
    """Local embeddings through Ollama; no data leaves the host."""

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
    ) -> None:
        self._settings = settings
        self._session = session or requests.Session()

    def embed(self, text: str) -> list[float]:
        """Generate one local embedding or fail explicitly."""
        if not text.strip():
            raise MemoryStoreError("embedding text cannot be empty")
        try:
            response = self._session.post(
                f"{self._settings.ollama_base_url}/api/embeddings",
                json={
                    "model": self._settings.memory_embedding_model,
                    "prompt": text,
                },
                timeout=self._settings.request_timeout,
                verify=self._settings.verify_tls,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise MemoryStoreError("Local embedding request failed") from exc
        except ValueError as exc:
            raise MemoryStoreError("Local embedding returned invalid JSON") from exc
        vector = payload.get("embedding") if isinstance(payload, dict) else None
        if (
            not isinstance(vector, list)
            or not vector
            or not all(isinstance(value, (int, float)) for value in vector)
        ):
            raise MemoryStoreError("Local embedding returned an invalid vector")
        return [float(value) for value in vector]


class RemoteEmbeddingClient:
    """OpenAI-compatible embeddings, enabled only via CTI_MEMORY_REMOTE_EMBEDDINGS."""

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
    ) -> None:
        self._settings = settings
        self._session = session or requests.Session()

    def embed(self, text: str) -> list[float]:
        """Generate one hosted embedding using the explicitly opted-in provider."""
        if not text.strip():
            raise MemoryStoreError("embedding text cannot be empty")
        try:
            response = self._session.post(
                f"{self._settings.ai_base_url}/embeddings",
                headers={
                    "Authorization": f"Bearer {self._settings.require_ai_api_key()}",
                    "Content-Type": "application/json",
                },
                json={"model": self._settings.memory_embedding_model, "input": text},
                timeout=self._settings.request_timeout,
                verify=self._settings.verify_tls,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise MemoryStoreError("Remote embedding request failed") from exc
        except ValueError as exc:
            raise MemoryStoreError("Remote embedding returned invalid JSON") from exc
        data = payload.get("data") if isinstance(payload, dict) else None
        vector = (
            data[0].get("embedding")
            if isinstance(data, list) and data and isinstance(data[0], dict)
            else None
        )
        if (
            not isinstance(vector, list)
            or not vector
            or not all(isinstance(value, (int, float)) for value in vector)
        ):
            raise MemoryStoreError("Remote embedding returned an invalid vector")
        return [float(value) for value in vector]


class QdrantVectorStore:
    """Qdrant REST adapter with timeouts, tenant filters and bounded deletes."""

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
    ) -> None:
        self._settings = settings
        self._session = session or requests.Session()

    def _call(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        accepted: tuple[int, ...] = (200, 201),
    ) -> dict[str, object]:
        try:
            response = self._session.request(
                method,
                f"{self._settings.memory_url}{path}",
                json=json_body,
                timeout=self._settings.request_timeout,
                verify=self._settings.verify_tls,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise MemoryStoreError("Memory store request failed") from exc
        if response.status_code not in accepted:
            raise MemoryStoreError("Memory store rejected the request")
        try:
            payload: object = response.json()
        except ValueError as exc:
            raise MemoryStoreError("Memory store returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise MemoryStoreError("Memory store returned a non-object response")
        return payload

    def ensure_collection(self, collection: str) -> None:
        """Create the collection when missing; vector size is provider dependent."""
        self._call(
            "PUT",
            f"/collections/{collection}",
            json_body={"vectors": {"size": 0, "distance": "Cosine"}},
        )

    def upsert(self, collection: str, points: Sequence[VectorPoint]) -> None:
        self._call(
            "PUT",
            f"/collections/{collection}/points",
            json_body={
                "points": [
                    {
                        "id": point.id,
                        "vector": list(point.vector),
                        "payload": point.payload,
                    }
                    for point in points
                ]
            },
        )

    def search(
        self,
        collection: str,
        vector: Sequence[float],
        *,
        limit: int,
        tenant: str,
    ) -> tuple[VectorMatch, ...]:
        payload = self._call(
            "POST",
            f"/collections/{collection}/points/search",
            json_body={
                "vector": list(vector),
                "limit": limit,
                "with_payload": True,
                "filter": {"must": [{"key": "tenant", "match": {"value": tenant}}]},
            },
        )
        hits = payload.get("result")
        if not isinstance(hits, list):
            raise MemoryStoreError("Memory store returned invalid search results")
        matches: list[VectorMatch] = []
        for hit in hits:
            if not isinstance(hit, dict):
                raise MemoryStoreError("Memory store returned an invalid hit")
            score = hit.get("score")
            point_id = hit.get("id")
            if not isinstance(score, (int, float)) or not isinstance(point_id, str):
                raise MemoryStoreError("Memory store hit is missing score or id")
            raw_payload = hit.get("payload", {})
            if not isinstance(raw_payload, dict):
                raise MemoryStoreError("Memory store hit has invalid payload")
            matches.append(
                VectorMatch(id=point_id, score=float(score), payload=dict(raw_payload))
            )
        return tuple(matches)

    def delete_older(self, collection: str, tenant: str, before: datetime) -> int:
        counted = self._call(
            "POST",
            f"/collections/{collection}/points/scroll",
            json_body={
                "limit": 1000,
                "with_payload": False,
                "filter": {
                    "must": [
                        {"key": "tenant", "match": {"value": tenant}},
                        {
                            "key": "created_at",
                            "range": {"lt": before.astimezone(UTC).isoformat()},
                        },
                    ]
                },
            },
        )
        result = counted.get("result")
        points = result.get("points") if isinstance(result, dict) else None
        if not isinstance(points, list):
            raise MemoryStoreError("Memory store returned invalid scroll data")
        ids = [
            point["id"]
            for point in points
            if isinstance(point, dict) and isinstance(point.get("id"), str)
        ]
        if not ids:
            return 0
        self._call(
            "POST",
            f"/collections/{collection}/points/delete",
            json_body={"points": ids},
        )
        return len(ids)


class MemoryFragment(BaseModel):
    """One retrieved memory fragment with provenance for citation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fragment_id: str
    text: str
    source_document: str
    techniques: tuple[str, ...] = ()
    created_at: str
    score: float = Field(ge=0)


class MemoryWriteResult(BaseModel):
    """Outcome of remembering one analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stored: int = Field(ge=0)
    duplicates: int = Field(ge=0)


def chunk_text(text: str, *, max_chars: int = 800) -> tuple[str, ...]:
    """Split text into bounded paragraph-preserving chunks."""
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text) if part.strip()]
    chunks: list[str] = []
    current = ""
    for paragraph in paragraphs:
        candidate = f"{current}\n{paragraph}".strip() if current else paragraph
        if len(candidate) <= max_chars:
            current = candidate
            continue
        if current:
            chunks.append(current)
        while len(paragraph) > max_chars:
            chunks.append(paragraph[:max_chars])
            paragraph = paragraph[max_chars:].strip()
        current = paragraph
    if current:
        chunks.append(current)
    return tuple(chunks)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class MemoryService:
    """Remember and recall analyses with tenant isolation and DLP enforcement."""

    def __init__(
        self,
        settings: Settings,
        *,
        embeddings: EmbeddingClient | None = None,
        store: VectorStore | None = None,
        sanitizer: Sanitizer | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self._settings = settings
        self._embeddings = embeddings or (
            RemoteEmbeddingClient(settings, session=session)
            if settings.memory_remote_embeddings
            else OllamaEmbeddingClient(settings, session=session)
        )
        self._store = store or QdrantVectorStore(settings, session=session)
        self._sanitizer = sanitizer or Sanitizer.from_settings(settings)

    def _require_enabled(self) -> None:
        if not self._settings.memory_enabled:
            raise MemoryStoreError(
                "Historical memory is disabled; set CTI_MEMORY_ENABLED=true"
            )

    @observe("memory")
    def remember(self, analysis: PDFAnalysis) -> MemoryWriteResult:
        """Store sanitized chunks of one analysis with deterministic point ids."""
        self._require_enabled()
        techniques = tuple(ttp.technique_id for ttp in analysis.ttps)
        created_at = datetime.now(UTC).isoformat()
        chunks = chunk_text(analysis.summary)
        chunks += tuple(
            f"{ttp.technique_id} {ttp.technique_name}: {ttp.rationale} "
            f"Evidence: {ttp.evidence}"
            for ttp in analysis.ttps
        )
        seen: set[str] = set()
        points: list[VectorPoint] = []
        duplicates = 0
        for index, raw in enumerate(chunks):
            sanitized = self._sanitizer.sanitize(raw)
            digest = _digest(sanitized.text)
            if digest in seen:
                duplicates += 1
                continue
            seen.add(digest)
            point_id = str(
                uuid5(
                    NAMESPACE_URL,
                    f"{_MEMORY_NAMESPACE}|{self._settings.memory_tenant}"
                    f"|{analysis.source_document}|{index}|{digest}",
                )
            )
            points.append(
                VectorPoint(
                    id=point_id,
                    vector=tuple(self._embeddings.embed(sanitized.text)),
                    payload={
                        "tenant": self._settings.memory_tenant,
                        "source_document": analysis.source_document,
                        "chunk_index": index,
                        "digest": digest,
                        "techniques": list(techniques),
                        "created_at": created_at,
                        "text": sanitized.text,
                    },
                )
            )
        self._store.upsert(self._settings.memory_collection, points)
        return MemoryWriteResult(stored=len(points), duplicates=duplicates)

    @observe("memory")
    def recall(self, query: str, *, limit: int = 5) -> tuple[MemoryFragment, ...]:
        """Retrieve cited fragments for a query within the configured tenant."""
        self._require_enabled()
        if not query.strip():
            raise ValueError("memory query cannot be empty")
        if not 1 <= limit <= 25:
            raise ValueError("memory recall limit must be between 1 and 25")
        sanitized = self._sanitizer.sanitize(query)
        vector = self._embeddings.embed(sanitized.text)
        matches = self._store.search(
            self._settings.memory_collection,
            vector,
            limit=limit,
            tenant=self._settings.memory_tenant,
        )
        fragments: list[MemoryFragment] = []
        for match in matches:
            payload = match.payload
            text = payload.get("text")
            source = payload.get("source_document")
            if not isinstance(text, str) or not isinstance(source, str):
                raise MemoryStoreError("Memory fragment payload is invalid")
            techniques = payload.get("techniques", [])
            created = payload.get("created_at", "")
            fragments.append(
                MemoryFragment(
                    fragment_id=match.id,
                    text=text,
                    source_document=source,
                    techniques=tuple(techniques)
                    if isinstance(techniques, list)
                    else (),
                    created_at=created if isinstance(created, str) else "",
                    score=match.score,
                )
            )
        return tuple(fragments)

    @observe("memory")
    def forget(self) -> int:
        """Apply the configured retention window for the current tenant."""
        self._require_enabled()
        before = datetime.now(UTC) - timedelta(
            days=self._settings.memory_retention_days
        )
        return self._store.delete_older(
            self._settings.memory_collection, self._settings.memory_tenant, before
        )
