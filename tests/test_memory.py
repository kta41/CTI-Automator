from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
import requests

import cti_automator.sanitizer as sanitizer_module
from cti_automator.config import Settings
from cti_automator.exceptions import MemoryStoreError
from cti_automator.memory import (
    MemoryService,
    QdrantVectorStore,
    VectorMatch,
    VectorPoint,
    chunk_text,
)
from cti_automator.models import (
    Indicator,
    IndicatorType,
    IntelligenceSource,
    PDFAnalysis,
    TTPMapping,
)

SanitizationPolicy = sanitizer_module.SanitizationPolicy
Sanitizer = sanitizer_module.Sanitizer


def analysis() -> PDFAnalysis:
    return PDFAnalysis(
        summary="Campaign summary.\n\nSecond paragraph about infrastructure.",
        source_document="report.pdf",
        indicators=(
            Indicator(
                value="evil.example",
                indicator_type=IndicatorType.DOMAIN,
                source=IntelligenceSource.PDF_REPORT,
            ),
        ),
        ttps=(
            TTPMapping(
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                tactic="Command and Control",
                rationale="Beaconing behavior",
                evidence="http beacon every 30s",
                confidence=70,
            ),
        ),
    )


class FakeEmbeddings:
    def __init__(self) -> None:
        self.seen: list[str] = []

    def embed(self, text: str) -> list[float]:
        self.seen.append(text)
        return [float(len(text)), 1.0]


class FakeStore:
    def __init__(self) -> None:
        self.points: dict[str, VectorPoint] = {}
        self.deleted: list[str] = []

    def upsert(self, collection: str, points: Sequence[VectorPoint]) -> None:
        for point in points:
            self.points[point.id] = point

    def search(
        self, collection: str, vector: Sequence[float], *, limit: int, tenant: str
    ) -> tuple[VectorMatch, ...]:
        matches = [
            VectorMatch(id=point.id, score=1.0, payload=point.payload)
            for point in self.points.values()
            if point.payload.get("tenant") == tenant
        ]
        return tuple(matches[:limit])

    def delete_older(self, collection: str, tenant: str, before: datetime) -> int:
        stale = [
            point.id
            for point in self.points.values()
            if point.payload.get("tenant") == tenant
            and point.payload.get("created_at", "") < before.isoformat()
        ]
        for identifier in stale:
            self.deleted.append(identifier)
            del self.points[identifier]
        return len(stale)


def service(
    **overrides: object,
) -> tuple[MemoryService, FakeEmbeddings, FakeStore]:
    settings = Settings(memory_enabled=True, **overrides)  # type: ignore[arg-type]
    embeddings = FakeEmbeddings()
    store = FakeStore()
    return (
        MemoryService(settings, embeddings=embeddings, store=store),
        embeddings,
        store,
    )


def test_memory_is_disabled_by_default_and_fails_explicitly() -> None:
    embeddings = FakeEmbeddings()
    store = FakeStore()
    memory = MemoryService(Settings(), embeddings=embeddings, store=store)
    with pytest.raises(MemoryStoreError, match="CTI_MEMORY_ENABLED"):
        memory.remember(analysis())
    with pytest.raises(MemoryStoreError, match="CTI_MEMORY_ENABLED"):
        memory.recall("query")
    assert not embeddings.seen
    assert not store.points


def test_remember_stores_chunks_with_provenance() -> None:
    memory, embeddings, store = service()
    result = memory.remember(analysis())
    assert result.stored == 2  # one summary chunk + one TTP chunk
    assert result.duplicates == 0
    point = next(iter(store.points.values()))
    assert point.payload["tenant"] == "default"
    assert point.payload["source_document"] == "report.pdf"
    assert point.payload["techniques"] == ["T1071"]
    assert len(embeddings.seen) == 2


def test_remember_is_idempotent_for_identical_analysis() -> None:
    memory, _, store = service()
    memory.remember(analysis())
    first = set(store.points)
    result = memory.remember(analysis())
    assert set(store.points) == first
    assert result.stored == 2


def test_dlp_policy_applies_before_embeddings() -> None:
    settings = Settings(
        memory_enabled=True,
        dlp_enabled=True,
        dlp_email_domains=("corp.example",),
    )
    embeddings = FakeEmbeddings()
    store = FakeStore()
    sanitizer = Sanitizer(SanitizationPolicy(email_domains=("corp.example",)))
    memory = MemoryService(
        settings, embeddings=embeddings, store=store, sanitizer=sanitizer
    )
    report = analysis().model_copy(
        update={"summary": "Contact bob@corp.example for incident details."}
    )
    memory.remember(report)
    assert embeddings.seen
    for embedded in embeddings.seen:
        assert "corp.example" not in embedded
    for point in store.points.values():
        assert "corp.example" not in str(point.payload["text"])


def test_recall_is_tenant_isolated_and_bounded() -> None:
    memory, _, _ = service(memory_tenant="tenant-a")
    memory.remember(analysis())
    other, _, other_store = service(memory_tenant="tenant-b")
    fragments = other.recall("campaign")
    assert fragments == ()
    own = memory.recall("campaign", limit=1)
    assert len(own) == 1
    assert own[0].source_document == "report.pdf"
    assert own[0].techniques == ("T1071",)
    assert other_store.points == {}


def test_recall_validates_query_and_limit() -> None:
    memory, _, _ = service()
    with pytest.raises(ValueError):
        memory.recall("   ")
    with pytest.raises(ValueError):
        memory.recall("query", limit=26)


def test_forget_applies_retention_window() -> None:
    memory, _, store = service(memory_retention_days=30)
    memory.remember(analysis())
    aged_at = (datetime.now(UTC) - timedelta(days=31)).isoformat()
    for identifier in list(store.points):
        point = store.points[identifier]
        store.points[identifier] = point.model_copy(
            update={"payload": {**point.payload, "created_at": aged_at}}
        )
    deleted = memory.forget()
    assert deleted == len(store.deleted)
    assert not store.points


def test_chunk_text_bounds_chunk_sizes() -> None:
    long_text = "\n\n".join(f"paragraph {index}" for index in range(200))
    chunks = chunk_text(long_text, max_chars=100)
    assert chunks
    assert all(len(chunk) <= 100 for chunk in chunks)


def test_qdrant_store_maps_rest_errors() -> None:
    session = Mock(spec=requests.Session)
    failure = Mock(spec=requests.Response)
    failure.status_code = 500
    session.request.return_value = failure
    store = QdrantVectorStore(Settings(memory_url="http://localhost:6333"), session)
    with pytest.raises(MemoryStoreError):
        store.upsert("collection", ())
