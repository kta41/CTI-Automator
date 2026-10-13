"""Allowlisted GitHub report ingestion; never fetch or execute malware samples."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import requests
from filelock import FileLock, Timeout
from pydantic import BaseModel, ConfigDict, Field

from cti_automator.analyzer import PDFAnalyzer
from cti_automator.config import Settings
from cti_automator.exceptions import ConnectorError
from cti_automator.exporters import OpenCTIExporter
from cti_automator.models import IntelligenceSource, PDFAnalysis
from cti_automator.observability import observe


class RepositoryDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    repository: str
    path: str
    commit: str
    digest: str
    reference: str
    fetched_at: datetime
    text: str = Field(min_length=1)


class Checkpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    completed: dict[str, str] = Field(default_factory=dict)


class RepositoryClient:
    def __init__(
        self, settings: Settings, session: requests.Session | None = None
    ) -> None:
        self.settings = settings
        self.session = session or requests.Session()

    def _json(self, endpoint: str) -> dict[str, object]:
        headers = {"Accept": "application/vnd.github+json"}
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"
        try:
            with self.session.get(
                f"https://api.github.com/{endpoint}",
                headers=headers,
                timeout=self.settings.request_timeout,
                verify=self.settings.verify_tls,
                allow_redirects=False,
                stream=True,
            ) as response:
                response.raise_for_status()
                if response.status_code != 200:
                    raise ConnectorError("Repository returned unexpected HTTP status")
                body = bytearray()
                for chunk in response.iter_content(8192):
                    body.extend(chunk)
                    if len(body) > 2_000_000:
                        raise ConnectorError(
                            "Repository metadata exceeds response limit"
                        )
            payload = json.loads(body)
        except requests.RequestException as exc:
            raise ConnectorError("Repository request failed") from exc
        except (ValueError, UnicodeError) as exc:
            raise ConnectorError("Repository returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ConnectorError("Repository returned non-object metadata")
        return payload

    def documents(
        self, repository: str, checkpoint: Checkpoint
    ) -> Iterator[RepositoryDocument]:
        if repository not in self.settings.repository_allowlist or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
        ):
            raise ValueError("Repository is not in CTI_REPOSITORY_ALLOWLIST")
        commit = self._json(f"repos/{repository}/commits/HEAD").get("sha")
        if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise ConnectorError("Repository returned an invalid commit SHA")
        tree = self._json(f"repos/{repository}/git/trees/{commit}?recursive=1")
        if tree.get("truncated"):
            raise ConnectorError(
                "Repository tree is truncated; narrow the source repository"
            )
        entries = tree.get("tree")
        if not isinstance(entries, list):
            raise ConnectorError("Repository tree is missing entries")
        seen: set[str] = set(checkpoint.completed.values())
        count = 0
        for entry in entries:
            if not isinstance(entry, dict):
                raise ConnectorError("Repository returned invalid tree entry")
            path = entry.get("path")
            if not isinstance(path, str):
                raise ConnectorError("Repository entry is missing a path")
            file = PurePosixPath(path)
            allowed = (
                file.suffix.lower() in {".md", ".txt", ".rst"}
                and (
                    path.startswith(("reports/", "docs/"))
                    or path.lower() == "readme.md"
                )
                and not set(file.parts[:-1])
                & {"samples", "binaries", "bin", "payloads"}
                and ".." not in file.parts
                and not file.is_absolute()
                and entry.get("mode") == "100644"
                and entry.get("type") == "blob"
            )
            if not allowed:
                continue
            size = entry.get("size")
            digest = entry.get("sha")
            if (
                not isinstance(size, int)
                or not isinstance(digest, str)
                or not re.fullmatch(r"[a-f0-9]{40}", digest)
            ):
                raise ConnectorError("Repository returned invalid report metadata")
            if size > self.settings.repository_max_bytes:
                raise ConnectorError("Repository report exceeds configured byte limit")
            if (
                digest in seen
                or checkpoint.completed.get(f"{repository}:{path}") == digest
            ):
                continue
            if count >= self.settings.repository_max_files:
                break
            blob = self._json(f"repos/{repository}/git/blobs/{digest}")
            content = blob.get("content")
            if blob.get("encoding") != "base64" or not isinstance(content, str):
                raise ConnectorError("Repository report has an unsupported encoding")
            try:
                raw = base64.b64decode("".join(content.splitlines()), validate=True)
                text = raw.decode("utf-8")
            except (ValueError, UnicodeError) as exc:
                raise ConnectorError("Repository report is not UTF-8 text") from exc
            actual = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
            if (
                actual != digest
                or len(raw) != size
                or len(raw) > self.settings.repository_max_bytes
            ):
                raise ConnectorError(
                    "Repository report integrity or size validation failed"
                )
            if not text.strip() or "\0" in text:
                raise ConnectorError("Repository report is empty or binary")
            seen.add(digest)
            count += 1
            yield RepositoryDocument(
                repository=repository,
                path=path,
                commit=commit,
                digest=digest,
                reference=f"https://github.com/{repository}/blob/{commit}/{quote(path, safe='/')}",
                fetched_at=datetime.now(UTC),
                text=text,
            )


class RepositoryIngestor:
    def __init__(
        self, settings: Settings, client: RepositoryClient | None = None
    ) -> None:
        self.settings = settings
        self.client = client or RepositoryClient(settings)

    @observe("repository")
    def run(
        self,
        process: Callable[[RepositoryDocument], None],
    ) -> tuple[str, ...]:
        if not self.settings.repository_allowlist:
            raise ValueError(
                "CTI_REPOSITORY_ALLOWLIST is required for repository ingestion"
            )
        path = Path(self.settings.repository_checkpoint)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with FileLock(str(path) + ".lock", timeout=1):
                return self._run_locked(path, process)
        except Timeout as exc:
            raise ConnectorError("Repository ingestion is already running") from exc

    def _run_locked(
        self,
        path: Path,
        process: Callable[[RepositoryDocument], None],
    ) -> tuple[str, ...]:
        checkpoint = (
            Checkpoint.model_validate_json(path.read_text())
            if path.exists()
            else Checkpoint()
        )
        processed: list[str] = []
        for repository in self.settings.repository_allowlist:
            for document in self.client.documents(repository, checkpoint):
                process(document)
                checkpoint.completed[f"{repository}:{document.path}"] = document.digest
                self._save(path, checkpoint)
                processed.append(document.reference)
        return tuple(processed)

    @staticmethod
    def _save(path: Path, payload: BaseModel) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".checkpoint-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload.model_dump_json())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def ingest_repository_reports(
    settings: Settings, *, opencti: bool = False
) -> tuple[PDFAnalysis, ...]:
    """Checkpoint only after analysis and requested delivery have succeeded."""
    exporter = OpenCTIExporter(settings) if opencti else None
    analyzer = PDFAnalyzer(settings)
    analyses: list[PDFAnalysis] = []

    def process(document: RepositoryDocument) -> None:
        analysis = analyzer.analyze_text(document.text, document.reference)
        indicators = tuple(
            item.model_copy(
                update={
                    "source": IntelligenceSource.REPOSITORY,
                    "source_id": document.reference,
                    "raw_data": {
                        "repository": document.repository,
                        "commit": document.commit,
                        "path": document.path,
                        "digest": document.digest,
                        "fetched_at": document.fetched_at.isoformat(),
                    },
                }
            )
            for item in analysis.indicators
        )
        analysis = analysis.model_copy(
            update={"indicators": indicators, "source_document": document.reference}
        )
        if exporter:
            exporter.export_analysis(analysis)
        artifact = (
            Path(settings.repository_checkpoint).with_suffix(".results")
            / f"{document.digest}.json"
        )
        RepositoryIngestor._save(artifact, analysis)
        analyses.append(analysis)

    RepositoryIngestor(settings).run(process)
    return tuple(analyses)
