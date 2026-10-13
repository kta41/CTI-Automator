import base64
import hashlib
import json
from unittest.mock import Mock

import pytest
import requests
from filelock import FileLock

from cti_automator.config import Settings
from cti_automator.exceptions import ConnectorError
from cti_automator.repositories import Checkpoint, RepositoryClient, RepositoryIngestor

REPO = "authorized/reports"
COMMIT = "a" * 40
CONTENT = b"# Threat report\nPublic indicators."
DIGEST = hashlib.sha1(f"blob {len(CONTENT)}\0".encode() + CONTENT).hexdigest()


def entry(path="reports/report.md", content=CONTENT):
    digest = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
    return {
        "path": path,
        "sha": digest,
        "size": len(content),
        "mode": "100644",
        "type": "blob",
    }


def fake_response(payload):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.iter_content.return_value = [json.dumps(payload).encode()]
    context = Mock()
    context.__enter__ = Mock(return_value=response)
    context.__exit__ = Mock(return_value=False)
    return context


def client(tmp_path, entries=None, blob=None):
    session = Mock(spec=requests.Session)
    session.get.side_effect = [
        fake_response({"sha": COMMIT}),
        fake_response({"tree": entries if entries is not None else [entry()]}),
        fake_response(
            blob
            or {"encoding": "base64", "content": base64.b64encode(CONTENT).decode()}
        ),
    ]
    settings = Settings(
        repository_allowlist=(REPO,), repository_checkpoint=str(tmp_path / "state.json")
    )
    return RepositoryClient(settings, session=session), session


def test_allowlist_blocks_before_network(tmp_path):
    source, session = client(tmp_path)
    with pytest.raises(ValueError, match="ALLOWLIST"):
        list(source.documents("unauthorized/repo", Checkpoint()))
    session.get.assert_not_called()


def test_provenance_and_text_only_filters(tmp_path):
    source, session = client(
        tmp_path,
        entries=[
            entry("samples/malware.exe"),
            entry("samples/code.txt"),
            entry("docs/samples/code.txt"),
            entry("samples/README.md"),
            {**entry("reports/link.md"), "mode": "120000"},
            entry(),
        ],
    )
    documents = list(source.documents(REPO, Checkpoint()))
    assert len(documents) == 1
    assert documents[0].commit == COMMIT
    assert documents[0].digest == DIGEST
    assert COMMIT in documents[0].reference
    assert documents[0].text == CONTENT.decode()
    assert session.get.call_count == 3


def test_checkpoint_and_dedup_prevent_repeat_fetch(tmp_path):
    source, session = client(tmp_path)
    ingestor = RepositoryIngestor(source.settings, source)
    process = Mock()
    assert len(ingestor.run(process)) == 1
    checkpoint = Checkpoint.model_validate_json((tmp_path / "state.json").read_text())
    assert checkpoint.completed == {f"{REPO}:reports/report.md": DIGEST}
    source, session = client(tmp_path, entries=[entry(), entry("reports/copy.md")])
    assert RepositoryIngestor(source.settings, source).run(process) == ()
    assert process.call_count == 1
    assert session.get.call_count == 2


def test_failed_delivery_is_not_checkpointed_and_can_resume(tmp_path):
    source, _ = client(tmp_path)
    with pytest.raises(RuntimeError):
        RepositoryIngestor(source.settings, source).run(
            Mock(side_effect=RuntimeError("delivery failed"))
        )
    assert not (tmp_path / "state.json").exists()
    source, _ = client(tmp_path)
    assert len(RepositoryIngestor(source.settings, source).run(Mock())) == 1


def test_parallel_ingestion_has_explicit_lock_failure(tmp_path):
    source, session = client(tmp_path)
    with (
        FileLock(str(tmp_path / "state.json") + ".lock"),
        pytest.raises(ConnectorError, match="already running"),
    ):
        RepositoryIngestor(source.settings, source).run(Mock())
    session.get.assert_not_called()


def test_size_limit_is_checked_before_blob_download(tmp_path):
    source, session = client(tmp_path, entries=[{**entry(), "size": 2_000_000}])
    with pytest.raises(ConnectorError, match="byte limit"):
        list(source.documents(REPO, Checkpoint()))
    assert session.get.call_count == 2


@pytest.mark.parametrize(
    "blob",
    [
        {"encoding": "utf8", "content": "bad"},
        {"encoding": "base64", "content": "!invalid!"},
        {"encoding": "base64", "content": base64.b64encode(b"changed").decode()},
    ],
)
def test_formats_and_integrity_are_validated(tmp_path, blob):
    source, _ = client(tmp_path, blob=blob)
    with pytest.raises(ConnectorError):
        list(source.documents(REPO, Checkpoint()))


def test_truncated_tree_is_explicit_error_not_silent_partial_success(tmp_path):
    source, session = client(tmp_path)
    session.get.side_effect = [
        fake_response({"sha": COMMIT}),
        fake_response({"truncated": True}),
    ]
    with pytest.raises(ConnectorError, match="truncated"):
        list(source.documents(REPO, Checkpoint()))


def test_partial_success_is_saved_before_a_later_failure(tmp_path):
    source, session = client(
        tmp_path, entries=[entry(), entry("reports/second.md", b"second")]
    )
    session.get.side_effect = [
        fake_response({"sha": COMMIT}),
        fake_response({"tree": [entry(), entry("reports/second.md", b"second")]}),
        fake_response(
            {"encoding": "base64", "content": base64.b64encode(CONTENT).decode()}
        ),
        requests.Timeout("failed"),
    ]
    with pytest.raises(ConnectorError):
        RepositoryIngestor(source.settings, source).run(Mock())
    state = Checkpoint.model_validate_json((tmp_path / "state.json").read_text())
    assert state.completed == {f"{REPO}:reports/report.md": DIGEST}


def test_file_budget_leaves_remaining_documents_for_next_execution(tmp_path):
    source, session = client(
        tmp_path, entries=[entry(), entry("reports/second.md", b"second")]
    )
    source.settings = source.settings.model_copy(update={"repository_max_files": 1})
    assert len(list(source.documents(REPO, Checkpoint()))) == 1
    assert session.get.call_count == 3


def test_report_size_at_exact_limit_is_accepted(tmp_path):
    source, _ = client(tmp_path)
    source.settings = source.settings.model_copy(
        update={"repository_max_bytes": len(CONTENT)}
    )
    assert len(list(source.documents(REPO, Checkpoint()))) == 1


def test_analysis_artifact_and_provenance_exist_before_checkpoint(
    tmp_path, monkeypatch
):
    from cti_automator.models import (
        Indicator,
        IndicatorType,
        IntelligenceSource,
        PDFAnalysis,
    )
    from cti_automator.repositories import ingest_repository_reports

    source, _ = client(tmp_path)
    monkeypatch.setattr(
        "cti_automator.repositories.RepositoryClient", Mock(return_value=source)
    )
    analyzer = Mock()
    analyzer.analyze_text.return_value = PDFAnalysis(
        summary="Validated analysis",
        source_document="report",
        indicators=(
            Indicator(
                value="8.8.8.8",
                indicator_type=IndicatorType.IPV4,
                source=IntelligenceSource.PDF_REPORT,
            ),
        ),
    )
    monkeypatch.setattr(
        "cti_automator.repositories.PDFAnalyzer", Mock(return_value=analyzer)
    )
    analyses = ingest_repository_reports(source.settings)
    result = analyses[0]
    assert result.indicators[0].source == IntelligenceSource.REPOSITORY
    assert COMMIT in result.source_document
    assert result.indicators[0].raw_data["digest"] == DIGEST
    artifact = tmp_path / "state.results" / f"{DIGEST}.json"
    assert PDFAnalysis.model_validate_json(artifact.read_text()) == result
    assert artifact.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "state.json").exists()
