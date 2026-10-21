import tomllib
from pathlib import Path

from cti_automator.cli import build_parser, main
from cti_automator.config import Settings
from cti_automator.mcp_server import create_mcp_server

ROOT = Path(__file__).resolve().parents[1]


def project_metadata() -> dict[str, object]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    return dict(data["project"])  # type: ignore[arg-type]


def test_project_metadata_is_release_ready() -> None:
    metadata = project_metadata()
    assert metadata["license"] == {"text": "MIT"}
    assert (ROOT / "LICENSE").is_file()
    assert "PyYAML>=6.0,<7.0" in metadata["dependencies"]
    assert metadata["scripts"] == {"cti-automator": "cti_automator.cli:main"}
    classifiers = metadata["classifiers"]
    assert any("3.13" in item for item in classifiers)
    urls = metadata["urls"]
    assert {"Homepage", "Repository", "Issues"} <= set(urls)


def test_pypi_workflow_uses_trusted_publishing_with_environments() -> None:
    workflow = (ROOT / ".github" / "workflows" / "pypi.yml").read_text()
    assert "pypa/gh-action-pypi-publish" in workflow
    assert "id-token: write" in workflow
    assert "attest-build-provenance" in workflow
    assert "testpypi" in workflow
    assert workflow.count("environment:") >= 1


def test_detections_gitops_gate_exists() -> None:
    workflow = (ROOT / ".github" / "workflows" / "detections.yml").read_text()
    assert "validate-detections" in workflow
    assert "pull_request" in workflow


def test_cli_parser_defines_phase_ten_to_fourteen_commands() -> None:
    parser = build_parser()
    assert (
        parser.parse_args(["generate-detections", "r.pdf"]).command
        == "generate-detections"
    )
    args = parser.parse_args(["generate-detections", "r.pdf", "--pr-repo", "acme/d"])
    assert args.pr_repo == "acme/d"
    assert args.formats == ["yara", "sigma"]
    assert (
        parser.parse_args(["validate-detections", "d/"]).command
        == "validate-detections"
    )
    assert parser.parse_args(["memory-remember", "r.pdf"]).command == "memory-remember"
    recall = parser.parse_args(["memory-recall", "query", "--limit", "3"])
    assert recall.limit == 3
    case = parser.parse_args(
        ["create-secops-case", "r.pdf", "--destination", "thehive", "--dry-run"]
    )
    assert case.destination == "thehive"
    assert case.dry_run
    chat = parser.parse_args(["notify-chatops", "r.pdf", "--destination", "soc"])
    assert chat.destination == "soc"


def test_memory_disabled_reports_clear_cli_error(capsys) -> None:
    exit_code = main(["memory-recall", "anything"])
    assert exit_code == 2
    assert "CTI_MEMORY_ENABLED" in capsys.readouterr().err


def test_secops_missing_credentials_reports_clear_cli_error(
    monkeypatch, capsys
) -> None:
    from unittest.mock import Mock

    from cti_automator.models import PDFAnalysis

    analyzer = Mock()
    analyzer.analyze.return_value = PDFAnalysis(summary="s", source_document="r.pdf")
    monkeypatch.setattr("cti_automator.cli.PDFAnalyzer", Mock(return_value=analyzer))
    exit_code = main(["create-secops-case", "missing.pdf", "--destination", "thehive"])
    assert exit_code == 2
    assert "CTI_THEHIVE_URL" in capsys.readouterr().err


def test_mcp_server_registers_new_tools() -> None:
    server = create_mcp_server(Settings())
    assert server is not None
