from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import requests
from starlette.testclient import TestClient

from cti_automator.analyzer import PDFAnalyzer, resolve_authorized_path
from cti_automator.cli import build_parser, main
from cti_automator.config import Settings
from cti_automator.doctor import (
    OLLAMA_RECOMMENDED_VERSION,
    OPENCTI_RECOMMENDED_VERSION,
    QDRANT_RECOMMENDED_VERSION,
    THEHIVE_RECOMMENDED_VERSION,
    run_doctor,
)
from cti_automator.exceptions import DocumentExtractionError
from cti_automator.exporters.stix import STIXExporter
from cti_automator.models import (
    Indicator,
    IndicatorType,
    IntelligenceSource,
    PDFAnalysis,
    TTPMapping,
)
from cti_automator.parsers.pdf import PDFTextExtractor
from cti_automator.stack import (
    build_stack_up_plan,
    execute_stack_down,
    execute_stack_up,
)
from cti_automator.ui import create_ui_app, is_loopback_host


def test_doctor_reports_recommended_versions_and_install_proposals() -> None:
    session = Mock(spec=requests.Session)
    session.get.side_effect = requests.ConnectionError("offline")
    report = run_doctor(Settings(), session=session)
    assert report.healthy is False
    by_name = {svc.service: svc for svc in report.services}
    assert by_name["opencti"].recommended_version == OPENCTI_RECOMMENDED_VERSION
    assert by_name["opencti"].status == "missing"
    assert "opencti/platform:6.9.29" in (by_name["opencti"].install_proposal or "")
    assert by_name["thehive"].recommended_version == THEHIVE_RECOMMENDED_VERSION
    assert "strangebee/thehive:5.5.0-1" in (by_name["thehive"].install_proposal or "")
    assert by_name["ollama"].recommended_version == OLLAMA_RECOMMENDED_VERSION
    assert by_name["qdrant"].recommended_version == QDRANT_RECOMMENDED_VERSION


def test_doctor_detects_running_local_services() -> None:
    session = Mock(spec=requests.Session)

    def fake_get(url: str, **kwargs: Any) -> Any:
        resp = Mock(spec=requests.Response)
        resp.status_code = 200
        if "8080" in url:
            resp.json.return_value = {"version": OPENCTI_RECOMMENDED_VERSION}
        elif "9000" in url:
            resp.json.return_value = {"versions": {"TheHive": THEHIVE_RECOMMENDED_VERSION}}
        else:
            resp.json.return_value = {"version": OLLAMA_RECOMMENDED_VERSION}
        return resp

    session.get.side_effect = fake_get
    report = run_doctor(
        Settings(
            opencti_url="http://127.0.0.1:8080",
            thehive_url="http://127.0.0.1:9000",
            memory_enabled=True,
        ),
        session=session,
    )
    assert report.healthy is True
    assert all(svc.status == "ok" for svc in report.services)


def test_cli_doctor_and_memory_forget_commands(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    parser = build_parser()
    assert parser.parse_args(["doctor"]).command == "doctor"
    assert parser.parse_args(["memory-forget"]).command == "memory-forget"
    assert parser.parse_args(["ui", "--port", "8085"]).port == 8085

    session = Mock(spec=requests.Session)
    session.get.side_effect = requests.ConnectionError("offline")
    monkeypatch.setattr(
        "cti_automator.cli.run_doctor",
        lambda settings: run_doctor(settings, session=session),
    )
    assert main(["doctor"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["healthy"] is False
    assert len(out["services"]) == 4


def test_pdf_analysis_artifact_and_sha256_cache_avoid_repeated_llm_calls(
    tmp_path: Path,
) -> None:
    pdf_file = tmp_path / "sample.pdf"
    pdf_file.write_bytes(b"%PDF-1.4 fake bytes")
    cache_dir = tmp_path / "cache"
    calls = 0

    class CountingExtractor:
        def extract(self, path: Path) -> str:
            return "Report text with 10.10.1.5 and 8.8.8.8"

    class CountingLLM:
        def generate_json(self, prompt: str) -> dict[str, Any]:
            nonlocal calls
            calls += 1
            return {
                "summary": "Cached summary",
                "indicators": [
                    {
                        "value": "<CTI_IP_1>",
                        "indicator_type": "ipv4-addr",
                        "source": "pdf-report",
                    },
                    {
                        "value": "10.10.1.5",
                        "indicator_type": "ipv4-addr",
                        "source": "pdf-report",
                    },
                    {
                        "value": "8.8.8.8",
                        "indicator_type": "ipv4-addr",
                        "source": "pdf-report",
                    },
                ],
                "ttps": [],
            }

    settings = Settings(
        analysis_cache_dir=str(cache_dir),
        dlp_enabled=True,
        dlp_internal_cidrs=("10.0.0.0/8",),
    )
    analyzer = PDFAnalyzer(
        settings,
        extractor=CountingExtractor(),  # type: ignore[arg-type]
        ollama=CountingLLM(),  # type: ignore[arg-type]
    )
    first = analyzer.analyze(pdf_file)
    second = analyzer.analyze(pdf_file)
    assert calls == 1
    assert first == second
    assert [i.value for i in first.indicators] == ["8.8.8.8"]

    artifact_file = tmp_path / "saved.analysis.json"
    artifact_file.write_text(first.model_dump_json(), encoding="utf-8")
    loaded = analyzer.analyze(artifact_file)
    assert loaded == first
    assert calls == 1


def test_pdf_extractor_enforces_byte_limit(tmp_path: Path) -> None:
    oversized = tmp_path / "big.pdf"
    oversized.write_bytes(b"%PDF-1.4" + b"0" * 200)
    extractor = PDFTextExtractor(max_bytes=50)
    with pytest.raises(DocumentExtractionError, match="byte limit"):
        extractor.extract(oversized)


def test_resolve_authorized_path_blocks_traversal(tmp_path: Path) -> None:
    allowed = tmp_path / "reports"
    allowed.mkdir()
    inside = allowed / "ok.pdf"
    inside.write_bytes(b"%PDF-1.4")
    assert resolve_authorized_path(inside, str(allowed)) == inside.resolve()
    with pytest.raises(ValueError, match="CTI_ALLOWED_PDF_DIR"):
        resolve_authorized_path(tmp_path / "outside.pdf", str(allowed))


def test_stix_exporter_optionally_includes_report_sdo() -> None:
    analysis = PDFAnalysis(
        source_document="report.pdf",
        summary="Threat report summary",
        indicators=(
            Indicator(
                value="evil.example",
                indicator_type=IndicatorType.DOMAIN,
                source=IntelligenceSource.PDF_REPORT,
            ),
        ),
        ttps=(
            TTPMapping(
                technique_id="T1059",
                technique_name="Command",
                tactic="Execution",
                rationale="Script execution",
                evidence="cmd.exe",
                confidence=80,
            ),
        ),
    )
    bundle = json.loads(
        STIXExporter().export_analysis(analysis, include_report=True).serialize()
    )
    types = [obj["type"] for obj in bundle["objects"]]
    assert "report" in types


def test_ui_loopback_validation_and_cli_guard(capsys: Any) -> None:
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("::1") is True
    assert is_loopback_host("localhost") is True
    assert is_loopback_host("0.0.0.0") is False
    assert is_loopback_host("192.168.1.10") is False

    assert main(["ui", "--host", "0.0.0.0"]) == 2
    assert "loopback" in capsys.readouterr().err


def test_ui_endpoints_enforce_csrf_header_and_analyze_pdf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_analysis = PDFAnalysis(
        source_document="report.pdf",
        summary="Analyzed via UI",
        indicators=(
            Indicator(
                value="8.8.8.8",
                indicator_type=IndicatorType.IPV4,
                source=IntelligenceSource.PDF_REPORT,
                confidence=85,
            ),
        ),
        ttps=(
            TTPMapping(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactic="Execution",
                rationale="Used shell",
                evidence="sh -c",
                confidence=85,
            ),
        ),
    )
    analyzer = Mock()
    analyzer.analyze.return_value = fake_analysis
    monkeypatch.setattr("cti_automator.ui.PDFAnalyzer", Mock(return_value=analyzer))

    session = Mock(spec=requests.Session)
    session.get.side_effect = requests.ConnectionError("offline")
    monkeypatch.setattr(
        "cti_automator.ui.run_doctor",
        lambda settings, timeout=1.5: run_doctor(settings, session=session),
    )

    app = create_ui_app(Settings(pdf_max_bytes=1024))
    with TestClient(app) as client:
        index = client.get("/")
        assert index.status_code == 200
        assert "Content-Security-Policy" in index.headers

        status = client.get("/api/status")
        assert status.status_code == 200
        assert status.json()["status"] == "ok"

        # Missing X-CTI-UI header is rejected
        csrf = client.post("/api/analyze-pdf", json={})
        assert csrf.status_code == 403

        # Non-PDF bytes are rejected
        bad = client.post(
            "/api/analyze-pdf",
            headers={"X-CTI-UI": "1"},
            json={
                "filename": "not-pdf.pdf",
                "content_base64": base64.b64encode(b"plain text").decode(),
            },
        )
        assert bad.status_code == 400

        # Valid PDF upload succeeds and returns analysis, STIX bundle, and detections
        good = client.post(
            "/api/analyze-pdf",
            headers={"X-CTI-UI": "1"},
            json={
                "filename": "apt.pdf",
                "content_base64": base64.b64encode(b"%PDF-1.4 content").decode(),
            },
        )
        assert good.status_code == 200
        payload = good.json()
        assert payload["analysis"]["source_document"] == "apt.pdf"
        assert payload["stix_bundle"]["type"] == "bundle"
        assert len(payload["detections"]) >= 2

        # OpenCTI export requires explicit confirm=true
        unconfirmed = client.post(
            "/api/export-opencti",
            headers={"X-CTI-UI": "1"},
            json={"analysis": payload["analysis"], "confirm": False},
        )
        assert unconfirmed.status_code == 400


def test_stack_up_bootstraps_env_reuses_host_services_and_executes(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env.example").write_text(
        "OPENCTI_TOKEN=\nOPENCTI_ADMIN_PASSWORD=\nCOMPOSE_PROFILES=\n",
        encoding="utf-8",
    )
    (tmp_path / "compose.yaml").write_text("services: {}\n", encoding="utf-8")

    # Simulate Ollama already running on host, while Qdrant is missing
    session = Mock(spec=requests.Session)

    def fake_get(url: str, **kwargs: Any) -> Any:
        if "11434" in url:
            resp = Mock(spec=requests.Response)
            resp.status_code = 200
            resp.json.return_value = {"version": OLLAMA_RECOMMENDED_VERSION}
            return resp
        raise requests.ConnectionError("offline")

    session.get.side_effect = fake_get
    report = run_doctor(Settings(), session=session)

    plan = build_stack_up_plan(
        Settings(),
        root=tmp_path,
        mode="standard",
        with_opencti=True,
        build_image=True,
        doctor_report=report,
    )
    assert plan.env_bootstrapped is True
    assert (tmp_path / ".env").is_file()
    assert ((tmp_path / ".env").stat().st_mode & 0o777) == 0o600
    assert (tmp_path / "state").is_dir()
    # Ollama was detected on host, so 'local-ai' profile is skipped and 'ollama' reused
    assert "ollama" in plan.reused_host_services
    assert "local-ai" not in plan.profiles
    assert "memory" in plan.profiles
    assert "opencti" in plan.profiles

    executed_cmds: list[tuple[str, ...]] = []

    def fake_runner(cmd: Any) -> Any:
        executed_cmds.append(tuple(cmd))
        return Mock(returncode=0)

    dry = execute_stack_up(plan, dry_run=True, runner=fake_runner)
    assert dry.executed is False
    assert not executed_cmds

    live = execute_stack_up(plan, dry_run=False, runner=fake_runner)
    assert live.executed is True
    assert len(executed_cmds) == len(plan.commands)

    down_plan = execute_stack_down(root=tmp_path, dry_run=False, runner=fake_runner)
    assert down_plan.executed is True
    assert down_plan.commands[0][-1] == "down"


def test_cli_up_down_status_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    session = Mock(spec=requests.Session)
    session.get.side_effect = requests.ConnectionError("offline")
    monkeypatch.setattr(
        "cti_automator.stack.run_doctor",
        lambda settings, timeout=1.0: run_doctor(settings, session=session),
    )
    assert main(["up", "--mode", "full", "--dry-run"]) == 0
    up_out = json.loads(capsys.readouterr().out)
    assert up_out["action"] == "up"
    assert up_out["mode"] == "full"
    assert up_out["executed"] is False
    assert "monitoring" in up_out["profiles"]

    assert main(["down", "--dry-run"]) == 0
    down_out = json.loads(capsys.readouterr().out)
    assert down_out["action"] == "down"
    assert down_out["executed"] is False

    assert main(["status"]) == 0
    status_out = json.loads(capsys.readouterr().out)
    assert "endpoints" in status_out
    assert "doctor" in status_out

