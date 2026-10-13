import pytest
from starlette.testclient import TestClient

from cti_automator.cli import build_parser, main
from cti_automator.config import Settings
from cti_automator.mcp_server import create_mcp_server


def test_cli_parser_defines_phase_five_commands() -> None:
    parser = build_parser()

    assert parser.parse_args(["analyze-pdf", "report.pdf"]).command == "analyze-pdf"
    assert parser.parse_args(["mcp"]).command == "mcp"
    mcp_args = parser.parse_args(
        [
            "mcp",
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ]
    )
    assert mcp_args.host == "0.0.0.0"
    assert mcp_args.port == 8000


def test_cli_rejects_missing_otx_credentials(capsys) -> None:
    exit_code = main(["ingest-otx"])

    assert exit_code == 2
    assert "OTX_API_KEY" in capsys.readouterr().err


def test_mcp_server_registers_tools() -> None:
    server = create_mcp_server(Settings())

    assert server is not None


def test_mcp_health_does_not_require_external_services() -> None:
    server = create_mcp_server(Settings())
    with TestClient(server.http_app()) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "arguments",
    [
        ["--host", "0.0.0.0"],
        ["--transport", "stdio", "--port", "8000"],
        ["--transport", "streamable-http", "--port", "0"],
        ["--transport", "streamable-http", "--port", "65536"],
    ],
)
def test_mcp_rejects_invalid_network_options(arguments, capsys) -> None:
    assert main(["mcp", *arguments]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["ingest-otx", "ingest-threatfox"])
def test_api_cli_delivers_to_opencti_without_printing_indicators(
    command, monkeypatch, capsys
):
    from unittest.mock import Mock

    from cti_automator.models import (
        Indicator,
        IndicatorType,
        IntelligenceSource,
        OTXPulse,
        ThreatFoxQueryResult,
    )

    indicator = Indicator(
        value="sensitive.example",
        indicator_type=IndicatorType.DOMAIN,
        source=IntelligenceSource.OTX,
    )
    exporter = Mock()
    exporter.export_indicators.return_value = '{"objects": [{"id": "fake"}]}'
    monkeypatch.setattr(
        "cti_automator.cli.OpenCTIExporter", Mock(return_value=exporter)
    )
    otx = Mock()
    otx.get_pulses.return_value = (
        OTXPulse(id="1", name="pulse", indicators=(indicator,)),
    )
    threatfox = Mock()
    threatfox.get_recent_iocs.return_value = ThreatFoxQueryResult(
        query_status="ok", indicators=(indicator,)
    )
    monkeypatch.setattr("cti_automator.cli.OTXClient", Mock(return_value=otx))
    monkeypatch.setattr(
        "cti_automator.cli.ThreatFoxClient", Mock(return_value=threatfox)
    )
    assert main([command, "--opencti"]) == 0
    exporter.export_indicators.assert_called_once_with((indicator,))
    output = capsys.readouterr()
    assert '"imported": 1' in output.out
    assert "sensitive.example" not in output.out + output.err


def test_validation_error_never_prints_settings_values(monkeypatch, capsys):
    monkeypatch.setenv("CTI_REQUEST_TIMEOUT", "sensitive@example.com")
    assert main(["ingest-otx"]) == 2
    assert "sensitive@example.com" not in capsys.readouterr().err


def test_mcp_masks_error_details_and_framework_logs(monkeypatch, capsys):
    import asyncio
    from unittest.mock import Mock

    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    analyzer = Mock()
    analyzer.analyze.side_effect = ValueError(
        "token=private@example.com and report-body"
    )
    monkeypatch.setattr(
        "cti_automator.mcp_server.PDFAnalyzer", Mock(return_value=analyzer)
    )
    server = create_mcp_server(Settings())

    async def run():
        async with Client(server) as client:
            with pytest.raises(ToolError) as failure:
                await client.call_tool("analyze_pdf", {"file": "private.pdf"})
            assert "private@example.com" not in str(failure.value)
            assert "report-body" not in str(failure.value)

    asyncio.run(run())
    output = capsys.readouterr()
    assert "private@example.com" not in output.err
    assert "report-body" not in output.err
    assert "Traceback" not in output.err
