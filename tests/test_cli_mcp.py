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
