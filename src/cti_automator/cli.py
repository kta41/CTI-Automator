"""Command-line interface for CTI Automator."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from cti_automator.analyzer import PDFAnalyzer
from cti_automator.config import Settings
from cti_automator.connectors import OTXClient, ThreatFoxClient
from cti_automator.enrichment import EnrichmentService
from cti_automator.exceptions import CTIAutomatorError
from cti_automator.exporters import OpenCTIExporter, STIXExporter
from cti_automator.observability import configure_logging, observe
from cti_automator.repositories import ingest_repository_reports


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser without reading environment variables."""
    parser = argparse.ArgumentParser(
        prog="cti-automator",
        description="Privacy-first CTI ingestion and OpenCTI automation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze-pdf", help="Analyze a PDF report.")
    analyze.add_argument("file", type=Path)
    analyze.add_argument(
        "--enrich", nargs="+", choices=("virustotal", "shodan"), default=[]
    )
    analyze.set_defaults(handler=_analyze_pdf)

    export = subparsers.add_parser(
        "export-pdf",
        help="Analyze a PDF and export it to OpenCTI or a STIX file.",
    )
    export.add_argument("file", type=Path)
    export.add_argument("--stix-output", type=Path)
    export.add_argument("--opencti", action="store_true")
    export.add_argument(
        "--enrich", nargs="+", choices=("virustotal", "shodan"), default=[]
    )
    export.set_defaults(handler=_export_pdf)

    otx = subparsers.add_parser("ingest-otx", help="Fetch subscribed OTX pulses.")
    otx.add_argument("--modified-since")
    otx.add_argument("--opencti", action="store_true")
    otx.add_argument(
        "--enrich", nargs="+", choices=("virustotal", "shodan"), default=[]
    )
    otx.set_defaults(handler=_ingest_otx)

    threatfox = subparsers.add_parser(
        "ingest-threatfox",
        help="Query recent ThreatFox IOCs.",
    )
    threatfox.add_argument("--days", type=int, default=1)
    threatfox.add_argument("--opencti", action="store_true")
    threatfox.add_argument(
        "--enrich", nargs="+", choices=("virustotal", "shodan"), default=[]
    )
    threatfox.set_defaults(handler=_ingest_threatfox)

    repository = subparsers.add_parser(
        "ingest-repositories", help="Analyze authorized textual repository reports."
    )
    repository.add_argument("--opencti", action="store_true")
    repository.set_defaults(handler=_ingest_repositories)

    mcp = subparsers.add_parser("mcp", help="Run the FastMCP server.")
    mcp.add_argument("--transport", choices=("stdio", "sse", "streamable-http"))
    mcp.add_argument(
        "--host", default=None, help="Network interface for HTTP transports."
    )
    mcp.add_argument("--port", type=int, default=None, help="Port for HTTP transports.")
    mcp.set_defaults(handler=_run_mcp)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    args = build_parser().parse_args(argv)
    try:
        settings = Settings.from_env()
        configure_logging(settings.log_level)
        return _execute(args, settings)
    except (CTIAutomatorError, OSError, ValueError) as exc:
        message = str(exc)
        safe = (
            message
            if message
            in {
                "OTX_API_KEY is required for AlienVault OTX",
                "ABUSECH_API_KEY is required for ThreatFox",
                "OPENCTI_URL and OPENCTI_TOKEN are required",
                "VIRUSTOTAL_API_KEY is required for enrichment",
                "SHODAN_API_KEY is required for enrichment",
                "CTI_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL",
                "--host and --port require an HTTP transport",
                "MCP port must be between 1 and 65535",
            }
            else f"{type(exc).__name__}; check configuration and structured error events"
        )
        print(f"error: {safe}", file=sys.stderr)
        return 2


@observe("cli")
def _execute(args: argparse.Namespace, settings: Settings) -> int:
    return int(args.handler(args, settings))


def _analyze_pdf(args: argparse.Namespace, settings: Settings) -> int:
    analysis = PDFAnalyzer(settings).analyze(args.file)
    analysis = analysis.model_copy(
        update={
            "indicators": EnrichmentService(settings).enrich(
                analysis.indicators,
                args.enrich,
            )
        }
    )
    print(analysis.model_dump_json(indent=2))
    return 0


def _export_pdf(args: argparse.Namespace, settings: Settings) -> int:
    analysis = PDFAnalyzer(settings).analyze(args.file)
    analysis = analysis.model_copy(
        update={
            "indicators": EnrichmentService(settings).enrich(
                analysis.indicators,
                args.enrich,
            )
        }
    )
    if args.opencti:
        OpenCTIExporter(settings).export_analysis(analysis)
        print("Analysis imported into OpenCTI.")
    else:
        bundle = STIXExporter().export_analysis(analysis).serialize()
        if args.stix_output:
            args.stix_output.write_text(bundle, encoding="utf-8")
            print(f"STIX bundle written to {args.stix_output}")
        else:
            print(bundle)
    return 0


def _ingest_otx(args: argparse.Namespace, settings: Settings) -> int:
    exporter = OpenCTIExporter(settings) if args.opencti else None
    pulses = OTXClient(settings).get_pulses(modified_since=args.modified_since)
    service = EnrichmentService(settings)
    pulses = tuple(
        pulse.model_copy(
            update={"indicators": service.enrich(pulse.indicators, args.enrich)}
        )
        for pulse in pulses
    )
    if exporter:
        indicators = tuple(item for pulse in pulses for item in pulse.indicators)
        serialized = exporter.export_indicators(indicators)
        print(
            json.dumps(
                {
                    "imported": len(json.loads(serialized).get("objects", [])),
                    "source": "otx",
                }
            )
        )
        return 0
    print(json.dumps([pulse.model_dump(mode="json") for pulse in pulses], indent=2))
    return 0


def _ingest_threatfox(args: argparse.Namespace, settings: Settings) -> int:
    exporter = OpenCTIExporter(settings) if args.opencti else None
    result = ThreatFoxClient(settings).get_recent_iocs(days=args.days)
    result = result.model_copy(
        update={
            "indicators": EnrichmentService(settings).enrich(
                result.indicators,
                args.enrich,
            )
        }
    )
    if exporter:
        serialized = exporter.export_indicators(result.indicators)
        print(
            json.dumps(
                {
                    "imported": len(json.loads(serialized).get("objects", [])),
                    "source": "threatfox",
                }
            )
        )
        return 0
    print(result.model_dump_json(indent=2))
    return 0


def _ingest_repositories(args: argparse.Namespace, settings: Settings) -> int:
    analyses = ingest_repository_reports(settings, opencti=args.opencti)
    if args.opencti:
        print(json.dumps({"imported_reports": len(analyses)}))
    else:
        print(json.dumps([analysis.model_dump(mode="json") for analysis in analyses]))
    return 0


def _run_mcp(args: argparse.Namespace, settings: Settings) -> int:
    from cti_automator.mcp_server import create_mcp_server

    if args.port is not None and not 1 <= args.port <= 65535:
        raise ValueError("MCP port must be between 1 and 65535")
    if (args.host is not None or args.port is not None) and args.transport not in {
        "sse",
        "streamable-http",
    }:
        raise ValueError("--host and --port require an HTTP transport")
    server = create_mcp_server(settings)
    if args.transport in {"sse", "streamable-http"}:
        server.run(
            transport=args.transport,
            show_banner=False,
            host=args.host,
            port=args.port,
            uvicorn_config={"log_config": None, "access_log": False},
        )
    else:
        server.run(transport=args.transport, show_banner=False)
    return 0
