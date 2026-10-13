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
from cti_automator.exceptions import CTIAutomatorError
from cti_automator.exporters import OpenCTIExporter, STIXExporter


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser without reading environment variables."""
    parser = argparse.ArgumentParser(
        prog="cti-automator",
        description="Privacy-first CTI ingestion and OpenCTI automation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze-pdf", help="Analyze a PDF report.")
    analyze.add_argument("file", type=Path)
    analyze.set_defaults(handler=_analyze_pdf)

    export = subparsers.add_parser(
        "export-pdf",
        help="Analyze a PDF and export it to OpenCTI or a STIX file.",
    )
    export.add_argument("file", type=Path)
    export.add_argument("--stix-output", type=Path)
    export.add_argument("--opencti", action="store_true")
    export.set_defaults(handler=_export_pdf)

    otx = subparsers.add_parser("ingest-otx", help="Fetch subscribed OTX pulses.")
    otx.add_argument("--modified-since")
    otx.set_defaults(handler=_ingest_otx)

    threatfox = subparsers.add_parser(
        "ingest-threatfox",
        help="Query recent ThreatFox IOCs.",
    )
    threatfox.add_argument("--days", type=int, default=1)
    threatfox.set_defaults(handler=_ingest_threatfox)

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
        return int(args.handler(args, Settings.from_env()))
    except (CTIAutomatorError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _analyze_pdf(args: argparse.Namespace, settings: Settings) -> int:
    analysis = PDFAnalyzer(settings).analyze(args.file)
    print(analysis.model_dump_json(indent=2))
    return 0


def _export_pdf(args: argparse.Namespace, settings: Settings) -> int:
    analysis = PDFAnalyzer(settings).analyze(args.file)
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
    pulses = OTXClient(settings).get_pulses(modified_since=args.modified_since)
    print(json.dumps([pulse.model_dump(mode="json") for pulse in pulses], indent=2))
    return 0


def _ingest_threatfox(args: argparse.Namespace, settings: Settings) -> int:
    result = ThreatFoxClient(settings).get_recent_iocs(days=args.days)
    print(result.model_dump_json(indent=2))
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
    if args.host is None and args.port is None:
        server.run(transport=args.transport)
    else:
        server.run(
            transport=args.transport,
            host=args.host,
            port=args.port,
        )
    return 0
