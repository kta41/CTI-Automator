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
from cti_automator.detections import (
    FileDetectionExporter,
    GitHubPullRequestExporter,
    generate_sigma_rules,
    generate_yara_rule,
    validate_directory,
)
from cti_automator.doctor import run_doctor
from cti_automator.enrichment import EnrichmentService
from cti_automator.exceptions import CTIAutomatorError
from cti_automator.exporters import OpenCTIExporter, STIXExporter
from cti_automator.memory import MemoryService
from cti_automator.observability import configure_logging, observe
from cti_automator.repositories import ingest_repository_reports
from cti_automator.secops import (
    CortexXSOARAdapter,
    TheHiveAdapter,
    WebhookNotifier,
    build_case,
)
from cti_automator.stack import (
    build_stack_up_plan,
    execute_stack_down,
    execute_stack_up,
    stack_status,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser without reading environment variables."""
    parser = argparse.ArgumentParser(
        prog="cti-automator",
        description="Privacy-first CTI ingestion and OpenCTI automation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze-pdf", help="Analyze a PDF report.")
    analyze.add_argument("file", type=Path)
    analyze.add_argument("--output", type=Path, help="Save validated PDFAnalysis JSON.")
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

    detections = subparsers.add_parser(
        "generate-detections",
        help="Generate YARA/SIGMA proposals from a PDF analysis.",
    )
    detections.add_argument("file", type=Path)
    detections.add_argument(
        "--formats",
        nargs="+",
        choices=("yara", "sigma"),
        default=["yara", "sigma"],
    )
    detections.add_argument("--yara-dir", type=Path)
    detections.add_argument("--sigma-dir", type=Path)
    detections.add_argument("--pr-repo", help="Authorized owner/name repository.")
    detections.add_argument(
        "--submit",
        action="store_true",
        help="Actually open the proposal pull request (default is dry-run).",
    )
    detections.set_defaults(handler=_generate_detections)

    validate = subparsers.add_parser(
        "validate-detections", help="Validate committed rule files (GitOps gate)."
    )
    validate.add_argument("directory", type=Path)
    validate.set_defaults(handler=_validate_detections)

    memory_remember = subparsers.add_parser(
        "memory-remember", help="Store one PDF analysis in historical memory."
    )
    memory_remember.add_argument("file", type=Path)
    memory_remember.set_defaults(handler=_memory_remember)

    memory_recall = subparsers.add_parser(
        "memory-recall", help="Recall cited historical fragments for a query."
    )
    memory_recall.add_argument("query")
    memory_recall.add_argument("--limit", type=int, default=5)
    memory_recall.set_defaults(handler=_memory_recall)

    memory_forget = subparsers.add_parser(
        "memory-forget",
        help="Delete expired historical memory fragments past retention.",
    )
    memory_forget.set_defaults(handler=_memory_forget)

    doctor = subparsers.add_parser(
        "doctor",
        help="Check local OpenCTI, TheHive, Ollama and Qdrant and propose installation.",
    )
    doctor.set_defaults(handler=_run_doctor)

    ui = subparsers.add_parser(
        "ui",
        help="Run the local loopback web UI.",
    )
    ui.add_argument("--host", default="127.0.0.1", help="Loopback interface only.")
    ui.add_argument("--port", type=int, default=8080, help="Port for local web UI.")
    ui.add_argument(
        "--allow-container-bind",
        action="store_true",
        help="Allow 0.0.0.0 inside a container published to host loopback.",
    )
    ui.set_defaults(handler=_run_ui)

    stack_up = subparsers.add_parser(
        "up",
        help="One-command stack startup (bootstraps .env, starts Compose and pulls models).",
    )
    stack_up.add_argument(
        "--mode",
        choices=("minimal", "standard", "full"),
        default="standard",
        help="Stack preset (default: standard = UI + MCP + Ingest + Ollama + Qdrant).",
    )
    stack_up.add_argument("--with-opencti", action="store_true")
    stack_up.add_argument("--with-thehive", action="store_true")
    stack_up.add_argument("--with-monitoring", action="store_true")
    stack_up.add_argument("--build", action="store_true")
    stack_up.add_argument("--no-pull-models", action="store_true")
    stack_up.add_argument("--dry-run", action="store_true")
    stack_up.set_defaults(handler=_run_stack_up)

    stack_down = subparsers.add_parser(
        "down",
        help="Stop all active and optional Docker Compose stack services.",
    )
    stack_down.add_argument("--dry-run", action="store_true")
    stack_down.set_defaults(handler=_run_stack_down)

    status_cmd = subparsers.add_parser(
        "status",
        help="Show stack health, detected versions and local endpoints.",
    )
    status_cmd.set_defaults(handler=_run_stack_status)

    secops = subparsers.add_parser(
        "create-secops-case",
        help="Create a TheHive or Cortex XSOAR case from one PDF analysis.",
    )
    secops.add_argument("file", type=Path)
    secops.add_argument("--destination", choices=("thehive", "xsoar"), required=True)
    secops.add_argument(
        "--severity", choices=("low", "medium", "high", "critical"), default=None
    )
    secops.add_argument(
        "--dry-run", action="store_true", help="Only show the planned payload."
    )
    secops.set_defaults(handler=_create_secops_case)

    chatops = subparsers.add_parser(
        "notify-chatops",
        help="Send a signed ChatOps notification about one PDF analysis.",
    )
    chatops.add_argument("file", type=Path)
    chatops.add_argument("--destination", required=True)
    chatops.add_argument(
        "--dry-run", action="store_true", help="Only show the planned notification."
    )
    chatops.set_defaults(handler=_notify_chatops)

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
                "CTI_THEHIVE_URL and CTI_THEHIVE_TOKEN are required",
                "CTI_XSOAR_URL and CTI_XSOAR_TOKEN are required",
                "GITHUB_TOKEN is required to submit detection proposals",
                "Repository is not in CTI_REPOSITORY_ALLOWLIST",
                "Repository is not in CTI_DETECTION_PR_ALLOWLIST",
                "Historical memory is disabled; set CTI_MEMORY_ENABLED=true",
                "ChatOps destination is not configured",
                "memory recall limit must be between 1 and 25",
                "memory query cannot be empty",
                "notification message cannot be empty",
                "Local UI requires a loopback host (127.0.0.1, ::1 or localhost)",
                "UI port must be between 1 and 65535",
                "PDF file path is outside CTI_ALLOWED_PDF_DIR",
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
    serialized = analysis.model_dump_json(indent=2)
    if getattr(args, "output", None):
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized)
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


def _generate_detections(args: argparse.Namespace, settings: Settings) -> int:
    analysis = PDFAnalyzer(settings).analyze(args.file)
    rules = []
    if "yara" in args.formats:
        rules.append(generate_yara_rule(analysis))
    if "sigma" in args.formats:
        rules.extend(generate_sigma_rules(analysis))
    summary: dict[str, object] = {"rules": [rule.summary() for rule in rules]}
    if args.yara_dir:
        outcome = FileDetectionExporter(args.yara_dir).export(
            tuple(rule for rule in rules if rule.rule_format == "yara")
        )
        summary["yara_export"] = outcome.model_dump(mode="json")
    if args.sigma_dir:
        outcome = FileDetectionExporter(args.sigma_dir).export(
            tuple(rule for rule in rules if rule.rule_format == "sigma")
        )
        summary["sigma_export"] = outcome.model_dump(mode="json")
    if args.pr_repo:
        exporter = GitHubPullRequestExporter(settings)
        plan = exporter.plan(analysis, tuple(rules), args.pr_repo)
        if args.submit:
            summary["pull_request"] = exporter.submit(plan)
        else:
            summary["pull_request_plan"] = plan.summary()
    print(json.dumps(summary, indent=2))
    return 0


def _validate_detections(args: argparse.Namespace, settings: Settings) -> int:
    count, errors = validate_directory(args.directory)
    if errors:
        print(json.dumps({"valid": False, "rules": count, "errors": errors}, indent=2))
        return 1
    print(json.dumps({"valid": True, "rules": count}))
    return 0


def _memory_remember(args: argparse.Namespace, settings: Settings) -> int:
    analysis = PDFAnalyzer(settings).analyze(args.file)
    result = MemoryService(settings).remember(analysis)
    print(result.model_dump_json())
    return 0


def _memory_recall(args: argparse.Namespace, settings: Settings) -> int:
    fragments = MemoryService(settings).recall(args.query, limit=args.limit)
    print(json.dumps([item.model_dump(mode="json") for item in fragments], indent=2))
    return 0


def _memory_forget(args: argparse.Namespace, settings: Settings) -> int:
    deleted = MemoryService(settings).forget()
    print(json.dumps({"deleted": deleted}))
    return 0


def _run_doctor(args: argparse.Namespace, settings: Settings) -> int:
    report = run_doctor(settings)
    print(report.model_dump_json(indent=2))
    return 0


def _run_ui(args: argparse.Namespace, settings: Settings) -> int:
    import uvicorn

    from cti_automator.ui import create_ui_app, is_loopback_host

    if not 1 <= args.port <= 65535:
        raise ValueError("UI port must be between 1 and 65535")
    if not getattr(args, "allow_container_bind", False) and not is_loopback_host(
        args.host
    ):
        raise ValueError(
            "Local UI requires a loopback host (127.0.0.1, ::1 or localhost)"
        )
    app = create_ui_app(settings)
    uvicorn.run(app, host=args.host, port=args.port, log_config=None, access_log=False)
    return 0


def _run_stack_up(args: argparse.Namespace, settings: Settings) -> int:
    plan = build_stack_up_plan(
        settings,
        mode=args.mode,
        with_opencti=args.with_opencti,
        with_thehive=args.with_thehive,
        with_monitoring=args.with_monitoring,
        build_image=args.build,
        pull_models=not args.no_pull_models,
    )
    outcome = execute_stack_up(plan, dry_run=args.dry_run)
    print(outcome.model_dump_json(indent=2))
    return 0


def _run_stack_down(args: argparse.Namespace, settings: Settings) -> int:
    outcome = execute_stack_down(dry_run=args.dry_run)
    print(outcome.model_dump_json(indent=2))
    return 0


def _run_stack_status(args: argparse.Namespace, settings: Settings) -> int:
    print(json.dumps(stack_status(settings), indent=2))
    return 0


def _create_secops_case(args: argparse.Namespace, settings: Settings) -> int:
    analysis = PDFAnalyzer(settings).analyze(args.file)
    case = build_case(analysis, severity=args.severity)
    adapter: TheHiveAdapter | CortexXSOARAdapter = (
        TheHiveAdapter(settings)
        if args.destination == "thehive"
        else CortexXSOARAdapter(settings)
    )
    delivery = adapter.deliver(case, dry_run=args.dry_run)
    print(
        json.dumps(
            {
                "case": case.payload_summary(),
                "delivery": delivery.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def _notify_chatops(args: argparse.Namespace, settings: Settings) -> int:
    analysis = PDFAnalyzer(settings).analyze(args.file)
    message = (
        f"[CTI] {analysis.source_document}: {len(analysis.indicators)} indicators, "
        f"{len(analysis.ttps)} ATT&CK mappings."
    )
    result = WebhookNotifier(settings).notify(
        args.destination, message, dry_run=args.dry_run
    )
    print(result.model_dump_json())
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
