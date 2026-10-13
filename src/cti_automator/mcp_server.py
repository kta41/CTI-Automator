"""FastMCP tools for CTI Automator operations."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from fastmcp import FastMCP
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from cti_automator.analyzer import PDFAnalyzer
from cti_automator.config import Settings
from cti_automator.connectors import OTXClient, ThreatFoxClient
from cti_automator.enrichment import EnrichmentService, Provider
from cti_automator.exporters import OpenCTIExporter, STIXExporter
from cti_automator.models import Indicator
from cti_automator.observability import configure_logging, observe
from cti_automator.repositories import ingest_repository_reports


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Create an MCP server with dependencies captured in its tool closures."""
    runtime_settings = settings or Settings.from_env()
    configure_logging(runtime_settings.log_level)
    enrichment = EnrichmentService(runtime_settings)
    server = FastMCP(
        name="cti-automator",
        mask_error_details=True,
        instructions=(
            "Use these tools to analyze threat reports and ingest CTI. "
            "Hosted AI use is controlled by the configured provider."
        ),
    )

    @server.custom_route("/healthz", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        """Check server responsiveness without querying external dependencies."""
        return JSONResponse({"status": "ok"})

    @server.custom_route("/metrics", methods=["GET"])
    async def metrics(request: Request) -> Response:
        return Response(
            generate_latest(), headers={"Content-Type": CONTENT_TYPE_LATEST}
        )

    @server.tool
    @observe("mcp", new_run=True)
    def analyze_pdf(
        file: str, enrich: list[Provider] | None = None
    ) -> dict[str, object]:
        """Analyze a local PDF and return validated IoCs and ATT&CK mappings."""
        analysis = PDFAnalyzer(runtime_settings).analyze(Path(file))
        analysis = analysis.model_copy(
            update={"indicators": enrichment.enrich(analysis.indicators, enrich or ())}
        )
        return analysis.model_dump(mode="json")

    @server.tool
    @observe("mcp", new_run=True)
    def export_pdf_to_opencti(file: str, enrich: list[Provider] | None = None) -> str:
        """Analyze a local PDF and import its STIX bundle into OpenCTI."""
        analysis = PDFAnalyzer(runtime_settings).analyze(Path(file))
        analysis = analysis.model_copy(
            update={"indicators": enrichment.enrich(analysis.indicators, enrich or ())}
        )
        return OpenCTIExporter(runtime_settings).export_analysis(analysis)

    @server.tool
    @observe("mcp", new_run=True)
    def export_pdf_to_stix(file: str, enrich: list[Provider] | None = None) -> str:
        """Analyze a local PDF and return its serialized STIX bundle."""
        analysis = PDFAnalyzer(runtime_settings).analyze(Path(file))
        analysis = analysis.model_copy(
            update={"indicators": enrichment.enrich(analysis.indicators, enrich or ())}
        )
        return cast(str, STIXExporter().export_analysis(analysis).serialize())

    @server.tool
    @observe("mcp", new_run=True)
    def get_otx_pulses(
        modified_since: str | None = None,
        opencti: bool = False,
        enrich: list[Provider] | None = None,
    ) -> list[dict[str, object]]:
        """Fetch subscribed AlienVault OTX pulses."""
        exporter = OpenCTIExporter(runtime_settings) if opencti else None
        pulses = OTXClient(runtime_settings).get_pulses(modified_since=modified_since)
        pulses = tuple(
            pulse.model_copy(
                update={
                    "indicators": enrichment.enrich(pulse.indicators, enrich or ()),
                }
            )
            for pulse in pulses
        )
        if exporter:
            exporter.export_indicators(
                tuple(item for pulse in pulses for item in pulse.indicators)
            )
        return [pulse.model_dump(mode="json") for pulse in pulses]

    @server.tool
    @observe("mcp", new_run=True)
    def get_threatfox_iocs(
        days: int = 1,
        opencti: bool = False,
        enrich: list[Provider] | None = None,
    ) -> dict[str, object]:
        """Fetch recent ThreatFox IOCs."""
        exporter = OpenCTIExporter(runtime_settings) if opencti else None
        result = ThreatFoxClient(runtime_settings).get_recent_iocs(days=days)
        result = result.model_copy(
            update={"indicators": enrichment.enrich(result.indicators, enrich or ())}
        )
        if exporter:
            exporter.export_indicators(result.indicators)
        return result.model_dump(mode="json")

    @server.tool
    @observe("mcp", new_run=True)
    def enrich_indicators(
        indicators: list[Indicator], providers: list[Provider]
    ) -> list[dict[str, object]]:
        """Explicitly authorize external queries of public indicators only."""
        return [
            item.model_dump(mode="json")
            for item in enrichment.enrich(indicators, providers)
        ]

    @server.tool
    @observe("mcp", new_run=True)
    def push_to_opencti(indicators: list[Indicator]) -> str:
        """Import normalized indicators using deterministic STIX IDs."""
        return OpenCTIExporter(runtime_settings).export_indicators(indicators)

    @server.tool
    @observe("mcp", new_run=True)
    def ingest_repositories(opencti: bool = False) -> list[dict[str, object]]:
        """Analyze allowlisted textual reports, checkpointing after successful delivery."""
        return [
            item.model_dump(mode="json")
            for item in ingest_repository_reports(
                runtime_settings,
                opencti=opencti,
            )
        ]

    return server
