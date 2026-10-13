"""FastMCP tools for CTI Automator operations."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from fastmcp import FastMCP

from cti_automator.analyzer import PDFAnalyzer
from cti_automator.config import Settings
from cti_automator.connectors import OTXClient, ThreatFoxClient
from cti_automator.exporters import OpenCTIExporter, STIXExporter


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Create an MCP server with dependencies captured in its tool closures."""
    runtime_settings = settings or Settings.from_env()
    server = FastMCP(
        name="cti-automator",
        instructions=(
            "Use these tools to analyze threat reports and ingest CTI. "
            "Hosted AI use is controlled by the configured provider."
        ),
    )

    @server.tool
    def analyze_pdf(file: str) -> dict[str, object]:
        """Analyze a local PDF and return validated IoCs and ATT&CK mappings."""
        analysis = PDFAnalyzer(runtime_settings).analyze(Path(file))
        return analysis.model_dump(mode="json")

    @server.tool
    def export_pdf_to_opencti(file: str) -> str:
        """Analyze a local PDF and import its STIX bundle into OpenCTI."""
        analysis = PDFAnalyzer(runtime_settings).analyze(Path(file))
        return OpenCTIExporter(runtime_settings).export_analysis(analysis)

    @server.tool
    def export_pdf_to_stix(file: str) -> str:
        """Analyze a local PDF and return its serialized STIX bundle."""
        analysis = PDFAnalyzer(runtime_settings).analyze(Path(file))
        return cast(str, STIXExporter().export_analysis(analysis).serialize())

    @server.tool
    def get_otx_pulses(modified_since: str | None = None) -> list[dict[str, object]]:
        """Fetch subscribed AlienVault OTX pulses."""
        pulses = OTXClient(runtime_settings).get_pulses(
            modified_since=modified_since
        )
        return [pulse.model_dump(mode="json") for pulse in pulses]

    @server.tool
    def get_threatfox_iocs(days: int = 1) -> dict[str, object]:
        """Fetch recent ThreatFox IOCs."""
        return ThreatFoxClient(runtime_settings).get_recent_iocs(
            days=days
        ).model_dump(mode="json")

    return server
