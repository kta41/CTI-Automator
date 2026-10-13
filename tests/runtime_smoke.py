"""Exercise the installed runtime, real pycti JSON adapter and local MCP."""

import asyncio
import logging
import time
import urllib.request
from types import SimpleNamespace

from fastmcp import Client
from fastmcp.exceptions import ToolError
from pycti.utils.opencti_stix2 import OpenCTIStix2

from cti_automator.config import Settings
from cti_automator.exporters import OpenCTIExporter
from cti_automator.models import Indicator, IndicatorType, IntelligenceSource


def verify_import_adapter():
    importer = OpenCTIStix2.__new__(OpenCTIStix2)
    importer.opencti = SimpleNamespace(
        logger_class=lambda name: logging.getLogger(name)
    )
    stored = {}

    def import_item(item, update, *args):
        assert update is True
        stored[item["id"]] = item
        return None

    importer.import_item_with_retries = import_item
    exporter = OpenCTIExporter(Settings(), client=SimpleNamespace(stix2=importer))
    indicators = [
        Indicator(
            value="8.8.8.8",
            indicator_type=IndicatorType.IPV4,
            source=IntelligenceSource.OTX,
        ),
        Indicator(
            value="a" * 64,
            indicator_type=IndicatorType.FILE_HASH_SHA256,
            source=IntelligenceSource.THREATFOX,
        ),
    ]
    exporter.export_indicators(indicators)
    exporter.export_indicators(indicators)
    assert len(stored) == 2
    print("Real pycti JSON adapter, splitter and retry identities: OK")


async def verify_mcp():
    for attempt in range(20):
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:8000/healthz", timeout=2
            ) as response:
                assert response.status == 200
            break
        except OSError:
            if attempt == 19:
                raise
            await asyncio.sleep(1)
    async with Client("http://127.0.0.1:8000/mcp") as client:
        await client.ping()
        tools = await client.list_tools()
        assert {tool.name for tool in tools} == {
            "analyze_pdf",
            "export_pdf_to_opencti",
            "export_pdf_to_stix",
            "get_otx_pulses",
            "get_threatfox_iocs",
            "enrich_indicators",
            "push_to_opencti",
            "ingest_repositories",
        }
        try:
            await client.call_tool("get_threatfox_iocs", {"days": 0})
        except ToolError:
            pass
        else:
            raise AssertionError("Invalid business operation must fail")
    with urllib.request.urlopen("http://127.0.0.1:8000/metrics", timeout=5) as response:
        metrics = response.read().decode()
        assert (
            'cti_operations_total{operation="threatfox",outcome="error"} 1.0' in metrics
        )
    print("MCP health, eight tools, error propagation and business metrics: OK")


if __name__ == "__main__":
    start = time.monotonic()
    verify_import_adapter()
    asyncio.run(verify_mcp())
    print(f"Runtime validation completed in {time.monotonic() - start:.2f}s")
