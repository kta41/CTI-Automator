import json

import pytest

from cti_automator.config import Settings
from cti_automator.exceptions import ExportError
from cti_automator.exporters.opencti import OpenCTIExporter
from cti_automator.exporters.stix import STIXExporter
from cti_automator.models import (
    Indicator,
    IndicatorType,
    IntelligenceSource,
    PDFAnalysis,
    TTPMapping,
)


def sample_analysis() -> PDFAnalysis:
    return PDFAnalysis(
        source_document="report.pdf",
        summary="PowerShell execution",
        indicators=[
            Indicator(
                value="evil.example",
                indicator_type=IndicatorType.DOMAIN,
                source=IntelligenceSource.PDF_REPORT,
                tags=("malware",),
                confidence=90,
            )
        ],
        ttps=[
            TTPMapping(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="Execution",
                rationale="The report describes PowerShell execution.",
                evidence="used PowerShell",
                confidence=90,
            )
        ],
    )


def test_stix_exporter_creates_bundle_and_relationship() -> None:
    serialized = STIXExporter().export_analysis(sample_analysis()).serialize()
    payload = json.loads(serialized)

    assert payload["type"] == "bundle"
    assert len(payload["objects"]) == 3
    assert any(obj["type"] == "relationship" for obj in payload["objects"])


def test_stix_exporter_rejects_unknown_indicator_type() -> None:
    analysis = sample_analysis()
    analysis.indicators[0].indicator_type = IndicatorType.UNKNOWN

    with pytest.raises(ExportError, match="cannot be represented"):
        STIXExporter().export_analysis(analysis)


def test_opencti_exporter_imports_serialized_bundle() -> None:
    class FakeSTIX:
        def __init__(self) -> None:
            self.bundle: str | None = None

        def import_bundle(self, bundle: str) -> None:
            self.bundle = bundle

    class FakeClient:
        def __init__(self) -> None:
            self.stix2 = FakeSTIX()

    client = FakeClient()
    serialized = OpenCTIExporter(
        Settings(),
        client=client,  # type: ignore[arg-type]
    ).export_analysis(sample_analysis())

    assert client.stix2.bundle == serialized


def test_opencti_exporter_requires_credentials_without_injected_client() -> None:
    with pytest.raises(ValueError, match="OPENCTI_URL"):
        OpenCTIExporter(Settings())
