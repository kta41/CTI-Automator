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

        def import_bundle_from_json(self, bundle: str, *, update: bool) -> object:
            self.bundle = bundle
            return ([{"id": item["id"]} for item in json.loads(bundle)["objects"]], [])

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


@pytest.mark.parametrize(
    "kind,value",
    [
        (IndicatorType.IPV4, "8.8.8.8"),
        (IndicatorType.IPV6, "2001:4860:4860::8888"),
        (IndicatorType.DOMAIN, "evil.example"),
        (IndicatorType.URL, "https://evil.example/report"),
        (IndicatorType.EMAIL, "actor@example.com"),
        (IndicatorType.FILE_HASH_MD5, "a" * 32),
        (IndicatorType.FILE_HASH_SHA1, "b" * 40),
        (IndicatorType.FILE_HASH_SHA256, "c" * 64),
    ],
)
def test_api_stix_patterns_are_valid_and_repeated_objects_identical(kind, value):
    from stix2 import parse

    indicator = Indicator(
        value=value, indicator_type=kind, source=IntelligenceSource.OTX
    )
    first = json.loads(
        STIXExporter().export_indicators([indicator, indicator]).serialize()
    )
    second = json.loads(STIXExporter().export_indicators([indicator]).serialize())
    assert len(first["objects"]) == 1
    assert first["objects"] == second["objects"]
    assert parse(json.dumps(first["objects"][0])).id == first["objects"][0]["id"]


def test_pdf_repeated_exports_retain_object_identifiers():
    first = json.loads(STIXExporter().export_analysis(sample_analysis()).serialize())
    second = json.loads(STIXExporter().export_analysis(sample_analysis()).serialize())
    assert [item["id"] for item in first["objects"]] == [
        item["id"] for item in second["objects"]
    ]


def test_api_export_failure_is_explicit_and_empty_batch_not_imported():
    from unittest.mock import Mock

    import requests

    client = Mock()
    exporter = OpenCTIExporter(Settings(), client=client)
    exporter.export_indicators([])
    client.stix2.import_bundle_from_json.assert_not_called()
    client.stix2.import_bundle_from_json.side_effect = requests.Timeout("secret")
    with pytest.raises(ExportError, match="import failed"):
        exporter.export_indicators(sample_analysis().indicators)


@pytest.mark.parametrize(
    "result",
    [
        None,
        [],
        ([], []),
        ([], [{"id": "rejected"}]),
        ([], "invalid"),
    ],
)
def test_partial_or_invalid_import_results_never_report_success(result):
    from unittest.mock import Mock

    client = Mock()
    client.stix2.import_bundle_from_json.return_value = result
    with pytest.raises(ExportError):
        OpenCTIExporter(Settings(), client=client).export_indicators(
            sample_analysis().indicators
        )


def test_deduplication_preserves_multiple_source_references_and_normalizes_case():
    first = sample_analysis().indicators[0].model_copy(update={"source_id": "one"})
    second = first.model_copy(
        update={
            "source": IntelligenceSource.OTX,
            "source_id": "two",
            "value": "EVIL.EXAMPLE",
        }
    )
    objects = json.loads(STIXExporter().export_indicators([first, second]).serialize())[
        "objects"
    ]
    assert len(objects) == 1
    assert {
        reference["external_id"] for reference in objects[0]["external_references"]
    } == {"one", "two"}
