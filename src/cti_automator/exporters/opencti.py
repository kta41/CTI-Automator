"""OpenCTI delivery adapter using pycti."""

from __future__ import annotations

from typing import Protocol, cast

from cti_automator.config import Settings
from cti_automator.exceptions import ExportError
from cti_automator.exporters.stix import STIXExporter
from cti_automator.models import PDFAnalysis


class STIXImporter(Protocol):
    """Minimal pycti surface required by the exporter."""

    def import_bundle(self, bundle: str) -> object:
        """Import a serialized STIX bundle."""


class OpenCTIApi(Protocol):
    """Minimal OpenCTI API surface used by this package."""

    stix2: STIXImporter


class OpenCTIExporter:
    """Serialize STIX and import it into OpenCTI."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: OpenCTIApi | None = None,
        stix_exporter: STIXExporter | None = None,
    ) -> None:
        self._settings = settings
        self._client = client or _build_pycti_client(settings)
        self._stix_exporter = stix_exporter or STIXExporter()

    def export_analysis(self, analysis: PDFAnalysis) -> str:
        """Import an analysis and return the serialized bundle."""
        bundle = self._stix_exporter.export_analysis(analysis)
        serialized = cast(str, bundle.serialize())
        self._client.stix2.import_bundle(serialized)
        return serialized


def _build_pycti_client(settings: Settings) -> OpenCTIApi:
    url, token = settings.require_opencti_credentials()
    try:
        from pycti import OpenCTIApiClient
    except ImportError as exc:
        raise ExportError("pycti is required for OpenCTI export") from exc
    return cast(
        OpenCTIApi,
        OpenCTIApiClient(url, token, ssl_verify=settings.verify_tls),
    )
