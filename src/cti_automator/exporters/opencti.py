"""OpenCTI delivery adapter using pycti."""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from typing import Protocol, cast

import requests

from cti_automator.config import Settings
from cti_automator.exceptions import ExportError
from cti_automator.exporters.stix import STIXExporter
from cti_automator.models import Indicator, PDFAnalysis
from cti_automator.observability import ITEMS, observe


class STIXImporter(Protocol):
    """Minimal pycti surface required by the exporter."""

    def import_bundle_from_json(self, bundle: str, *, update: bool) -> object:
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

    @observe("opencti")
    def export_analysis(self, analysis: PDFAnalysis) -> str:
        """Import an analysis and return the serialized bundle."""
        bundle = self._stix_exporter.export_analysis(analysis)
        serialized = cast(str, bundle.serialize())
        self._import(serialized)
        return serialized

    @observe("opencti")
    def export_indicators(self, indicators: Sequence[Indicator]) -> str:
        """Import API indicators, skipping only a genuinely empty batch."""
        serialized = cast(
            str, self._stix_exporter.export_indicators(indicators).serialize()
        )
        if indicators:
            self._import(serialized)
        return serialized

    def _import(self, serialized: str) -> None:
        expected = {item["id"] for item in json.loads(serialized).get("objects", [])}
        if not expected:
            return
        try:
            result = self._client.stix2.import_bundle_from_json(serialized, update=True)
        except (requests.RequestException, ValueError) as exc:
            raise ExportError("OpenCTI bundle import failed") from exc
        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not isinstance(result[0], list)
            or not isinstance(result[1], list)
        ):
            raise ExportError("OpenCTI returned an invalid import result")
        imported, rejected = result
        if not all(
            isinstance(item, dict) and isinstance(item.get("id"), str)
            for item in imported
        ):
            raise ExportError("OpenCTI returned invalid imported object identifiers")
        imported_ids = {item["id"] for item in imported}
        if rejected or not expected.issubset(imported_ids):
            raise ExportError("OpenCTI did not import every requested STIX object")
        ITEMS.labels("opencti").inc(len(expected))


def _build_pycti_client(settings: Settings) -> OpenCTIApi:
    url, token = settings.require_opencti_credentials()
    try:
        from pycti import OpenCTIApiClient
    except ImportError as exc:
        raise ExportError(
            "pycti and system libmagic are required for OpenCTI export"
        ) from exc
    try:
        return cast(
            OpenCTIApi,
            OpenCTIApiClient(
                url,
                token,
                ssl_verify=settings.verify_tls,
                requests_timeout=math.ceil(settings.request_timeout),
            ),
        )
    except (requests.RequestException, ValueError) as exc:
        raise ExportError("OpenCTI connection initialization failed") from exc
