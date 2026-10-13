"""AlienVault OTX connector."""

from __future__ import annotations

from typing import Any

import requests

from cti_automator.config import Settings
from cti_automator.connectors._http import request_json
from cti_automator.exceptions import ConnectorError
from cti_automator.models import Indicator, IndicatorType, IntelligenceSource, OTXPulse


class OTXClient:
    """Read subscribed OTX pulses and normalize their indicators."""

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
    ) -> None:
        self._settings = settings
        self._session = session or requests.Session()

    def get_pulses(self, *, modified_since: str | None = None) -> tuple[OTXPulse, ...]:
        """Fetch subscribed pulses, optionally filtered by modification time."""
        params = {"modified_since": modified_since} if modified_since else None
        payload = request_json(
            self._session,
            "GET",
            f"{self._settings.otx_base_url}/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": self._settings.require_otx_api_key()},
            params=params,
            timeout=self._settings.request_timeout,
            verify=self._settings.verify_tls,
        )
        results = payload.get("results")
        if not isinstance(results, list):
            raise ConnectorError("OTX response is missing a results list")

        pulses: list[OTXPulse] = []
        for raw_pulse in results:
            if not isinstance(raw_pulse, dict):
                raise ConnectorError("OTX response contains an invalid pulse")
            pulse_id = raw_pulse.get("id")
            name = raw_pulse.get("name")
            raw_indicators = raw_pulse.get("indicators", [])
            if not isinstance(pulse_id, str) or not isinstance(name, str):
                raise ConnectorError("OTX pulse is missing id or name")
            if not isinstance(raw_indicators, list):
                raise ConnectorError(f"OTX pulse {pulse_id} has invalid indicators")
            indicators_list: list[Indicator] = []
            for item in raw_indicators:
                if not isinstance(item, dict):
                    raise ConnectorError(
                        f"OTX pulse {pulse_id} contains an invalid indicator"
                    )
                indicators_list.append(self._indicator_from_payload(item, pulse_id))
            pulses.append(
                OTXPulse(id=pulse_id, name=name, indicators=tuple(indicators_list))
            )
        return tuple(pulses)

    @staticmethod
    def _indicator_from_payload(
        payload: dict[str, Any],
        pulse_id: str,
    ) -> Indicator:
        value = payload.get("indicator")
        indicator_type = _OTX_TYPES.get(payload.get("type"), IndicatorType.UNKNOWN)
        if not isinstance(value, str) or not value.strip():
            raise ConnectorError(f"OTX pulse {pulse_id} contains an invalid indicator")
        tags = payload.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise ConnectorError(f"OTX pulse {pulse_id} contains invalid tags")
        return Indicator(
            value=value,
            indicator_type=indicator_type,
            source=IntelligenceSource.OTX,
            source_id=str(payload.get("id", pulse_id)),
            tags=tuple(tags),
            raw_data=payload,
        )


_OTX_TYPES: dict[object, IndicatorType] = {
    "IPv4": IndicatorType.IPV4,
    "IPv6": IndicatorType.IPV6,
    "domain": IndicatorType.DOMAIN,
    "hostname": IndicatorType.DOMAIN,
    "URL": IndicatorType.URL,
    "email": IndicatorType.EMAIL,
    "FileHash-MD5": IndicatorType.FILE_HASH_MD5,
    "FileHash-SHA1": IndicatorType.FILE_HASH_SHA1,
    "FileHash-SHA256": IndicatorType.FILE_HASH_SHA256,
}
