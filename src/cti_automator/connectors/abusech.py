"""Abuse.ch ThreatFox connector."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import requests

from cti_automator.config import Settings
from cti_automator.connectors._http import request_json
from cti_automator.exceptions import ConnectorError
from cti_automator.models import (
    Indicator,
    IndicatorType,
    IntelligenceSource,
    ThreatFoxQueryResult,
)


class ThreatFoxClient:
    """Query ThreatFox IOCs through the Abuse.ch API."""

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
    ) -> None:
        self._settings = settings
        self._session = session or requests.Session()

    def get_recent_iocs(self, *, days: int = 1) -> ThreatFoxQueryResult:
        """Fetch IOCs published during the requested number of days."""
        if days < 1:
            raise ValueError("days must be greater than zero")
        payload = self._post({"query": "get_iocs", "days": days})
        return self._parse_result(payload)

    def search_ioc(self, value: str) -> ThreatFoxQueryResult:
        """Search ThreatFox for one exact IOC value."""
        if not value.strip():
            raise ValueError("IOC value cannot be empty")
        payload = self._post({"query": "search_ioc", "search_term": value.strip()})
        return self._parse_result(payload)

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        return request_json(
            self._session,
            "POST",
            f"{self._settings.threatfox_base_url}/api/v1/",
            headers={
                "Auth-Key": self._settings.require_abusech_api_key(),
                "Content-Type": "application/json",
            },
            json=body,
            timeout=self._settings.request_timeout,
            verify=self._settings.verify_tls,
        )

    @staticmethod
    def _parse_result(payload: dict[str, Any]) -> ThreatFoxQueryResult:
        query_status = payload.get("query_status")
        raw_data = payload.get("data", [])
        if not isinstance(query_status, str) or not isinstance(raw_data, list):
            raise ConnectorError("ThreatFox response has an invalid shape")
        indicators_list: list[Indicator] = []
        for item in raw_data:
            if not isinstance(item, dict):
                raise ConnectorError("ThreatFox response contains an invalid IOC")
            indicators_list.append(_indicator_from_payload(item))
        return ThreatFoxQueryResult(
            query_status=query_status,
            indicators=tuple(indicators_list),
        )


def _indicator_from_payload(payload: dict[str, Any]) -> Indicator:
    value = payload.get("ioc")
    if not isinstance(value, str) or not value.strip():
        raise ConnectorError("ThreatFox response contains an invalid IOC")
    return Indicator(
        value=value,
        indicator_type=_THREATFOX_TYPES.get(
            payload.get("ioc_type"),
            IndicatorType.UNKNOWN,
        ),
        source=IntelligenceSource.THREATFOX,
        source_id=_as_string(payload.get("id")),
        first_seen=_parse_datetime(payload.get("first_seen")),
        last_seen=_parse_datetime(payload.get("last_seen")),
        confidence=_as_confidence(payload.get("confidence_level")),
        tags=_tags_from_payload(payload),
        raw_data=payload,
    )


def _as_string(value: object) -> str | None:
    return str(value) if value is not None else None


def _as_confidence(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ConnectorError("ThreatFox response contains an invalid confidence level")


def _parse_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ConnectorError("ThreatFox response contains an invalid timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ConnectorError(
            "ThreatFox response contains an invalid timestamp"
        ) from None


def _tags_from_payload(payload: dict[str, Any]) -> tuple[str, ...]:
    tags = payload.get("tags")
    if tags is None:
        return ()
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise ConnectorError("ThreatFox response contains invalid tags")
    return tuple(tags)


_THREATFOX_TYPES: dict[object, IndicatorType] = {
    "domain": IndicatorType.DOMAIN,
    "ip:port": IndicatorType.IPV4,
    "url": IndicatorType.URL,
    "md5_hash": IndicatorType.FILE_HASH_MD5,
    "sha1_hash": IndicatorType.FILE_HASH_SHA1,
    "sha256_hash": IndicatorType.FILE_HASH_SHA256,
}
