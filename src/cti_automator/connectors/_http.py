"""Small shared HTTP boundary for external connectors."""

from __future__ import annotations

from typing import Any

import requests
from requests import Response

from cti_automator.exceptions import ConnectorError


def request_json(
    session: requests.Session,
    method: str,
    url: str,
    *,
    timeout: float,
    verify: bool,
    headers: dict[str, str] | None = None,
    json: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Make one request and convert transport/format failures to domain errors."""
    try:
        response: Response = session.request(
            method,
            url,
            headers=headers,
            json=json,
            params=params,
            timeout=timeout,
            verify=verify,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.exceptions.RequestException as exc:
        raise ConnectorError(f"request to {url} failed: {exc}") from exc
    except ValueError as exc:
        raise ConnectorError(f"connector returned invalid JSON from {url}") from exc

    if not isinstance(payload, dict):
        raise ConnectorError(f"connector returned a non-object JSON payload from {url}")
    return payload
