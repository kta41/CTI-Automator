"""SecOps case automation and signed ChatOps notifications."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections import defaultdict, deque
from collections.abc import Callable
from ipaddress import ip_address
from typing import Any, Literal
from urllib.parse import urlparse

import requests
from pydantic import BaseModel, ConfigDict, Field

from cti_automator.config import Settings
from cti_automator.exceptions import NotificationError, SecOpsError
from cti_automator.models import PDFAnalysis
from cti_automator.observability import observe

CaseSeverity = Literal["low", "medium", "high", "critical"]
SeverityLevel = Literal[1, 2, 3, 4]
_SEVERITY_LEVELS: dict[CaseSeverity, SeverityLevel] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def derive_severity(analysis: PDFAnalysis) -> CaseSeverity:
    """Derive a deterministic severity when the operator does not select one."""
    confidences = [
        item.confidence for item in analysis.indicators if item.confidence is not None
    ]
    if confidences and max(confidences) >= 80:
        return "high"
    if analysis.ttps and len(analysis.indicators) >= 3:
        return "medium"
    return "low"


class SecOpsCase(BaseModel):
    """A case proposal carrying only filtered, already-sanitized intelligence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str
    severity: CaseSeverity
    summary: str
    indicators: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    source_document: str
    references: tuple[str, ...] = ()
    idempotency_key: str = Field(min_length=16)

    def payload_summary(self) -> dict[str, object]:
        """Return the case without raw report text for safe display."""
        return {
            "title": self.title,
            "severity": self.severity,
            "indicators": len(self.indicators),
            "techniques": list(self.techniques),
            "source_document": self.source_document,
            "idempotency_key": self.idempotency_key,
        }


def build_case(
    analysis: PDFAnalysis, severity: CaseSeverity | None = None
) -> SecOpsCase:
    """Build one case with a deterministic idempotency key."""
    indicators = tuple(sorted({item.value for item in analysis.indicators}))
    techniques = tuple(sorted({ttp.technique_id for ttp in analysis.ttps}))
    digest = hashlib.sha256(
        json.dumps(
            [analysis.source_document, indicators, techniques],
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return SecOpsCase(
        title=f"CTI: {analysis.source_document}",
        severity=severity or derive_severity(analysis),
        summary=analysis.summary,
        indicators=indicators,
        techniques=techniques,
        source_document=analysis.source_document,
        references=(analysis.source_document,),
        idempotency_key=digest,
    )


class CaseDeliveryResult(BaseModel):
    """Outcome of one case delivery attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    destination: Literal["thehive", "xsoar"]
    status: Literal["created", "existing", "dry-run"]
    reference: str | None = None
    attempts: int = Field(ge=1)


class _CaseTransport:
    """Shared bounded-retry delivery loop with ambiguous-response reconciliation."""

    def __init__(
        self,
        settings: Settings,
        base_url: str,
        token: str,
        session: requests.Session | None,
    ) -> None:
        self._settings = settings
        self._base_url = base_url
        self._token = token
        self._session = session or requests.Session()

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> requests.Response:
        try:
            response = self._session.request(
                method,
                f"{self._base_url}{path}",
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
                json=json_body,
                timeout=self._settings.request_timeout,
                verify=self._settings.verify_tls,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise SecOpsError("SecOps destination request failed") from exc
        if response.status_code >= 500:
            raise SecOpsError("SecOps destination returned a server error")
        return response


def _reconciled_delivery(
    settings: Settings,
    destination: Literal["thehive", "xsoar"],
    search: Callable[[], str | None],
    create: Callable[[], str],
) -> CaseDeliveryResult:
    """Deliver once per key; reconcile ambiguous outcomes before recreating."""
    attempts = 0
    max_attempts = settings.secops_retry_attempts + 1
    while True:
        attempts += 1
        existing = search()
        if existing is not None:
            return CaseDeliveryResult(
                destination=destination,
                status="existing",
                reference=existing,
                attempts=attempts,
            )
        try:
            return CaseDeliveryResult(
                destination=destination,
                status="created",
                reference=create(),
                attempts=attempts,
            )
        except (requests.RequestException, SecOpsError):
            if attempts >= max_attempts:
                raise SecOpsError(f"{destination} case delivery failed") from None
            reconciled = search()
            if reconciled is not None:
                return CaseDeliveryResult(
                    destination=destination,
                    status="existing",
                    reference=reconciled,
                    attempts=attempts,
                )


class TheHiveAdapter:
    """Create TheHive cases exactly once per deterministic idempotency key."""

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
    ) -> None:
        url, token = settings.require_thehive_credentials()
        _assert_safe_destination(url, settings.secops_allowed_hosts)
        self._settings = settings
        self._transport = _CaseTransport(settings, url, token, session)

    @observe("secops")
    def deliver(self, case: SecOpsCase, *, dry_run: bool = False) -> CaseDeliveryResult:
        """Find or create the case; dry-run reports the planned payload only."""
        if dry_run:
            return CaseDeliveryResult(
                destination="thehive", status="dry-run", attempts=1
            )
        return _reconciled_delivery(
            self._settings,
            "thehive",
            lambda: self._search(case),
            lambda: self._create(case),
        )

    def _search(self, case: SecOpsCase) -> str | None:
        response = self._transport.request(
            "GET",
            "/api/v1/case",
            json_body={
                "query": {"_field": "ctiIdempotencyKey", "_value": case.idempotency_key}
            },
        )
        if response.status_code != 200:
            raise SecOpsError("TheHive search was rejected")
        payload = response.json()
        cases = payload if isinstance(payload, list) else []
        for candidate in cases:
            if isinstance(candidate, dict) and isinstance(candidate.get("_id"), str):
                return str(candidate["_id"])
        return None

    def _create(self, case: SecOpsCase) -> str:
        response = self._transport.request(
            "POST",
            "/api/v1/case",
            json_body={
                "title": case.title,
                "severity": _SEVERITY_LEVELS[case.severity],
                "description": case.summary,
                "tags": [f"cti:{value}" for value in case.indicators[:20]],
                "customFields": [
                    {
                        "name": "ctiIdempotencyKey",
                        "type": "string",
                        "value": case.idempotency_key,
                    }
                ],
            },
        )
        if response.status_code not in (200, 201):
            raise SecOpsError("TheHive rejected the case creation")
        payload = response.json()
        identifier = payload.get("_id") if isinstance(payload, dict) else None
        if not isinstance(identifier, str):
            raise SecOpsError("TheHive returned an invalid case reference")
        return identifier


class CortexXSOARAdapter:
    """Create Cortex XSOAR incidents once per deterministic idempotency key."""

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
    ) -> None:
        url, token = settings.require_xsoar_credentials()
        _assert_safe_destination(url, settings.secops_allowed_hosts)
        self._settings = settings
        self._transport = _CaseTransport(settings, url, token, session)

    @observe("secops")
    def deliver(self, case: SecOpsCase, *, dry_run: bool = False) -> CaseDeliveryResult:
        """Find or create the incident; dry-run reports the planned payload only."""
        if dry_run:
            return CaseDeliveryResult(destination="xsoar", status="dry-run", attempts=1)
        return _reconciled_delivery(
            self._settings,
            "xsoar",
            lambda: self._search(case),
            lambda: self._create(case),
        )

    def _search(self, case: SecOpsCase) -> str | None:
        response = self._transport.request(
            "POST",
            "/incidents/search",
            json_body={
                "query": f'customFields.ctiidempotencykey:="{case.idempotency_key}"'
            },
        )
        if response.status_code != 200:
            raise SecOpsError("Cortex XSOAR search was rejected")
        payload = response.json()
        total = payload.get("total") if isinstance(payload, dict) else None
        if not isinstance(total, (int, float)):
            raise SecOpsError("Cortex XSOAR returned invalid search metadata")
        if total <= 0:
            return None
        return case.idempotency_key

    def _create(self, case: SecOpsCase) -> str:
        response = self._transport.request(
            "POST",
            "/incident",
            json_body={
                "name": case.title,
                "type": "cti-automator",
                "severity": _SEVERITY_LEVELS[case.severity],
                "details": case.summary,
                "labels": [
                    {"type": "cti-indicator", "value": value}
                    for value in case.indicators[:20]
                ],
                "customFields": {"ctiidempotencykey": case.idempotency_key},
            },
        )
        if response.status_code not in (200, 201):
            raise SecOpsError("Cortex XSOAR rejected the incident creation")
        payload = response.json()
        identifier = (
            payload.get("id") if isinstance(payload, dict) else None
        ) or case.idempotency_key
        return str(identifier)


class NotificationResult(BaseModel):
    """Outcome of one ChatOps notification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    destination: str
    status: Literal["sent", "duplicate", "dry-run"]
    signed: bool


class WebhookNotifier:
    """Signed, deduplicated and SSRF-guarded ChatOps webhook delivery."""

    def __init__(
        self,
        settings: Settings,
        *,
        session: requests.Session | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._settings = settings
        self._session = session or requests.Session()
        self._clock = clock or time.monotonic
        self._recent: dict[str, deque[float]] = defaultdict(deque)
        self._sent_digests: dict[str, tuple[float, str]] = {}

    @observe("secops")
    def notify(
        self,
        destination: str,
        message: str,
        *,
        dry_run: bool = False,
    ) -> NotificationResult:
        """Send one signed notification; duplicates and spikes are refused."""
        if not message.strip():
            raise ValueError("notification message cannot be empty")
        url, secret = self._settings.chatops_destination(destination)
        signed = secret is not None
        if dry_run:
            return NotificationResult(
                destination=destination, status="dry-run", signed=signed
            )
        _assert_safe_destination(url, self._settings.secops_allowed_hosts)
        body = json.dumps(
            {"text": message[:4000], "source": "cti-automator"}, ensure_ascii=True
        ).encode("utf-8")
        now = self._clock()
        digest = hashlib.sha256(body).hexdigest()
        previous = self._sent_digests.get(destination)
        if previous and now - previous[0] < 300 and previous[1] == digest:
            return NotificationResult(
                destination=destination, status="duplicate", signed=signed
            )
        self._throttle(destination, now)
        headers = {"Content-Type": "application/json"}
        if secret is not None:
            signature = hmac.new(
                secret.encode("utf-8"), body, hashlib.sha256
            ).hexdigest()
            headers["X-CTI-Signature"] = f"sha256={signature}"
        try:
            response = self._session.post(
                url,
                data=body,
                headers=headers,
                timeout=self._settings.request_timeout,
                verify=self._settings.verify_tls,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise NotificationError("ChatOps notification request failed") from exc
        if response.status_code == 429:
            raise NotificationError("ChatOps destination rate limited the delivery")
        if response.status_code not in (200, 201, 202, 204):
            raise NotificationError("ChatOps destination rejected the notification")
        self._sent_digests[destination] = (now, digest)
        return NotificationResult(destination=destination, status="sent", signed=signed)

    def _throttle(self, destination: str, now: float) -> None:
        window = self._recent[destination]
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= 6:
            raise NotificationError("ChatOps destination frequency limit reached")
        window.append(now)


def _assert_safe_destination(url: str, allowed_hosts: tuple[str, ...]) -> None:
    """Refuse redirect-prone or internal destinations without explicit consent."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise NotificationError("ChatOps destination must be an absolute http(s) URL")
    host = parsed.hostname.lower()
    authorized = {entry.lower() for entry in allowed_hosts}
    private = False
    try:
        private = not ip_address(host).is_global
    except ValueError:
        private = host in {"localhost"} or host.endswith((".local", ".internal"))
    if (parsed.scheme != "https" or private) and host not in authorized:
        raise NotificationError(
            "ChatOps destination requires HTTPS or explicit CTI_SECOPS_ALLOWED_HOSTS"
        )
    if parsed.username or parsed.password:
        raise NotificationError("ChatOps destination cannot embed credentials")
