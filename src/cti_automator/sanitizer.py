"""Configurable PII redaction applied before any LLM call or embedding."""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cti_automator.config import Settings
from cti_automator.exceptions import SanitizationError
from cti_automator.observability import record_redactions

_EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IPV4_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
_IPV6_PATTERN = re.compile(
    r"(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])"
)


class SanitizedText(BaseModel):
    """Result of one sanitization pass; never carries original protected values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str
    counts: dict[str, int] = Field(default_factory=dict)

    @property
    def total(self) -> int:
        """Total number of redactions across categories."""
        return sum(self.counts.values())


class SanitizationPolicy(BaseModel):
    """Declare what must be protected and which public values stay untouched."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    email_domains: tuple[str, ...] = ()
    internal_networks: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    allowed_values: frozenset[str] = frozenset()

    @field_validator("names")
    @classmethod
    def drop_ambiguous_short_names(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        """Ignore names too short to redact without high false positives."""
        return tuple(dict.fromkeys(name for name in names if len(name.strip()) >= 3))

    @classmethod
    def from_settings(cls, settings: Settings) -> Self:
        """Build the policy from validated runtime settings."""
        return cls(
            email_domains=settings.dlp_email_domains,
            internal_networks=settings.dlp_internal_cidrs,
            names=tuple(name.strip() for name in settings.dlp_names if name.strip()),
            allowed_values=frozenset(
                value.strip().lower()
                for value in settings.dlp_allowed_values
                if value.strip()
            ),
        )


class Sanitizer:
    """Redact protected values with stable per-instance placeholder tokens."""

    def __init__(self, policy: SanitizationPolicy, *, enabled: bool = True) -> None:
        self._policy = policy
        self._enabled = enabled
        self._tokens: dict[tuple[str, str], str] = {}
        self._category_counts: dict[str, int] = {"email": 0, "ip": 0, "name": 0}
        try:
            self._networks = tuple(
                ip_network(cidr, strict=False) for cidr in policy.internal_networks
            )
        except ValueError as exc:
            raise SanitizationError("DLP internal networks are invalid") from exc

    @classmethod
    def from_settings(cls, settings: Settings) -> Sanitizer:
        """Create the sanitizer declared by settings; disabled is a no-op."""
        return cls(
            SanitizationPolicy.from_settings(settings),
            enabled=settings.dlp_enabled,
        )

    @property
    def enabled(self) -> bool:
        """Whether this instance actively redacts text."""
        return self._enabled

    def sanitize(self, text: str) -> SanitizedText:
        """Return redacted text; any failure blocks the protected operation."""
        if not self._enabled:
            return SanitizedText(text=text)
        try:
            result = self._redact(text)
        except SanitizationError:
            raise
        except Exception as exc:  # regex or addressing engine failures are blocking
            raise SanitizationError("DLP sanitization failed") from exc
        if not result.text.strip():
            raise SanitizationError("DLP sanitization emptied the document text")
        record_redactions(dict(result.counts))
        return result

    def _redact(self, text: str) -> SanitizedText:
        counts: dict[str, int] = {"email": 0, "ip": 0, "name": 0}
        text = self._redact_emails(text, counts)
        text = self._redact_ips(text, counts)
        text = self._redact_names(text, counts)
        return SanitizedText(text=text, counts=counts)

    def _redact_emails(self, text: str, counts: dict[str, int]) -> str:
        if not self._policy.email_domains:
            return text

        def replace(match: re.Match[str]) -> str:
            address = match.group(0)
            if address.lower() in self._policy.allowed_values:
                return address
            domain = address.rsplit("@", 1)[1].lower()
            if not any(
                domain == suffix or domain.endswith("." + suffix)
                for suffix in self._policy.email_domains
            ):
                return address
            counts["email"] += 1
            return self._token("email", address.lower())

        return _EMAIL_PATTERN.sub(replace, text)

    def _redact_ips(self, text: str, counts: dict[str, int]) -> str:
        if not self._networks:
            return text

        def replace(match: re.Match[str]) -> str:
            raw = match.group(0)
            if raw.lower() in self._policy.allowed_values:
                return raw
            try:
                address = ip_address(raw)
            except ValueError:
                return raw
            if not any(address in network for network in self._networks):
                return raw
            counts["ip"] += 1
            return self._token("ip", str(address))

        text = _IPV4_PATTERN.sub(replace, text)
        return _IPV6_PATTERN.sub(replace, text)

    def _redact_names(self, text: str, counts: dict[str, int]) -> str:
        for name in self._policy.names:
            if name.lower() in self._policy.allowed_values:
                continue
            pattern = re.compile(rf"(?<![\w]){re.escape(name)}(?![\w])", re.IGNORECASE)
            occurrences = len(pattern.findall(text))
            if occurrences:
                counts["name"] += occurrences
                text = pattern.sub(self._token("name", name.lower()), text)
        return text

    def _token(self, category: str, value: str) -> str:
        """Map one protected value to one stable placeholder per instance."""
        key = (category, value)
        token = self._tokens.get(key)
        if token is None:
            self._category_counts[category] += 1
            token = f"<CTI_{category.upper()}_{self._category_counts[category]}>"
            self._tokens[key] = token
        return token


def audit_protected_values(text: str, policy: SanitizationPolicy) -> dict[str, int]:
    """Count protected values still present; used to inspect prompts and exports."""
    findings: dict[str, int] = {"email": 0, "ip": 0, "name": 0}
    allowed = set(policy.allowed_values)
    for match in _EMAIL_PATTERN.finditer(text):
        address = match.group(0)
        if address.lower() in allowed:
            continue
        domain = address.rsplit("@", 1)[1].lower()
        if any(
            domain == suffix or domain.endswith("." + suffix)
            for suffix in policy.email_domains
        ):
            findings["email"] += 1
    networks = tuple(
        ip_network(cidr, strict=False) for cidr in policy.internal_networks
    )
    for pattern in (_IPV4_PATTERN, _IPV6_PATTERN):
        for match in pattern.finditer(text):
            raw = match.group(0)
            if raw.lower() in allowed:
                continue
            try:
                candidate = ip_address(raw)
            except ValueError:
                continue
            if any(candidate in network for network in networks):
                findings["ip"] += 1
    for name in policy.names:
        if name.lower() in allowed:
            continue
        findings["name"] += len(
            re.findall(rf"(?<![\w]){re.escape(name)}(?![\w])", text, re.IGNORECASE)
        )
    return findings
