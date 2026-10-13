"""Explicitly authorized, privacy-filtered external enrichment."""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from ipaddress import IPv6Address, ip_address
from threading import Lock
from typing import Literal
from urllib.parse import quote

import requests
from pydantic import BaseModel, Field, ValidationError

from cti_automator.config import Settings
from cti_automator.exceptions import ConnectorError
from cti_automator.models import EnrichmentResult, Indicator, IndicatorType
from cti_automator.observability import observe

Provider = Literal["virustotal", "shodan"]


class QuotaError(ConnectorError):
    """A local request budget or remote rate limit was exceeded."""


class _VTStats(BaseModel):
    malicious: int = Field(ge=0)
    suspicious: int = Field(ge=0)
    harmless: int = Field(ge=0)
    undetected: int = Field(ge=0)
    timeout: int = Field(default=0, ge=0)


def check_public_indicator(
    indicator: Indicator, restricted_domains: Sequence[str]
) -> None:
    """Refuse PII, internal addresses, URLs and invalid values before any request."""
    value = indicator.value
    kind = indicator.indicator_type
    if kind in {IndicatorType.IPV4, IndicatorType.IPV6}:
        address = ip_address(value)
        if (kind == IndicatorType.IPV4) != (address.version == 4):
            raise ValueError("External enrichment refuses an IP type mismatch")
        if not address.is_global or (
            isinstance(address, IPv6Address)
            and address.ipv4_mapped is not None
            and not address.ipv4_mapped.is_global
        ):
            raise ValueError("External enrichment refuses internal or reserved IPs")
        return
    if kind == IndicatorType.DOMAIN:
        domain = value.lower().rstrip(".")
        if (
            len(domain) > 253
            or not re.fullmatch(
                r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain
            )
            or any(
                domain == suffix or domain.endswith("." + suffix)
                for suffix in (
                    "local",
                    "internal",
                    "localhost",
                    "lan",
                    "home",
                    "test",
                    "invalid",
                    "example",
                    "example.com",
                    "example.net",
                    "example.org",
                    "onion",
                    "arpa",
                    "alt",
                    *restricted_domains,
                )
            )
        ):
            raise ValueError("External enrichment refuses internal or invalid domains")
        return
    lengths = {
        IndicatorType.FILE_HASH_MD5: 32,
        IndicatorType.FILE_HASH_SHA1: 40,
        IndicatorType.FILE_HASH_SHA256: 64,
    }
    length = lengths.get(kind)
    if length and re.fullmatch(rf"[a-fA-F0-9]{{{length}}}", value):
        return
    raise ValueError(
        "External enrichment allows only public IPs/domains and valid hashes"
    )


class EnrichmentService:
    """Process-scoped TTL cache and per-provider request budgets."""

    def __init__(
        self,
        settings: Settings,
        *,
        session: requests.Session | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.session = session or requests.Session()
        self.clock = clock
        self.cache: dict[
            tuple[Provider, IndicatorType, str], tuple[float, EnrichmentResult]
        ] = {}
        self.budgets: dict[Provider, list[float]] = {}
        self.lock = Lock()

    @observe("enrichment")
    def enrich(
        self,
        indicators: Sequence[Indicator],
        providers: Sequence[Provider] = (),
    ) -> tuple[Indicator, ...]:
        if not providers:
            return tuple(indicators)
        providers = tuple(dict.fromkeys(providers))
        for provider in providers:
            self._key(provider)
        for item in indicators:
            check_public_indicator(item, self.settings.restricted_domains)
            if (
                "shodan" in providers
                and item.indicator_type not in {IndicatorType.IPV4, IndicatorType.IPV6}
                and "virustotal" not in providers
            ):
                raise ValueError("Shodan enrichment supports only IP indicators")
        output: list[Indicator] = []
        with self.lock:
            for item in indicators:
                results = {result.provider: result for result in item.enrichments}
                for provider in providers:
                    if provider == "shodan" and item.indicator_type not in {
                        IndicatorType.IPV4,
                        IndicatorType.IPV6,
                    }:
                        continue
                    key = (provider, item.indicator_type, item.value.lower())
                    now = self.clock()
                    cached = self.cache.get(key)
                    if cached and cached[0] > now:
                        result = cached[1]
                    else:
                        budget = [
                            stamp
                            for stamp in self.budgets.get(provider, [])
                            if now - stamp < 60
                        ]
                        if len(budget) >= self.settings.enrichment_requests_per_minute:
                            raise QuotaError(
                                f"{provider} local request budget exhausted"
                            )
                        self.budgets[provider] = [*budget, now]
                        result = self._query(provider, item)
                        if len(self.cache) >= 1000:
                            self.cache.pop(next(iter(self.cache)))
                        self.cache[key] = (
                            self.clock() + self.settings.enrichment_cache_ttl,
                            result,
                        )
                    results[provider] = result
                output.append(
                    item.model_copy(update={"enrichments": tuple(results.values())})
                )
        return tuple(output)

    def _key(self, provider: Provider) -> str:
        if provider not in {"virustotal", "shodan"}:
            raise ValueError("Unknown enrichment provider")
        key = (
            self.settings.virustotal_api_key
            if provider == "virustotal"
            else self.settings.shodan_api_key
        )
        if not key:
            raise ValueError(f"{provider.upper()}_API_KEY is required for enrichment")
        return key

    def _query(self, provider: Provider, item: Indicator) -> EnrichmentResult:
        key = self._key(provider)
        if provider == "virustotal":
            resource = (
                "ip_addresses"
                if item.indicator_type in {IndicatorType.IPV4, IndicatorType.IPV6}
                else "domains"
                if item.indicator_type == IndicatorType.DOMAIN
                else "files"
            )
            url = f"https://www.virustotal.com/api/v3/{resource}/{quote(item.value, safe='')}"
            params = None
            headers = {"x-apikey": key}
            gui = (
                "ip-address"
                if resource == "ip_addresses"
                else "domain"
                if resource == "domains"
                else "file"
            )
            reference = (
                f"https://www.virustotal.com/gui/{gui}/{quote(item.value, safe='')}"
            )
        else:
            url = f"https://api.shodan.io/shodan/host/{quote(item.value, safe='')}"
            params = {"key": key}
            headers = {}
            reference = f"https://www.shodan.io/host/{quote(item.value, safe='')}"
        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.settings.request_timeout,
                verify=self.settings.verify_tls,
                allow_redirects=False,
            )
            if response.status_code == 429:
                raise QuotaError(f"{provider} remote rate limit exceeded")
            if response.status_code == 404:
                return EnrichmentResult(
                    provider=provider,
                    retrieved_at=datetime.now(UTC),
                    status="not-found",
                    reference_url=reference,
                )
            response.raise_for_status()
            if response.status_code != 200:
                raise ConnectorError(f"{provider} unexpected HTTP response")
            payload = response.json()
            confidence = None
            tags: tuple[str, ...] = ()
            if provider == "virustotal":
                stats = _VTStats.model_validate(
                    payload["data"]["attributes"]["last_analysis_stats"]
                )
                total = sum(stats.model_dump().values())
                confidence = round(100 * stats.malicious / total) if total else None
            else:
                if not isinstance(payload, dict) or not isinstance(
                    payload.get("ip_str"), str
                ):
                    raise ValueError("Invalid Shodan result")
                raw_tags = payload.get("tags", [])
                if not isinstance(raw_tags, list) or not all(
                    isinstance(tag, str) for tag in raw_tags
                ):
                    raise ValueError("Invalid Shodan tags")
                tags = tuple(raw_tags[:20])
            return EnrichmentResult(
                provider=provider,
                retrieved_at=datetime.now(UTC),
                status="found",
                reference_url=reference,
                confidence=confidence,
                tags=tags,
            )
        except requests.RequestException as exc:
            raise ConnectorError(f"{provider} request failed") from exc
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise ConnectorError(f"{provider} returned malformed enrichment") from exc
