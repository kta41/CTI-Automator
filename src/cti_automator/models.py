"""Validated internal models used by deterministic CTI ingestion."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IndicatorType(StrEnum):
    """Indicator types normalized across external providers."""

    DOMAIN = "domain-name"
    EMAIL = "email-addr"
    FILE_HASH_MD5 = "file-hash-md5"
    FILE_HASH_SHA1 = "file-hash-sha1"
    FILE_HASH_SHA256 = "file-hash-sha256"
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    URL = "url"
    UNKNOWN = "unknown"


class IntelligenceSource(StrEnum):
    """Supported deterministic intelligence sources."""

    OTX = "alienvault-otx"
    THREATFOX = "abusech-threatfox"
    PDF_REPORT = "pdf-report"


class Indicator(BaseModel):
    """A normalized observable extracted from a CTI source."""

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1)
    indicator_type: IndicatorType
    source: IntelligenceSource
    source_id: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    tags: tuple[str, ...] = ()
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str) -> str:
        """Avoid creating indicators from whitespace-only values."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("indicator value cannot be empty")
        return normalized

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, tags: tuple[str, ...]) -> tuple[str, ...]:
        """Drop empty tags while retaining stable insertion order."""
        return tuple(dict.fromkeys(tag.strip() for tag in tags if tag.strip()))


class OTXPulse(BaseModel):
    """Minimal normalized representation of an OTX pulse."""

    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    indicators: tuple[Indicator, ...]


class ThreatFoxQueryResult(BaseModel):
    """Normalized ThreatFox response."""

    query_status: str
    indicators: tuple[Indicator, ...]


class TTPMapping(BaseModel):
    """A justified mapping between report evidence and MITRE ATT&CK."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    technique_name: str = Field(min_length=1)
    tactic: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    confidence: int = Field(ge=0, le=100)


class PDFAnalysis(BaseModel):
    """Structured result returned by the local semantic analysis stage."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1)
    indicators: tuple[Indicator, ...] = ()
    ttps: tuple[TTPMapping, ...] = ()
    source_document: str = Field(min_length=1)
