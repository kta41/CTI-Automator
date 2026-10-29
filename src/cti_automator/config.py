"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
import re
from ipaddress import ip_network
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _parse_named_values(raw: str) -> tuple[tuple[str, str], ...]:
    """Parse ``name=value`` comma-separated pairs used by ChatOps destinations."""
    pairs: list[tuple[str, str]] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        name, separator, value = item.partition("=")
        if not separator or not name.strip() or not value.strip():
            raise ValueError("named values must use name=value pairs")
        pairs.append((name.strip(), value.strip()))
    return tuple(pairs)


class Settings(BaseModel):
    """Runtime settings shared by deterministic ingestion connectors."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    otx_api_key: str | None = Field(default=None, repr=False)
    otx_base_url: str = "https://otx.alienvault.com"
    abusech_api_key: str | None = Field(default=None, repr=False)
    threatfox_base_url: str = "https://threatfox-api.abuse.ch"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"
    ai_provider: str = "ollama"
    ai_api_key: str | None = Field(default=None, repr=False)
    ai_base_url: str = "https://api.openai.com/v1"
    ai_model: str = "gpt-4o-mini"
    opencti_url: str | None = None
    opencti_token: str | None = Field(default=None, repr=False)
    request_timeout: float = Field(default=30.0, gt=0)
    verify_tls: bool = True
    virustotal_api_key: str | None = Field(default=None, repr=False)
    shodan_api_key: str | None = Field(default=None, repr=False)
    enrichment_cache_ttl: float = Field(default=3600, gt=0)
    enrichment_requests_per_minute: int = Field(default=4, ge=1, le=1000)
    restricted_domains: tuple[str, ...] = ()
    github_token: str | None = Field(default=None, repr=False)
    repository_allowlist: tuple[str, ...] = ()
    repository_checkpoint: str = "/state/repositories.json"
    repository_max_files: int = Field(default=20, ge=1, le=100)
    repository_max_bytes: int = Field(default=100_000, ge=1, le=1_000_000)
    pdf_max_bytes: int = Field(default=20_000_000, ge=1, le=100_000_000)
    pdf_max_pages: int = Field(default=100, ge=1, le=2_000)
    allowed_pdf_dir: str | None = None
    analysis_cache_dir: str | None = None
    log_level: str = "INFO"
    dlp_enabled: bool = False
    dlp_email_domains: tuple[str, ...] = ()
    dlp_internal_cidrs: tuple[str, ...] = ()
    dlp_names: tuple[str, ...] = ()
    dlp_allowed_values: tuple[str, ...] = ()
    detection_pr_allowlist: tuple[str, ...] = ()
    memory_enabled: bool = False
    memory_url: str = "http://localhost:6333"
    memory_collection: str = "cti-memory"
    memory_embedding_model: str = "nomic-embed-text"
    memory_tenant: str = "default"
    memory_remote_embeddings: bool = False
    memory_retention_days: int = Field(default=365, ge=1, le=3650)
    thehive_url: str | None = None
    thehive_token: str | None = Field(default=None, repr=False)
    xsoar_url: str | None = None
    xsoar_token: str | None = Field(default=None, repr=False)
    secops_allowed_hosts: tuple[str, ...] = ()
    secops_retry_attempts: int = Field(default=2, ge=0, le=5)
    chatops_webhooks: tuple[tuple[str, str], ...] = ()
    chatops_signing_secrets: tuple[tuple[str, str], ...] = ()

    @field_validator("restricted_domains")
    @classmethod
    def normalize_restricted_domains(cls, domains: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                domain.strip().lower().rstrip(".")
                for domain in domains
                if domain.strip()
            )
        )

    @field_validator(
        "otx_base_url",
        "threatfox_base_url",
        "ollama_base_url",
        "ai_base_url",
        "opencti_url",
        "thehive_url",
        "xsoar_url",
        "memory_url",
    )
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        """Reject malformed connector URLs before making a network request."""
        value = value.strip().rstrip("/")
        if not value.startswith(("http://", "https://")):
            raise ValueError("connector URLs must use http:// or https://")
        return value

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, value: str) -> str:
        """Allow only supported provider adapters."""
        normalized = value.strip().lower()
        if normalized not in {"ollama", "openai", "groq"}:
            raise ValueError("AI_PROVIDER must be ollama, openai, or groq")
        return normalized

    @field_validator("dlp_email_domains")
    @classmethod
    def normalize_dlp_email_domains(cls, domains: tuple[str, ...]) -> tuple[str, ...]:
        """Normalize corporate email domains for case-insensitive matching."""
        return tuple(
            dict.fromkeys(
                domain.strip().lower().lstrip("@").rstrip(".")
                for domain in domains
                if domain.strip()
            )
        )

    @field_validator("dlp_internal_cidrs")
    @classmethod
    def validate_internal_cidrs(cls, cidrs: tuple[str, ...]) -> tuple[str, ...]:
        """Reject malformed DLP CIDR blocks before they are used for redaction."""
        for cidr in cidrs:
            try:
                ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(
                    "CTI_DLP_INTERNAL_CIDRS contains an invalid network"
                ) from exc
        return tuple(dict.fromkeys(cidrs))

    @field_validator("memory_tenant")
    @classmethod
    def validate_memory_tenant(cls, value: str) -> str:
        """Keep tenant identifiers bounded and usable as filter values."""
        normalized = value.strip().lower()
        if (
            not normalized
            or len(normalized) > 64
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", normalized)
        ):
            raise ValueError("CTI_MEMORY_TENANT must be a short slug identifier")
        return normalized

    @field_validator("chatops_webhooks", "chatops_signing_secrets")
    @classmethod
    def validate_chatops_pairs(
        cls, pairs: tuple[tuple[str, str], ...]
    ) -> tuple[tuple[str, str], ...]:
        """Keep ChatOps destination names bounded and non-empty."""
        names: list[str] = []
        for name, value in pairs:
            if not name.strip() or not value.strip() or len(name) > 64:
                raise ValueError("ChatOps destinations need a name and a value")
            names.append(name.strip())
        if len(names) != len(set(names)):
            raise ValueError("ChatOps destination names must be unique")
        return tuple((name.strip(), value.strip()) for name, value in pairs)

    @classmethod
    def from_env(cls) -> Self:
        """Build settings from the documented environment variables."""
        values: dict[str, object] = {}
        environment_map = {
            "OTX_API_KEY": "otx_api_key",
            "OTX_BASE_URL": "otx_base_url",
            "ABUSECH_API_KEY": "abusech_api_key",
            "THREATFOX_BASE_URL": "threatfox_base_url",
            "CTI_REQUEST_TIMEOUT": "request_timeout",
            "CTI_VERIFY_TLS": "verify_tls",
            "OPENCTI_VERIFY_TLS": "verify_tls",
            "OLLAMA_BASE_URL": "ollama_base_url",
            "OLLAMA_MODEL": "ollama_model",
            "AI_PROVIDER": "ai_provider",
            "AI_API_KEY": "ai_api_key",
            "AI_BASE_URL": "ai_base_url",
            "AI_MODEL": "ai_model",
            "OPENCTI_URL": "opencti_url",
            "OPENCTI_TOKEN": "opencti_token",
            "VIRUSTOTAL_API_KEY": "virustotal_api_key",
            "SHODAN_API_KEY": "shodan_api_key",
            "CTI_ENRICHMENT_CACHE_TTL": "enrichment_cache_ttl",
            "CTI_ENRICHMENT_RPM": "enrichment_requests_per_minute",
            "GITHUB_TOKEN": "github_token",
            "CTI_REPOSITORY_CHECKPOINT": "repository_checkpoint",
            "CTI_REPOSITORY_MAX_FILES": "repository_max_files",
            "CTI_REPOSITORY_MAX_BYTES": "repository_max_bytes",
            "CTI_PDF_MAX_BYTES": "pdf_max_bytes",
            "CTI_PDF_MAX_PAGES": "pdf_max_pages",
            "CTI_ALLOWED_PDF_DIR": "allowed_pdf_dir",
            "CTI_ANALYSIS_CACHE_DIR": "analysis_cache_dir",
            "CTI_LOG_LEVEL": "log_level",
            "CTI_DLP_ENABLED": "dlp_enabled",
            "CTI_MEMORY_ENABLED": "memory_enabled",
            "CTI_MEMORY_URL": "memory_url",
            "CTI_MEMORY_COLLECTION": "memory_collection",
            "CTI_MEMORY_EMBEDDING_MODEL": "memory_embedding_model",
            "CTI_MEMORY_TENANT": "memory_tenant",
            "CTI_MEMORY_REMOTE_EMBEDDINGS": "memory_remote_embeddings",
            "CTI_MEMORY_RETENTION_DAYS": "memory_retention_days",
            "CTI_THEHIVE_URL": "thehive_url",
            "CTI_THEHIVE_TOKEN": "thehive_token",
            "CTI_XSOAR_URL": "xsoar_url",
            "CTI_XSOAR_TOKEN": "xsoar_token",
            "CTI_SECOPS_RETRY_ATTEMPTS": "secops_retry_attempts",
        }
        for environment_name, field_name in environment_map.items():
            value = os.getenv(environment_name)
            if value is not None and value.strip():
                values[field_name] = value
        for env, name in {
            "CTI_REPOSITORY_ALLOWLIST": "repository_allowlist",
            "CTI_RESTRICTED_DOMAINS": "restricted_domains",
            "CTI_DLP_EMAIL_DOMAINS": "dlp_email_domains",
            "CTI_DLP_INTERNAL_CIDRS": "dlp_internal_cidrs",
            "CTI_DLP_NAMES": "dlp_names",
            "CTI_DLP_ALLOWED_VALUES": "dlp_allowed_values",
            "CTI_DETECTION_PR_ALLOWLIST": "detection_pr_allowlist",
            "CTI_SECOPS_ALLOWED_HOSTS": "secops_allowed_hosts",
        }.items():
            values[name] = tuple(
                item.strip() for item in os.getenv(env, "").split(",") if item.strip()
            )
        values["chatops_webhooks"] = _parse_named_values(
            os.getenv("CTI_CHATOPS_WEBHOOKS", "")
        )
        values["chatops_signing_secrets"] = _parse_named_values(
            os.getenv("CTI_CHATOPS_SECRETS", "")
        )
        return cls.model_validate(values)

    def require_otx_api_key(self) -> str:
        """Return the OTX key or fail explicitly when OTX is requested."""
        if not self.otx_api_key:
            raise ValueError("OTX_API_KEY is required for AlienVault OTX")
        return self.otx_api_key

    def require_abusech_api_key(self) -> str:
        """Return the Abuse.ch key or fail explicitly when ThreatFox needs it."""
        if not self.abusech_api_key:
            raise ValueError("ABUSECH_API_KEY is required for ThreatFox")
        return self.abusech_api_key

    def require_ai_api_key(self) -> str:
        """Return a hosted-provider key or fail before making a request."""
        if not self.ai_api_key:
            raise ValueError("AI_API_KEY is required for hosted AI providers")
        return self.ai_api_key

    def require_opencti_credentials(self) -> tuple[str, str]:
        """Return OpenCTI URL and token or fail before connecting."""
        if not self.opencti_url or not self.opencti_token:
            raise ValueError("OPENCTI_URL and OPENCTI_TOKEN are required")
        return self.opencti_url, self.opencti_token

    def require_thehive_credentials(self) -> tuple[str, str]:
        """Return TheHive URL and token or fail before creating a case."""
        if not self.thehive_url or not self.thehive_token:
            raise ValueError("CTI_THEHIVE_URL and CTI_THEHIVE_TOKEN are required")
        return self.thehive_url, self.thehive_token

    def require_xsoar_credentials(self) -> tuple[str, str]:
        """Return Cortex XSOAR URL and token or fail before creating an incident."""
        if not self.xsoar_url or not self.xsoar_token:
            raise ValueError("CTI_XSOAR_URL and CTI_XSOAR_TOKEN are required")
        return self.xsoar_url, self.xsoar_token

    def chatops_destination(self, name: str) -> tuple[str, str | None]:
        """Return the configured webhook URL and signing secret for a name."""
        webhooks = dict(self.chatops_webhooks)
        if name not in webhooks:
            raise ValueError("ChatOps destination is not configured")
        secret = dict(self.chatops_signing_secrets).get(name)
        return webhooks[name], secret
