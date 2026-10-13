"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Settings(BaseModel):
    """Runtime settings shared by deterministic ingestion connectors."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    otx_api_key: str | None = Field(default=None, repr=False)
    otx_base_url: str = "https://otx.alienvault.com"
    abusech_api_key: str | None = Field(default=None, repr=False)
    threatfox_base_url: str = "https://threatfox-api.abuse.ch"
    request_timeout: float = Field(default=30.0, gt=0)
    verify_tls: bool = True

    @field_validator("otx_base_url", "threatfox_base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        """Reject malformed connector URLs before making a network request."""
        value = value.strip().rstrip("/")
        if not value.startswith(("http://", "https://")):
            raise ValueError("connector URLs must use http:// or https://")
        return value

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
        }
        for environment_name, field_name in environment_map.items():
            value = os.getenv(environment_name)
            if value is not None and value.strip():
                values[field_name] = value
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
