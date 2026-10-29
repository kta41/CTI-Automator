"""Local environment and external dependency diagnostic checks."""

from __future__ import annotations

import shutil
from typing import Literal

import requests
from pydantic import BaseModel, ConfigDict

from cti_automator.config import Settings

OPENCTI_RECOMMENDED_VERSION = "6.9.29"
THEHIVE_RECOMMENDED_VERSION = "5.5.0-1"
OLLAMA_RECOMMENDED_VERSION = "0.5.12"
QDRANT_RECOMMENDED_VERSION = "v1.13.4"

OPENCTI_IMAGE = f"opencti/platform:{OPENCTI_RECOMMENDED_VERSION}"
THEHIVE_IMAGE = f"strangebee/thehive:{THEHIVE_RECOMMENDED_VERSION}"
OLLAMA_IMAGE = f"ollama/ollama:{OLLAMA_RECOMMENDED_VERSION}"
QDRANT_IMAGE = f"qdrant/qdrant:{QDRANT_RECOMMENDED_VERSION}"

ServiceStatus = Literal["ok", "missing", "unreachable", "unconfigured"]


class ServiceDiagnosis(BaseModel):
    """Status and installation guidance for one external dependency."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service: str
    status: ServiceStatus
    recommended_version: str
    image: str
    configured_url: str | None = None
    detected_version: str | None = None
    install_proposal: str | None = None


class DoctorReport(BaseModel):
    """Aggregate diagnostic report for local and external dependencies."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    healthy: bool
    docker_installed: bool
    ollama_binary_installed: bool
    services: tuple[ServiceDiagnosis, ...]


def _probe_http(
    session: requests.Session,
    url: str,
    *,
    timeout: float,
    verify: bool,
    headers: dict[str, str] | None = None,
) -> tuple[bool, dict[str, object] | None]:
    try:
        response = session.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=verify,
            allow_redirects=False,
        )
        if 200 <= response.status_code < 500:
            try:
                data = response.json()
                return True, data if isinstance(data, dict) else None
            except ValueError:
                return True, None
    except requests.RequestException:
        return False, None
    return False, None


def _check_opencti(
    settings: Settings, session: requests.Session, timeout: float
) -> ServiceDiagnosis:
    url = settings.opencti_url or "http://127.0.0.1:8080"
    proposal = (
        f"Install OpenCTI {OPENCTI_RECOMMENDED_VERSION} locally with Docker Compose "
        f"(image: {OPENCTI_IMAGE}) from https://github.com/OpenCTI-Platform/docker "
        "and set OPENCTI_URL and OPENCTI_TOKEN in .env."
    )
    reachable, payload = _probe_http(
        session,
        f"{url.rstrip('/')}/health",
        timeout=timeout,
        verify=settings.verify_tls,
    )
    if not reachable:
        status: ServiceStatus = "missing" if not settings.opencti_url else "unreachable"
        return ServiceDiagnosis(
            service="opencti",
            status=status,
            recommended_version=OPENCTI_RECOMMENDED_VERSION,
            image=OPENCTI_IMAGE,
            configured_url=settings.opencti_url,
            install_proposal=proposal,
        )
    version = (
        str(payload.get("version"))
        if isinstance(payload, dict) and payload.get("version")
        else None
    )
    return ServiceDiagnosis(
        service="opencti",
        status="ok",
        recommended_version=OPENCTI_RECOMMENDED_VERSION,
        image=OPENCTI_IMAGE,
        configured_url=url,
        detected_version=version,
    )


def _check_thehive(
    settings: Settings, session: requests.Session, timeout: float
) -> ServiceDiagnosis:
    url = settings.thehive_url or "http://127.0.0.1:9000"
    proposal = (
        f"Install TheHive {THEHIVE_RECOMMENDED_VERSION} locally with Docker: "
        f"docker run -d --name thehive -p 127.0.0.1:9000:9000 {THEHIVE_IMAGE} "
        "and set CTI_THEHIVE_URL=http://127.0.0.1:9000 and CTI_THEHIVE_TOKEN in .env."
    )
    reachable, payload = _probe_http(
        session,
        f"{url.rstrip('/')}/api/status",
        timeout=timeout,
        verify=settings.verify_tls,
    )
    if not reachable:
        status: ServiceStatus = "missing" if not settings.thehive_url else "unreachable"
        return ServiceDiagnosis(
            service="thehive",
            status=status,
            recommended_version=THEHIVE_RECOMMENDED_VERSION,
            image=THEHIVE_IMAGE,
            configured_url=settings.thehive_url,
            install_proposal=proposal,
        )
    versions = payload.get("versions") if isinstance(payload, dict) else None
    detected = (
        str(versions.get("TheHive"))
        if isinstance(versions, dict) and versions.get("TheHive")
        else None
    )
    return ServiceDiagnosis(
        service="thehive",
        status="ok",
        recommended_version=THEHIVE_RECOMMENDED_VERSION,
        image=THEHIVE_IMAGE,
        configured_url=url,
        detected_version=detected,
    )


def _check_ollama(
    settings: Settings, session: requests.Session, timeout: float
) -> ServiceDiagnosis:
    url = settings.ollama_base_url
    proposal = (
        f"Start local Ollama ({OLLAMA_RECOMMENDED_VERSION}) with: "
        "docker compose --profile local-ai up -d && "
        f"ollama pull {settings.ollama_model}"
    )
    reachable, payload = _probe_http(
        session,
        f"{url.rstrip('/')}/api/version",
        timeout=timeout,
        verify=settings.verify_tls,
    )
    if not reachable:
        return ServiceDiagnosis(
            service="ollama",
            status="missing",
            recommended_version=OLLAMA_RECOMMENDED_VERSION,
            image=OLLAMA_IMAGE,
            configured_url=url,
            install_proposal=proposal,
        )
    detected = (
        str(payload.get("version"))
        if isinstance(payload, dict) and payload.get("version")
        else None
    )
    return ServiceDiagnosis(
        service="ollama",
        status="ok",
        recommended_version=OLLAMA_RECOMMENDED_VERSION,
        image=OLLAMA_IMAGE,
        configured_url=url,
        detected_version=detected,
    )


def _check_qdrant(
    settings: Settings, session: requests.Session, timeout: float
) -> ServiceDiagnosis:
    url = settings.memory_url
    proposal = (
        f"Start local Qdrant ({QDRANT_RECOMMENDED_VERSION}) with: "
        "docker compose --profile memory up -d"
    )
    reachable, payload = _probe_http(
        session,
        f"{url.rstrip('/')}/",
        timeout=timeout,
        verify=settings.verify_tls,
    )
    if not reachable:
        status: ServiceStatus = (
            "unconfigured" if not settings.memory_enabled else "missing"
        )
        return ServiceDiagnosis(
            service="qdrant",
            status=status,
            recommended_version=QDRANT_RECOMMENDED_VERSION,
            image=QDRANT_IMAGE,
            configured_url=url,
            install_proposal=proposal,
        )
    detected = (
        str(payload.get("version"))
        if isinstance(payload, dict) and payload.get("version")
        else None
    )
    return ServiceDiagnosis(
        service="qdrant",
        status="ok",
        recommended_version=QDRANT_RECOMMENDED_VERSION,
        image=QDRANT_IMAGE,
        configured_url=url,
        detected_version=detected,
    )


def run_doctor(
    settings: Settings,
    *,
    session: requests.Session | None = None,
    timeout: float = 2.0,
) -> DoctorReport:
    """Inspect local binaries and probe OpenCTI, TheHive, Ollama and Qdrant."""
    http = session or requests.Session()
    docker_ok = shutil.which("docker") is not None
    ollama_bin = shutil.which("ollama") is not None
    services = (
        _check_opencti(settings, http, timeout),
        _check_thehive(settings, http, timeout),
        _check_ollama(settings, http, timeout),
        _check_qdrant(settings, http, timeout),
    )
    healthy = all(item.status == "ok" for item in services[:3])
    return DoctorReport(
        healthy=healthy,
        docker_installed=docker_ok,
        ollama_binary_installed=ollama_bin,
        services=services,
    )
