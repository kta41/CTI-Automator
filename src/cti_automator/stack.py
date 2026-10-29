"""One-command Docker Compose stack orchestrator (up, down, status)."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from cti_automator.config import Settings
from cti_automator.doctor import DoctorReport, run_doctor

StackMode = Literal["minimal", "standard", "full"]
ALL_PROFILES: tuple[str, ...] = (
    "local-ai",
    "memory",
    "monitoring",
    "secops",
    "opencti",
)
MODE_PROFILES: dict[StackMode, tuple[str, ...]] = {
    "minimal": (),
    "standard": ("local-ai", "memory"),
    "full": ("local-ai", "memory", "monitoring", "secops", "opencti"),
}

SERVICE_ENDPOINTS: dict[str, str] = {
    "ui": "http://127.0.0.1:8085",
    "mcp": "http://127.0.0.1:8000/mcp",
    "healthz": "http://127.0.0.1:8000/healthz",
    "metrics": "http://127.0.0.1:8000/metrics",
    "ollama": "http://127.0.0.1:11434",
    "qdrant": "http://127.0.0.1:6333",
    "prometheus": "http://127.0.0.1:9090",
    "grafana": "http://127.0.0.1:3000",
    "thehive": "http://127.0.0.1:9000",
    "opencti": "http://127.0.0.1:8080",
}

CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class StackPlan(BaseModel):
    """Computed execution plan for one stack lifecycle operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal["up", "down", "status"]
    mode: StackMode = "standard"
    profiles: tuple[str, ...] = ()
    reused_host_services: tuple[str, ...] = ()
    env_file: str
    env_bootstrapped: bool = False
    state_dir: str
    commands: tuple[tuple[str, ...], ...] = ()
    endpoints: dict[str, str]
    executed: bool = False


def _default_runner(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(cmd),
        check=True,
        text=True,
        capture_output=True,
    )


def bootstrap_environment(root: Path, *, mode: StackMode = "standard") -> bool:
    """Ensure `.env` and `./state` exist with secure permissions and tokens."""
    state_dir = root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    env_path = root / ".env"
    example_path = root / ".env.example"
    created = False
    if not env_path.exists():
        template = (
            example_path.read_text(encoding="utf-8")
            if example_path.exists()
            else "AI_PROVIDER=ollama\n"
        )
        lines: list[str] = []
        profiles_csv = ",".join(MODE_PROFILES[mode])
        for line in template.splitlines():
            if line.startswith("OPENCTI_TOKEN=") and line.strip() == "OPENCTI_TOKEN=":
                lines.append(f"OPENCTI_TOKEN={uuid4()}")
            elif (
                line.startswith("OPENCTI_ADMIN_PASSWORD=")
                and line.strip() == "OPENCTI_ADMIN_PASSWORD="
            ):
                lines.append(f"OPENCTI_ADMIN_PASSWORD={secrets.token_urlsafe(16)}")
            elif line.startswith("COMPOSE_PROFILES="):
                lines.append(f"COMPOSE_PROFILES={profiles_csv}")
            else:
                lines.append(line)
        if not any(line.startswith("GF_SECURITY_ADMIN_PASSWORD=") for line in lines):
            lines.append(
                f"GF_SECURITY_ADMIN_PASSWORD={secrets.token_urlsafe(16)}"
            )
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(env_path, 0o600)
        created = True
    return created


def resolve_active_profiles(
    mode: StackMode,
    doctor: DoctorReport,
    *,
    with_opencti: bool = False,
    with_thehive: bool = False,
    with_monitoring: bool = False,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Select Compose profiles while skipping services already active on the host."""
    requested = list(MODE_PROFILES[mode])
    if with_monitoring and "monitoring" not in requested:
        requested.append("monitoring")
    if with_thehive and "secops" not in requested:
        requested.append("secops")
    if with_opencti and "opencti" not in requested:
        requested.append("opencti")

    running = {svc.service for svc in doctor.services if svc.status == "ok"}
    profile_service_map = {
        "local-ai": "ollama",
        "memory": "qdrant",
        "secops": "thehive",
        "opencti": "opencti",
    }
    active: list[str] = []
    reused: list[str] = []
    for profile in requested:
        mapped = profile_service_map.get(profile)
        if mapped and mapped in running:
            reused.append(mapped)
        else:
            active.append(profile)
    return tuple(active), tuple(reused)


def build_stack_up_plan(
    settings: Settings,
    *,
    root: Path | None = None,
    mode: StackMode = "standard",
    with_opencti: bool = False,
    with_thehive: bool = False,
    with_monitoring: bool = False,
    build_image: bool = False,
    pull_models: bool = True,
    doctor_report: DoctorReport | None = None,
) -> StackPlan:
    """Compute the full startup sequence without executing external processes."""
    workspace = (root or Path.cwd()).resolve()
    compose_file = workspace / "compose.yaml"
    bootstrapped = bootstrap_environment(workspace, mode=mode)
    report = doctor_report or run_doctor(settings, timeout=1.0)
    profiles, reused = resolve_active_profiles(
        mode,
        report,
        with_opencti=with_opencti,
        with_thehive=with_thehive,
        with_monitoring=with_monitoring,
    )
    commands: list[tuple[str, ...]] = []
    if build_image:
        commands.append(
            ("docker", "build", "-t", "ghcr.io/kta41/cti-automator:latest", str(workspace))
        )
    compose_cmd: list[str] = ["docker", "compose", "-f", str(compose_file)]
    for profile in profiles:
        compose_cmd.extend(["--profile", profile])
    compose_cmd.extend(["up", "-d"])
    commands.append(tuple(compose_cmd))

    if pull_models and settings.ai_provider == "ollama":
        if "ollama" in reused and shutil.which("ollama"):
            commands.append(("ollama", "pull", settings.ollama_model))
            if "memory" in profiles or "qdrant" in reused:
                commands.append(("ollama", "pull", settings.memory_embedding_model))
        elif "local-ai" in profiles:
            commands.append(
                (
                    "docker",
                    "compose",
                    "-f",
                    str(compose_file),
                    "exec",
                    "-T",
                    "ollama",
                    "ollama",
                    "pull",
                    settings.ollama_model,
                )
            )
            if "memory" in profiles or "qdrant" in reused:
                commands.append(
                    (
                        "docker",
                        "compose",
                        "-f",
                        str(compose_file),
                        "exec",
                        "-T",
                        "ollama",
                        "ollama",
                        "pull",
                        settings.memory_embedding_model,
                    )
                )

    endpoints = {
        "ui": SERVICE_ENDPOINTS["ui"],
        "mcp": SERVICE_ENDPOINTS["mcp"],
        "healthz": SERVICE_ENDPOINTS["healthz"],
        "metrics": SERVICE_ENDPOINTS["metrics"],
    }
    if "local-ai" in profiles or "ollama" in reused:
        endpoints["ollama"] = SERVICE_ENDPOINTS["ollama"]
    if "memory" in profiles or "qdrant" in reused:
        endpoints["qdrant"] = SERVICE_ENDPOINTS["qdrant"]
    if "monitoring" in profiles:
        endpoints["prometheus"] = SERVICE_ENDPOINTS["prometheus"]
        endpoints["grafana"] = SERVICE_ENDPOINTS["grafana"]
    if "secops" in profiles or "thehive" in reused:
        endpoints["thehive"] = SERVICE_ENDPOINTS["thehive"]
    if "opencti" in profiles or "opencti" in reused:
        endpoints["opencti"] = SERVICE_ENDPOINTS["opencti"]

    return StackPlan(
        action="up",
        mode=mode,
        profiles=profiles,
        reused_host_services=reused,
        env_file=str(workspace / ".env"),
        env_bootstrapped=bootstrapped,
        state_dir=str(workspace / "state"),
        commands=tuple(commands),
        endpoints=endpoints,
        executed=False,
    )


def execute_stack_up(
    plan: StackPlan,
    *,
    dry_run: bool = False,
    runner: CommandRunner | None = None,
) -> StackPlan:
    """Execute the planned stack startup commands unless dry_run is requested."""
    if dry_run:
        return plan
    run = runner or _default_runner
    for cmd in plan.commands:
        run(cmd)
    return plan.model_copy(update={"executed": True})


def execute_stack_down(
    *,
    root: Path | None = None,
    dry_run: bool = False,
    runner: CommandRunner | None = None,
) -> StackPlan:
    """Stop all active and optional profiles cleanly."""
    workspace = (root or Path.cwd()).resolve()
    compose_file = workspace / "compose.yaml"
    compose_cmd: list[str] = ["docker", "compose", "-f", str(compose_file)]
    for profile in ALL_PROFILES:
        compose_cmd.extend(["--profile", profile])
    compose_cmd.append("down")
    plan = StackPlan(
        action="down",
        profiles=ALL_PROFILES,
        env_file=str(workspace / ".env"),
        state_dir=str(workspace / "state"),
        commands=(tuple(compose_cmd),),
        endpoints={},
        executed=False,
    )
    if dry_run:
        return plan
    run = runner or _default_runner
    for cmd in plan.commands:
        run(cmd)
    return plan.model_copy(update={"executed": True})


def stack_status(settings: Settings) -> dict[str, object]:
    """Return a unified view of local stack health and service URLs."""
    report = run_doctor(settings, timeout=1.5)
    return {
        "healthy": report.healthy,
        "endpoints": SERVICE_ENDPOINTS,
        "doctor": report.model_dump(mode="json"),
    }
