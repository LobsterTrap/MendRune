"""Rootless Podman/krun command construction and preflight."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from mendrune.errors import MendRuneError
from mendrune.models import ExecutionConfig


@dataclass(frozen=True)
class Mount:
    source: Path
    destination: str
    read_only: bool


@dataclass(frozen=True)
class Invocation:
    image: str
    argv: tuple[str, ...]
    mounts: tuple[Mount, ...]
    environment: dict[str, str]
    timeout_seconds: int


def build_podman_command(config: ExecutionConfig, invocation: Invocation) -> list[str]:
    if invocation.image != config.image:
        raise MendRuneError("invocation image mismatch", reason_code="image_digest_mismatch")
    command = [
        "podman",
        "run",
        "--rm",
        "--runtime",
        config.runtime,
        "--network",
        "none",
        "--cap-drop",
        "all",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--cpus",
        str(config.cpus),
        "--memory",
        f"{config.memory_mib}m",
        "--pids-limit",
        str(config.pids_limit),
        "--workdir",
        config.container_workdir,
    ]
    for key, value in sorted(invocation.environment.items()):
        if key not in config.environment and key != "MENDRUNE_ORACLE_NONCE":
            raise MendRuneError(
                f"invocation environment variable is not allowed: {key}",
                reason_code="isolation_control_unavailable",
            )
        command.extend(("--env", f"{key}={value}"))
    destinations: set[str] = set()
    for mount in invocation.mounts:
        source = mount.source.resolve(strict=True)
        if mount.destination in destinations:
            raise MendRuneError("duplicate mount destination", reason_code="unsafe_path")
        destinations.add(mount.destination)
        suffix = ":ro" if mount.read_only else ":rw"
        command.extend(("--volume", f"{source}:{mount.destination}{suffix}"))
    command.append(config.image)
    command.extend(invocation.argv)
    return command


def preflight(config: ExecutionConfig) -> None:
    if os.geteuid() == 0:
        raise MendRuneError("MendRune requires a non-root user", reason_code="rootless_required")
    rootless = _podman("info", "--format", "{{.Host.Security.Rootless}}")
    if rootless.strip() != "true":
        raise MendRuneError("Podman is not rootless", reason_code="rootless_required")
    runtime = Path(config.runtime)
    runtime_path = runtime if runtime.is_absolute() else _which(config.runtime)
    if runtime_path is None or not runtime_path.is_file():
        raise MendRuneError("configured runtime is unavailable", reason_code="runtime_unavailable")
    if not Path("/dev/kvm").exists():
        raise MendRuneError("KVM is unavailable", reason_code="runtime_unqualified")
    inspected = _podman("image", "inspect", config.image, "--format", "{{.Digest}}")
    expected = config.image.rsplit("@", 1)[1]
    if inspected.strip() != expected:
        raise MendRuneError("image digest mismatch", reason_code="image_digest_mismatch")


def _which(value: str) -> Path | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / value
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _podman(*args: str) -> str:
    try:
        result = subprocess.run(
            ["podman", *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MendRuneError("Podman unavailable", reason_code="podman_unavailable") from exc
    if result.returncode != 0:
        raise MendRuneError(
            f"Podman command failed: {result.stderr.strip()[:1000]}",
            reason_code="podman_unavailable",
        )
    return result.stdout
