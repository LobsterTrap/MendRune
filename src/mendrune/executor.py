"""Rootless Podman/krun command construction and preflight."""

from __future__ import annotations

import os
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from mendrune.errors import MendRuneError
from mendrune.models import ExecutionConfig


@dataclass(frozen=True)
class Mount:
    source: Path
    destination: str
    read_only: bool
    tmpfs_limit_bytes: int | None = None
    capture_to_source: bool = False


@dataclass(frozen=True)
class Invocation:
    image: str
    argv: tuple[str, ...]
    mounts: tuple[Mount, ...]
    environment: dict[str, str]
    timeout_seconds: int


@dataclass(frozen=True)
class CapturedOutput:
    data: bytes
    total_bytes: int
    truncated: bool


@dataclass(frozen=True)
class ExecutionResult:
    argv: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    started_at: datetime
    duration_ms: int
    container_name: str
    image: str
    runtime: str
    stdout: CapturedOutput
    stderr: CapturedOutput


def build_podman_command(
    config: ExecutionConfig, invocation: Invocation, *, container_name: str | None = None
) -> list[str]:
    if invocation.image != config.image:
        raise MendRuneError("invocation image mismatch", reason_code="image_digest_mismatch")
    command = [
        "podman",
        "run",
        "--name",
        container_name or f"mendrune-{uuid.uuid4().hex}",
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
        "--annotation",
        f"krun.cpus={config.cpus}",
        "--annotation",
        f"krun.ram_mib={max(129, config.memory_mib)}",
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
        if mount.destination in destinations:
            raise MendRuneError("duplicate mount destination", reason_code="unsafe_path")
        destinations.add(mount.destination)
        if mount.tmpfs_limit_bytes is not None:
            if mount.read_only or mount.tmpfs_limit_bytes <= 0:
                raise MendRuneError("invalid limited mount", reason_code="unsafe_path")
            source = mount.source.resolve(strict=True)
            suffix = ":rw,z"
            command.extend(("--volume", f"{source}:{mount.destination}{suffix}"))
        else:
            if mount.capture_to_source:
                raise MendRuneError("capture requires a limited mount", reason_code="unsafe_path")
            source = mount.source.resolve(strict=True)
            suffix = ":ro,z" if mount.read_only else ":rw,z"
            command.extend(("--volume", f"{source}:{mount.destination}{suffix}"))
    command.append(config.image)
    command.extend(invocation.argv)
    return command


def execute(config: ExecutionConfig, invocation: Invocation) -> ExecutionResult:
    """Run one named Podman container and return independently bounded output."""
    container_name = f"mendrune-{uuid.uuid4().hex}"
    command = build_podman_command(config, invocation, container_name=container_name)
    for mount in invocation.mounts:
        if not mount.capture_to_source:
            continue
        if mount.source.is_symlink():
            raise MendRuneError("capture destination is a symlink", reason_code="unsafe_path")
        source = mount.source.resolve(strict=True)
        if not source.is_dir() or any(source.iterdir()):
            raise MendRuneError(
                "capture destination must be an empty directory", reason_code="unsafe_path"
            )
    started_at = datetime.now(UTC)
    started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    stdout = _Capture(config.maximum_output_bytes)
    stderr = _Capture(config.maximum_output_bytes)
    readers: list[threading.Thread] = []
    timed_out = False
    lifecycle_error: Exception | None = None
    launch_error: OSError | None = None

    try:
        process = subprocess.Popen(
            command,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
        )
        if process.stdout is None or process.stderr is None:
            raise OSError("Podman output pipes unavailable")
        readers = [
            threading.Thread(target=stdout.read, args=(process.stdout,), daemon=True),
            threading.Thread(target=stderr.read, args=(process.stderr,), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            process.wait(timeout=invocation.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            lifecycle_error = _container_command("stop", "--time", "1", "--ignore", container_name)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=30)
    except OSError as exc:
        launch_error = exc
    finally:
        for reader in readers:
            reader.join(timeout=30)
        if any(reader.is_alive() for reader in readers) and lifecycle_error is None:
            lifecycle_error = RuntimeError("container output capture did not finish")
        cleanup_error = _container_command("rm", "--force", "--ignore", container_name)
        if lifecycle_error is None:
            lifecycle_error = cleanup_error

    if lifecycle_error is not None:
        raise MendRuneError(
            f"container cleanup uncertain: {lifecycle_error}", reason_code="cleanup_uncertain"
        ) from lifecycle_error
    if launch_error is not None:
        raise MendRuneError(
            "Podman container launch failed", reason_code="container_launch_failed"
        ) from launch_error
    if process is None:
        raise MendRuneError("Podman container launch failed", reason_code="container_launch_failed")
    return ExecutionResult(
        argv=tuple(command),
        exit_code=process.returncode,
        timed_out=timed_out,
        started_at=started_at,
        duration_ms=int((time.monotonic() - started) * 1000),
        container_name=container_name,
        image=invocation.image,
        runtime=config.runtime,
        stdout=stdout.result(),
        stderr=stderr.result(),
    )


class _Capture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.total_bytes = 0

    def read(self, stream: BinaryIO) -> None:
        while chunk := stream.read(64 * 1024):
            self.total_bytes += len(chunk)
            remaining = self.limit - len(self.data)
            if remaining > 0:
                self.data.extend(chunk[:remaining])

    def result(self) -> CapturedOutput:
        return CapturedOutput(
            data=bytes(self.data),
            total_bytes=self.total_bytes,
            truncated=self.total_bytes > self.limit,
        )


def _container_command(*args: str) -> Exception | None:
    try:
        result = subprocess.run(
            ["podman", *args],
            shell=False,
            check=False,
            capture_output=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return exc
    if result.returncode != 0:
        return RuntimeError(f"podman {args[0]} failed with exit code {result.returncode}")
    return None


def preflight(config: ExecutionConfig) -> None:
    if os.geteuid() == 0:
        raise MendRuneError("MendRune requires a non-root user", reason_code="rootless_required")
    rootless = _podman("info", "--format", "{{.Host.Security.Rootless}}")
    if rootless.strip().lower() != "true":
        raise MendRuneError("Podman is not rootless", reason_code="rootless_required")

    runtime = Path(config.runtime)
    runtime_path = runtime if runtime.is_absolute() else _which(config.runtime)
    if runtime_path is None or not runtime_path.is_file() or not os.access(runtime_path, os.X_OK):
        raise MendRuneError("configured runtime is unavailable", reason_code="runtime_unavailable")
    _qualify_runtime_identity(runtime_path)
    _qualify_kvm()

    inspected = _podman("image", "inspect", config.image, "--format", "{{.Digest}}")
    expected = config.image.rsplit("@", 1)[1]
    if inspected.strip() != expected:
        raise MendRuneError("image digest mismatch", reason_code="image_digest_mismatch")
    _qualify_runtime_launch(config)


def _qualify_runtime_identity(runtime_path: Path) -> None:
    try:
        result = subprocess.run(
            [str(runtime_path), "--version"],
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MendRuneError(
            "configured runtime is unavailable", reason_code="runtime_unavailable"
        ) from exc
    identity = f"{result.stdout}\n{result.stderr}".lower()
    if (
        result.returncode != 0
        or "crun" not in identity
        or not ("+krun" in identity or "libkrun" in identity)
    ):
        raise MendRuneError(
            "configured runtime is not crun with libkrun capability",
            reason_code="runtime_unqualified",
        )


def _qualify_kvm() -> None:
    try:
        descriptor = os.open("/dev/kvm", os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise MendRuneError("KVM is unusable", reason_code="runtime_unqualified") from exc
    os.close(descriptor)


def _qualify_runtime_launch(config: ExecutionConfig) -> None:
    container_name = f"mendrune-preflight-{uuid.uuid4().hex}"
    invocation = Invocation(
        image=config.image,
        argv=("true",),
        mounts=(),
        environment={},
        timeout_seconds=30,
    )
    command = build_podman_command(config, invocation, container_name=container_name)
    command.insert(2, "--pull=never")
    launch_error: Exception | None = None
    try:
        result = subprocess.run(
            command,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
        )
        if result.returncode != 0:
            launch_error = RuntimeError(
                f"qualification container exited with status {result.returncode}: "
                f"{result.stderr.strip()[:1000]}"
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        launch_error = exc
    finally:
        cleanup_error = _container_command("rm", "--force", "--ignore", container_name)
    if cleanup_error is not None:
        raise MendRuneError(
            f"preflight container cleanup uncertain: {cleanup_error}",
            reason_code="cleanup_uncertain",
        ) from cleanup_error
    if launch_error is not None:
        raise MendRuneError(
            f"libkrun qualification launch failed: {launch_error}",
            reason_code="runtime_unqualified",
        ) from launch_error


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
