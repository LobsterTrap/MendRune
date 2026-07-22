from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from mendrune.errors import MendRuneError
from mendrune.executor import Invocation, Mount, execute, preflight
from mendrune.models import ExecutionConfig

_IMAGE_ENV = "MENDRUNE_RUNTIME_TEST_IMAGE"
_RUNTIME_ENV = "MENDRUNE_RUNTIME_TEST_RUNTIME"
_COMMAND_ENV = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=_COMMAND_ENV,
    )


def _skip_unless_qualified() -> ExecutionConfig:
    image = os.environ.get(_IMAGE_ENV)
    if image is None:
        pytest.skip(f"{_IMAGE_ENV} is not set to a locally available immutable image")
    if re.fullmatch(r".+@sha256:[0-9a-f]{64}", image) is None:
        pytest.skip(f"{_IMAGE_ENV} is not an immutable sha256 digest reference")
    if os.geteuid() == 0:
        pytest.skip("qualified runtime tests require a non-root user")
    if shutil.which("podman") is None:
        pytest.skip("qualified runtime tests require Podman on PATH")

    rootless = _run(["podman", "info", "--format", "{{.Host.Security.Rootless}}"])
    if rootless.returncode != 0:
        pytest.skip(f"rootless Podman qualification failed: {rootless.stderr.strip()[:300]}")
    if rootless.stdout.strip().lower() != "true":
        pytest.skip("qualified runtime tests require rootless Podman")

    runtime = os.environ.get(_RUNTIME_ENV, "crun-krun")
    runtime_path = shutil.which(runtime)
    if runtime_path is None:
        pytest.skip(f"qualified runtime tests require {runtime!r} on PATH")
    identity = _run([runtime_path, "--version"])
    version = f"{identity.stdout}\n{identity.stderr}".lower()
    if (
        identity.returncode != 0
        or "crun" not in version
        or not ("+krun" in version or "libkrun" in version)
    ):
        pytest.skip(f"{runtime!r} is not a crun runtime with libkrun capability")

    try:
        descriptor = os.open("/dev/kvm", os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        pytest.skip(f"qualified runtime tests require usable /dev/kvm: {exc}")
    else:
        os.close(descriptor)

    inspected = _run(["podman", "image", "inspect", image, "--format", "{{.Digest}}"])
    if inspected.returncode != 0:
        pytest.skip(
            f"{_IMAGE_ENV} must already exist locally; images are never pulled: "
            f"{inspected.stderr.strip()[:300]}"
        )
    expected_digest = image.rsplit("@", 1)[1]
    if inspected.stdout.strip() != expected_digest:
        pytest.skip(f"local {_IMAGE_ENV} digest does not match its immutable reference")

    config = ExecutionConfig(
        image=image,
        runtime=runtime,
        network="none",
        container_workdir="/",
        default_timeout_seconds=10,
        cpus=1,
        memory_mib=128,
        pids_limit=32,
        maximum_output_bytes=64 * 1024,
        environment={"LANG": "C.UTF-8"},
    )
    try:
        preflight(config)
    except MendRuneError as exc:
        if exc.reason_code in {
            "podman_unavailable",
            "rootless_required",
            "runtime_unavailable",
            "runtime_unqualified",
        }:
            pytest.skip(
                f"rootless Podman/libkrun qualification launch unavailable "
                f"({exc.reason_code}): {exc}"
            )
        pytest.fail(f"qualified-host preflight failed closed ({exc.reason_code}): {exc}")
    return config


@pytest.fixture(scope="session")
def runtime_config() -> ExecutionConfig:
    return _skip_unless_qualified()


def _execute(
    config: ExecutionConfig,
    script: str,
    *,
    mounts: tuple[Mount, ...] = (),
    timeout: int = 10,
):
    result = execute(
        config,
        Invocation(
            image=config.image,
            argv=("sh", "-ceu", script),
            mounts=mounts,
            environment={"LANG": "C.UTF-8"},
            timeout_seconds=timeout,
        ),
    )
    assert not result.timed_out, result.stderr.data.decode(errors="replace")
    assert result.exit_code == 0, result.stderr.data.decode(errors="replace")
    return result


@pytest.mark.runtime
def test_network_is_denied(runtime_config: ExecutionConfig) -> None:
    _execute(
        runtime_config,
        """
interfaces=
for path in /sys/class/net/*; do
    interface=${path##*/}
    interfaces=${interfaces}${interfaces:+,}${interface}
done
test "$interfaces" = lo
test "$(wc -l < /proc/net/route)" -eq 1
""",
    )


@pytest.mark.runtime
def test_mount_boundaries_are_enforced(runtime_config: ExecutionConfig, tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    output = tmp_path / "output"
    evidence.mkdir()
    output.mkdir()
    (evidence / "sentinel").write_text("immutable\n")
    host_only = tmp_path / "host-credential"
    host_only.write_text("must-not-be-visible\n")
    script = f"""
test "$(cat /evidence/sentinel)" = immutable
! printf compromised > /evidence/sentinel
printf allowed > /output/result
! test -e {shlex.quote(str(host_only))}
"""

    _execute(
        runtime_config,
        script,
        mounts=(Mount(evidence, "/evidence", True), Mount(output, "/output", False)),
    )

    assert (evidence / "sentinel").read_text() == "immutable\n"
    assert (output / "result").read_text() == "allowed"


@pytest.mark.runtime
def test_host_credentials_and_sockets_are_absent(runtime_config: ExecutionConfig) -> None:
    _execute(
        runtime_config,
        """
test -z "${AWS_ACCESS_KEY_ID+x}"
test -z "${AWS_SECRET_ACCESS_KEY+x}"
test -z "${AWS_SESSION_TOKEN+x}"
test -z "${SSH_AUTH_SOCK+x}"
test -z "${DOCKER_HOST+x}"
test -z "${CONTAINER_HOST+x}"
! test -e /run/podman/podman.sock
! test -e /var/run/docker.sock
! test -e /root/.aws/credentials
! test -e /root/.ssh
! test -e /run/host
""",
    )


@pytest.mark.runtime
def test_capabilities_no_new_privileges_and_read_only_root(
    runtime_config: ExecutionConfig,
) -> None:
    _execute(
        runtime_config,
        """
for field in CapInh CapPrm CapEff CapAmb; do
    grep -Eq "^${field}:[[:space:]]+0+$" /proc/self/status
done
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
! touch /mendrune-root-write-test
""",
    )


@pytest.mark.runtime
def test_cpu_memory_and_pid_limits_are_applied(runtime_config: ExecutionConfig) -> None:
    result = _execute(
        runtime_config,
        """
printf 'cpu='; cat /sys/fs/cgroup/cpu.max
printf 'memory='; cat /sys/fs/cgroup/memory.max
printf 'pids='; cat /sys/fs/cgroup/pids.max
""",
    )
    values = dict(
        line.split("=", 1) for line in result.stdout.data.decode().splitlines() if "=" in line
    )
    quota, period = (int(value) for value in values["cpu"].split())
    assert quota == period
    assert int(values["memory"]) == runtime_config.memory_mib * 1024 * 1024
    assert int(values["pids"]) == runtime_config.pids_limit


@pytest.mark.runtime
def test_timeout_kills_and_removes_container(runtime_config: ExecutionConfig) -> None:
    result = execute(
        runtime_config,
        Invocation(
            image=runtime_config.image,
            argv=("sh", "-c", "sleep 30"),
            mounts=(),
            environment={},
            timeout_seconds=1,
        ),
    )

    assert result.timed_out
    assert result.duration_ms < 15_000
    exists = _run(["podman", "container", "exists", result.container_name])
    assert exists.returncode != 0, f"timed-out container remains: {result.container_name}"
