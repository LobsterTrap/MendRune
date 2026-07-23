import io
import subprocess
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mendrune.errors import MendRuneError
from mendrune.executor import Invocation, Mount, build_podman_command, execute, preflight
from mendrune.models import ExecutionConfig
from tests.unit.test_models import campaign_data


def config() -> ExecutionConfig:
    return ExecutionConfig.model_validate(deepcopy(campaign_data()["execution"]))


def test_builds_hardened_podman_command(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    evidence = tmp_path / "evidence"
    output = tmp_path / "output"
    for path in (worktree, evidence, output):
        path.mkdir()
    execution = config()
    invocation = Invocation(
        image=execution.image,
        argv=("python", "/evidence/check.py"),
        mounts=(
            Mount(worktree, "/workspace", False),
            Mount(evidence, "/evidence", True),
            Mount(output, "/output", False),
        ),
        environment={"LANG": "C.UTF-8"},
        timeout_seconds=60,
    )

    command = build_podman_command(execution, invocation)

    assert command[:4] == ["podman", "run", "--name", command[3]]
    assert command[3].startswith("mendrune-")
    assert command[command.index("--runtime") :][:2] == ["--runtime", "crun-krun"]
    assert command[command.index("--network") :][:2] == ["--network", "none"]
    assert command[command.index("--cap-drop") :][:2] == ["--cap-drop", "all"]
    assert "no-new-privileges" in command
    assert any(value.endswith(":/evidence:ro,z") for value in command)
    assert f"fsize={execution.maximum_output_bytes}:{execution.maximum_output_bytes}" in command
    assert f"krun.cpus={execution.cpus}" in command
    assert f"krun.ram_mib={execution.memory_mib}" in command
    assert execution.image in command


def test_builds_confined_capture_mount(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    invocation = Invocation(
        image=config().image,
        argv=("check",),
        mounts=(Mount(output, "/output", False, 4096, True),),
        environment={},
        timeout_seconds=1,
    )

    command = build_podman_command(config(), invocation, container_name="bounded")

    assert any(value.endswith(":/output:rw,z") for value in command)


def test_rejects_unapproved_environment(tmp_path: Path) -> None:
    execution = config()
    invocation = Invocation(
        image=execution.image,
        argv=("true",),
        mounts=(),
        environment={"AWS_SECRET_ACCESS_KEY": "secret"},
        timeout_seconds=1,
    )

    with pytest.raises(MendRuneError) as raised:
        build_podman_command(execution, invocation)
    assert raised.value.reason_code == "isolation_control_unavailable"


def invocation(execution: ExecutionConfig, *, timeout: int = 1) -> Invocation:
    return Invocation(
        image=execution.image,
        argv=("printf", "output"),
        mounts=(),
        environment={},
        timeout_seconds=timeout,
    )


def process(stdout: bytes, stderr: bytes, returncode: int = 0) -> MagicMock:
    mocked = MagicMock()
    mocked.stdout = io.BytesIO(stdout)
    mocked.stderr = io.BytesIO(stderr)
    mocked.returncode = returncode
    mocked.wait.return_value = returncode
    return mocked


def test_execute_uses_argv_and_independently_bounds_output() -> None:
    execution = config().model_copy(update={"maximum_output_bytes": 4})
    mocked_process = process(b"abcdef", b"12345", 7)
    cleanup = subprocess.CompletedProcess([], 0, b"", b"")

    with (
        patch("mendrune.executor.subprocess.Popen", return_value=mocked_process) as popen,
        patch("mendrune.executor.subprocess.run", return_value=cleanup) as run,
    ):
        result = execute(execution, invocation(execution))

    assert result.exit_code == 7
    assert result.timed_out is False
    assert result.stdout.data == b"abcd"
    assert result.stdout.total_bytes == 6
    assert result.stdout.truncated is True
    assert result.stderr.data == b"1234"
    assert result.stderr.total_bytes == 5
    assert result.stderr.truncated is True
    assert result.container_name.startswith("mendrune-")
    assert result.image == execution.image
    assert result.runtime == execution.runtime
    assert result.duration_ms >= 0
    assert popen.call_args.kwargs["shell"] is False
    assert popen.call_args.args[0][:3] == ["podman", "run", "--name"]
    assert run.call_count == 1
    assert run.call_args.args[0] == [
        "podman",
        "rm",
        "--force",
        "--ignore",
        result.container_name,
    ]
    assert run.call_args.kwargs["shell"] is False


def test_timeout_kills_then_removes_named_container() -> None:
    execution = config()
    mocked_process = process(b"partial", b"warning")
    mocked_process.wait.side_effect = [subprocess.TimeoutExpired("podman", 1), 137]
    success = subprocess.CompletedProcess([], 0, b"", b"")

    with (
        patch("mendrune.executor.subprocess.Popen", return_value=mocked_process),
        patch("mendrune.executor.subprocess.run", return_value=success) as run,
    ):
        result = execute(execution, invocation(execution))

    assert result.timed_out is True
    assert result.exit_code == mocked_process.returncode
    name = result.container_name
    assert run.call_args_list[0].args[0] == [
        "podman",
        "stop",
        "--time",
        "1",
        "--ignore",
        name,
    ]
    assert run.call_args_list[1].args[0] == ["podman", "rm", "--force", "--ignore", name]


def test_cleanup_uncertainty_fails_closed() -> None:
    execution = config()
    mocked_process = process(b"", b"")
    failed = subprocess.CompletedProcess([], 125, b"", b"failure")

    with (
        patch("mendrune.executor.subprocess.Popen", return_value=mocked_process),
        patch("mendrune.executor.subprocess.run", return_value=failed),
        pytest.raises(MendRuneError) as raised,
    ):
        execute(execution, invocation(execution))

    assert raised.value.reason_code == "cleanup_uncertain"


def preflight_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
    if command[:2] == ["crun-krun", "--version"]:
        return subprocess.CompletedProcess(command, 0, "crun version 1.20 +KRUN", "")
    if command[:3] == ["podman", "info", "--format"]:
        return subprocess.CompletedProcess(command, 0, "true\n", "")
    if command[:3] == ["podman", "image", "inspect"]:
        return subprocess.CompletedProcess(command, 0, config().image.rsplit("@", 1)[1], "")
    return subprocess.CompletedProcess(command, 0, "", "")


def test_preflight_qualifies_strict_runtime_and_launch_controls() -> None:
    with (
        patch("mendrune.executor.os.geteuid", return_value=1000),
        patch("mendrune.executor._which", return_value=Path("crun-krun")),
        patch("mendrune.executor.Path.is_file", return_value=True),
        patch("mendrune.executor.os.access", return_value=True),
        patch("mendrune.executor.os.open", return_value=9) as open_kvm,
        patch("mendrune.executor.os.close") as close_kvm,
        patch("mendrune.executor.subprocess.run", side_effect=preflight_run) as run,
    ):
        preflight(config())

    open_kvm.assert_called_once()
    assert open_kvm.call_args.args[0] == "/dev/kvm"
    close_kvm.assert_called_once_with(9)
    launch = next(
        call.args[0] for call in run.call_args_list if call.args[0][:2] == ["podman", "run"]
    )
    assert "--pull=never" in launch
    assert launch[launch.index("--runtime") + 1] == "crun-krun"
    assert launch[launch.index("--network") + 1] == "none"
    assert launch[launch.index("--cap-drop") + 1] == "all"
    assert "no-new-privileges" in launch
    assert "--read-only" in launch
    assert launch[launch.index("--cpus") + 1] == str(config().cpus)
    assert launch[launch.index("--memory") + 1] == f"{config().memory_mib}m"
    assert launch[launch.index("--pids-limit") + 1] == str(config().pids_limit)
    assert launch[-2:] == [config().image, "true"]
    cleanup = run.call_args_list[-1].args[0]
    assert cleanup[:5] == ["podman", "rm", "--force", "--ignore", launch[4]]


@pytest.mark.parametrize(
    ("overrides", "reason_code"),
    [
        ({"euid": 0}, "rootless_required"),
        ({"rootless": "false"}, "rootless_required"),
        ({"runtime": None}, "runtime_unavailable"),
        ({"identity": "crun version 1.20"}, "runtime_unqualified"),
        ({"kvm_error": PermissionError()}, "runtime_unqualified"),
        ({"digest": "sha256:" + "f" * 64}, "image_digest_mismatch"),
        ({"launch_status": 125}, "runtime_unqualified"),
        ({"cleanup_status": 125}, "cleanup_uncertain"),
    ],
)
def test_preflight_fails_closed(overrides: dict[str, object], reason_code: str) -> None:
    execution = config()

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["crun-krun", "--version"]:
            return subprocess.CompletedProcess(
                command, 0, str(overrides.get("identity", "crun version 1.20 +KRUN")), ""
            )
        if command[:3] == ["podman", "info", "--format"]:
            return subprocess.CompletedProcess(
                command, 0, str(overrides.get("rootless", "true")), ""
            )
        if command[:3] == ["podman", "image", "inspect"]:
            return subprocess.CompletedProcess(
                command,
                0,
                str(overrides.get("digest", execution.image.rsplit("@", 1)[1])),
                "",
            )
        if command[:2] == ["podman", "run"]:
            launch_status = overrides.get("launch_status", 0)
            assert isinstance(launch_status, int)
            return subprocess.CompletedProcess(command, launch_status, "", "launch failed")
        cleanup_status = overrides.get("cleanup_status", 0)
        assert isinstance(cleanup_status, int)
        return subprocess.CompletedProcess(command, cleanup_status, "", "cleanup failed")

    kvm = overrides.get("kvm_error", 9)
    with (
        patch("mendrune.executor.os.geteuid", return_value=overrides.get("euid", 1000)),
        patch("mendrune.executor._which", return_value=overrides.get("runtime", Path("crun-krun"))),
        patch("mendrune.executor.Path.is_file", return_value=True),
        patch("mendrune.executor.os.access", return_value=True),
        patch(
            "mendrune.executor.os.open",
            side_effect=kvm if isinstance(kvm, OSError) else None,
            return_value=kvm,
        ),
        patch("mendrune.executor.os.close"),
        patch("mendrune.executor.subprocess.run", side_effect=run),
        pytest.raises(MendRuneError) as raised,
    ):
        preflight(execution)

    assert raised.value.reason_code == reason_code
