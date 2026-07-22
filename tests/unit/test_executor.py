import io
import subprocess
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mendrune.errors import MendRuneError
from mendrune.executor import Invocation, Mount, build_podman_command, execute
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
    assert any(value.endswith(":/evidence:ro") for value in command)
    assert execution.image in command


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
    assert run.call_args_list[0].args[0] == ["podman", "kill", "--ignore", name]
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
