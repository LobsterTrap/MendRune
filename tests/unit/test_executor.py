from copy import deepcopy
from pathlib import Path

import pytest

from mendrune.errors import MendRuneError
from mendrune.executor import Invocation, Mount, build_podman_command
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

    assert command[:3] == ["podman", "run", "--rm"]
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
