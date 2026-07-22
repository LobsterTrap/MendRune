import os
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from mendrune.errors import ConfigurationError
from mendrune.models import PatchPolicyConfig
from mendrune.patches import parse_patch
from mendrune.repository import Worktree, verify_repository
from tests.unit.test_models import campaign_data


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", os.fspath(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": os.fspath(repository.parent), "LC_ALL": "C"},
    )
    return result.stdout.strip()


def _repository(path: Path) -> None:
    path.mkdir()
    _git(path, "init", "-q")
    _git(path, "config", "user.name", "Security Test")
    _git(path, "config", "user.email", "security@example.invalid")
    (path / "file.txt").write_text("base\n", encoding="utf-8")
    _git(path, "add", "file.txt")
    _git(path, "commit", "-qm", "base")


def _policy() -> PatchPolicyConfig:
    data = deepcopy(campaign_data()["patch_policy"])
    data["allowed_paths"] = ["src/**"]
    return PatchPolicyConfig.model_validate(data)


def test_git_hooks_and_local_config_cannot_execute(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _repository(repository)
    marker = tmp_path / "host-code-executed"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    hook.chmod(0o700)
    external = tmp_path / "external-diff"
    external.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    external.chmod(0o700)
    _git(repository, "config", "core.hooksPath", os.fspath(hooks))
    _git(repository, "config", "diff.external", os.fspath(external))
    _git(repository, "config", "alias.rev-parse", f"!touch '{marker}'")

    verified = verify_repository(repository, "HEAD")
    with Worktree.create(verified, tmp_path / "worktrees") as worktree:
        (worktree.path / "file.txt").write_text("changed\n", encoding="utf-8")
        assert b"+changed" in worktree.diff()

    assert not marker.exists()


def test_git_environment_and_global_config_are_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    _repository(repository)
    fake_repository = tmp_path / "fake"
    _repository(fake_repository)
    marker = tmp_path / "global-hook-executed"
    hooks = tmp_path / "global-hooks"
    hooks.mkdir()
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    hook.chmod(0o700)
    home = tmp_path / "hostile-home"
    home.mkdir()
    (home / ".gitconfig").write_text(
        f"[core]\n\thooksPath = {hooks}\n[alias]\n\trev-parse = !touch '{marker}'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.setenv("GIT_DIR", os.fspath(fake_repository / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", os.fspath(fake_repository))

    verified = verify_repository(repository, "HEAD")
    with Worktree.create(verified, tmp_path / "worktrees"):
        pass

    assert verified.path == repository.resolve()
    assert not marker.exists()


@pytest.mark.parametrize(
    "path",
    ["../escape.py", "src/../../escape.py", "/tmp/escape.py", "src\\..\\escape.py"],
)
def test_rejects_traversal_diff_paths(path: str) -> None:
    patch = f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n".encode()

    with pytest.raises(ConfigurationError) as raised:
        parse_patch(patch, _policy())

    assert raised.value.reason_code == "patch_policy_violation"
