import subprocess
from pathlib import Path

import pytest

from mendrune.errors import ConfigurationError
from mendrune.repository import Worktree, verify_repository


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(path.parent), "LC_ALL": "C"},
    )
    return result.stdout.strip()


def create_repository(path: Path) -> str:
    path.mkdir()
    git(path, "init", "-q")
    git(path, "config", "user.name", "Test")
    git(path, "config", "user.email", "test@example.invalid")
    (path / "file.txt").write_text("base\n")
    git(path, "add", "file.txt")
    git(path, "commit", "-qm", "base")
    return git(path, "rev-parse", "HEAD")


def test_verify_repository_resolves_commit(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    expected = create_repository(repository)

    verified = verify_repository(repository, "HEAD")

    assert verified.path == repository.resolve()
    assert verified.base_commit == expected


def test_verify_repository_does_not_require_clean_source(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    expected = create_repository(repository)
    (repository / "file.txt").write_text("dirty\n")

    assert verify_repository(repository, "HEAD").base_commit == expected
    assert (repository / "file.txt").read_text() == "dirty\n"


def test_worktree_is_detached_clean_and_removed(tmp_path: Path) -> None:
    repository_path = tmp_path / "repo"
    expected = create_repository(repository_path)
    repository = verify_repository(repository_path, "HEAD")

    with Worktree.create(repository, tmp_path / "scratch") as worktree:
        assert git(worktree.path, "rev-parse", "HEAD") == expected
        detached = subprocess.run(
            ["git", "-C", str(worktree.path), "symbolic-ref", "-q", "HEAD"],
            check=False,
            capture_output=True,
        )
        assert detached.returncode == 1
        assert worktree.path.exists()
        worktree_path = worktree.path

    assert not worktree_path.exists()
    assert git(repository_path, "worktree", "list", "--porcelain").count("worktree ") == 1


def test_worktree_applies_patch_and_reports_diff(tmp_path: Path) -> None:
    repository_path = tmp_path / "repo"
    create_repository(repository_path)
    repository = verify_repository(repository_path, "HEAD")
    patch = tmp_path / "change.diff"
    patch.write_bytes(b"--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-base\n+fixed\n")

    with Worktree.create(repository, tmp_path / "scratch") as worktree:
        worktree.apply_patch(patch)
        assert (worktree.path / "file.txt").read_text() == "fixed\n"
        assert b"+fixed" in worktree.diff()
        assert worktree.status().startswith(" M file.txt")


def test_verify_repository_rejects_unknown_ref(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    create_repository(repository)

    with pytest.raises(ConfigurationError) as raised:
        verify_repository(repository, "missing")

    assert raised.value.reason_code == "base_ref_not_commit"
