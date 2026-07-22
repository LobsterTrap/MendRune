"""Defensive Git repository inspection."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from mendrune.errors import ConfigurationError

_GIT_ENV_REMOVE_PREFIXES = ("GIT_",)


@dataclass(frozen=True)
class VerifiedRepository:
    path: Path
    git_common_dir: Path
    base_commit: str


class Worktree:
    def __init__(self, repository: VerifiedRepository, path: Path) -> None:
        self.repository = repository
        self.path = path
        self._removed = False

    @classmethod
    def create(cls, repository: VerifiedRepository, parent: Path) -> Worktree:
        parent.mkdir(parents=True, exist_ok=True)
        path = Path(tempfile.mkdtemp(prefix="mendrune-worktree-", dir=parent))
        path.rmdir()
        try:
            _git(
                repository.path,
                "worktree",
                "add",
                "--detach",
                os.fspath(path),
                repository.base_commit,
            )
            worktree = cls(repository, path)
            if _git(path, "rev-parse", "HEAD").strip() != repository.base_commit:
                raise ConfigurationError(
                    "worktree HEAD does not match frozen base commit",
                    reason_code="worktree_invalid",
                )
            if _git(path, "status", "--porcelain=v1", "--untracked-files=all").strip():
                raise ConfigurationError(
                    "new worktree is not clean", reason_code="worktree_invalid"
                )
            return worktree
        except Exception:
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
            raise

    def remove(self) -> None:
        if self._removed:
            return
        result_error: Exception | None = None
        try:
            _git(self.repository.path, "worktree", "remove", "--force", os.fspath(self.path))
        except Exception as exc:
            result_error = exc
        finally:
            if self.path.exists():
                shutil.rmtree(self.path, ignore_errors=True)
            self._removed = True
        if result_error is not None:
            raise ConfigurationError(
                f"worktree cleanup failed: {result_error}", reason_code="cleanup_uncertain"
            ) from result_error

    def apply_patch(self, patch: Path) -> None:
        _git(self.path, "apply", "--check", "--whitespace=error-all", os.fspath(patch))
        _git(self.path, "apply", "--whitespace=error-all", os.fspath(patch))

    def diff(self) -> bytes:
        return _git_bytes(
            self.path,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--src-prefix=a/",
            "--dst-prefix=b/",
        )

    def status(self) -> str:
        return _git(self.path, "status", "--porcelain=v1", "--untracked-files=all")

    def __enter__(self) -> Worktree:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.remove()


def verify_repository(path: Path, base_ref: str) -> VerifiedRepository:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ConfigurationError(
            f"repository path is invalid: {exc}", reason_code="repository_not_local_git"
        ) from exc
    if path.is_symlink() or not resolved.is_dir():
        raise ConfigurationError(
            "repository must be a non-symlink local directory",
            reason_code="repository_not_local_git",
        )

    inside = _git(resolved, "rev-parse", "--is-inside-work-tree").strip()
    bare = _git(resolved, "rev-parse", "--is-bare-repository").strip()
    if inside != "true" or bare != "false":
        raise ConfigurationError(
            "repository must be a local non-bare Git worktree",
            reason_code="repository_not_local_git",
        )

    commit = _git(resolved, "rev-parse", "--verify", f"{base_ref}^{{commit}}").strip()
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise ConfigurationError(
            "base_ref did not resolve to a full SHA-1 commit",
            reason_code="base_ref_not_commit",
        )

    common_value = _git(resolved, "rev-parse", "--git-common-dir").strip()
    common_dir = Path(common_value)
    if not common_dir.is_absolute():
        common_dir = resolved / common_dir
    try:
        common_dir = common_dir.resolve(strict=True)
    except OSError as exc:
        raise ConfigurationError(
            f"Git common directory is invalid: {exc}", reason_code="repository_not_local_git"
        ) from exc

    return VerifiedRepository(path=resolved, git_common_dir=common_dir, base_commit=commit)


def _git(repository: Path, *args: str) -> str:
    return _git_bytes(repository, *args).decode("utf-8", errors="strict")


def _git_bytes(repository: Path, *args: str) -> bytes:
    command = [
        "git",
        "-c",
        "alias.rev-parse=",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "diff.external=",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-C",
        os.fspath(repository),
        *args,
    ]
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(_GIT_ENV_REMOVE_PREFIXES)
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigurationError(
            f"unable to inspect Git repository: {exc}", reason_code="repository_not_local_git"
        ) from exc
    if result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", errors="replace").strip()[:2000]
        reason = "base_ref_not_commit" if "rev-parse" in args else "repository_not_local_git"
        raise ConfigurationError(
            f"Git repository inspection failed: {diagnostic}", reason_code=reason
        )
    return result.stdout
