"""Defensive Git repository inspection."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from mendrune.errors import ConfigurationError
from mendrune.models import PatchPolicyConfig
from mendrune.patches import HunkPlacement, locate_hunks, parse_patch
from mendrune.policy import matches_path

_GIT_ENV_REMOVE_PREFIXES = ("GIT_",)


@dataclass(frozen=True)
class TreeEntry:
    path: PurePosixPath
    mode: int
    size: int
    sha256: str


@dataclass(frozen=True)
class TreeSnapshot:
    tracked: tuple[TreeEntry, ...]


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

    def apply_patch(
        self, patch: Path, policy: PatchPolicyConfig | None = None
    ) -> tuple[HunkPlacement, ...]:
        data = patch.read_bytes()
        placements = locate_hunks(self.path, parse_patch(data, policy)) if policy else ()
        _apply(self.path, patch, check=True)
        _apply(self.path, patch, check=False)
        return placements

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

    def snapshot(self) -> TreeSnapshot:
        entries: list[TreeEntry] = []
        for raw_path in _git_bytes(self.path, "ls-files", "-z").split(b"\0"):
            if not raw_path:
                continue
            path = PurePosixPath(raw_path.decode("utf-8", errors="strict"))
            source = self.path.joinpath(*path.parts)
            source_stat = source.lstat()
            if not stat.S_ISREG(source_stat.st_mode) or source.is_symlink():
                raise ConfigurationError(
                    f"tracked path is not a regular file: {path}",
                    reason_code="actual_diff_mismatch",
                )
            entries.append(
                TreeEntry(
                    path,
                    stat.S_IMODE(source_stat.st_mode),
                    source_stat.st_size,
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                )
            )
        return TreeSnapshot(tuple(entries))

    def verify_integrity(
        self, expected: TreeSnapshot, allowed_generated_paths: tuple[str, ...] = ()
    ) -> None:
        if self.snapshot() != expected:
            raise ConfigurationError(
                "tracked source tree changed unexpectedly", reason_code="actual_diff_mismatch"
            )
        for raw_path in _git_bytes(
            self.path, "ls-files", "--others", "--exclude-standard", "-z"
        ).split(b"\0"):
            if not raw_path:
                continue
            path = PurePosixPath(raw_path.decode("utf-8", errors="strict"))
            source = self.path.joinpath(*path.parts)
            source_stat = source.lstat()
            if (
                source.is_symlink()
                or not stat.S_ISREG(source_stat.st_mode)
                or not any(
                    matches_path(pattern, path.as_posix()) for pattern in allowed_generated_paths
                )
            ):
                raise ConfigurationError(
                    f"unexpected generated path: {path}", reason_code="actual_diff_mismatch"
                )

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


def _apply(repository: Path, patch: Path, *, check: bool) -> None:
    args = ["apply"]
    if check:
        args.append("--check")
    args.extend(("--whitespace=error-all", os.fspath(patch)))
    try:
        _git(repository, *args)
    except ConfigurationError as exc:
        reason = "patch_check_failed" if check else "patch_apply_failed"
        raise ConfigurationError(str(exc), reason_code=reason) from exc


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
