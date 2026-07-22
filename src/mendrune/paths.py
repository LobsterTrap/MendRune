"""Path validation and evidence inventory."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from mendrune.errors import ConfigurationError

MAX_EVIDENCE_FILES = 10_000
MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class EvidenceFile:
    relative_path: PurePosixPath
    source_path: Path
    size: int
    executable: bool
    declared_by: tuple[str, ...]


def resolve_directory(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ConfigurationError(f"invalid {label}: {exc}", reason_code="unsafe_path") from exc
    if path.is_symlink() or not resolved.is_dir():
        raise ConfigurationError(
            f"{label} must be a non-symlink directory", reason_code="unsafe_path"
        )
    return resolved


def inventory_evidence(
    root: Path,
    declarations: dict[str, tuple[str, ...]],
) -> tuple[EvidenceFile, ...]:
    """Inventory declared evidence paths without following symlinks."""
    evidence_root = resolve_directory(root, label="evidence root")
    owners: dict[PurePosixPath, set[str]] = {}
    sources: dict[PurePosixPath, Path] = {}
    total_bytes = 0

    for owner, paths in sorted(declarations.items()):
        for value in paths:
            relative = _relative_path(value)
            source = evidence_root.joinpath(*relative.parts)
            _assert_beneath(evidence_root, source)
            try:
                source_stat = source.lstat()
            except OSError as exc:
                raise ConfigurationError(
                    f"evidence path does not exist: {value}", reason_code="evidence_path_invalid"
                ) from exc
            if stat.S_ISLNK(source_stat.st_mode):
                raise ConfigurationError(
                    f"evidence symlink is not allowed: {value}",
                    reason_code="evidence_type_unsupported",
                )
            if stat.S_ISREG(source_stat.st_mode):
                entries = [(relative, source, source_stat)]
            elif stat.S_ISDIR(source_stat.st_mode):
                entries = list(_walk_directory(evidence_root, relative, source))
            else:
                raise ConfigurationError(
                    f"unsupported evidence type: {value}",
                    reason_code="evidence_type_unsupported",
                )

            for entry_relative, entry_source, entry_stat in entries:
                if entry_stat.st_nlink != 1:
                    raise ConfigurationError(
                        f"hard-linked evidence is not supported: {entry_relative}",
                        reason_code="evidence_type_unsupported",
                    )
                if entry_stat.st_size > MAX_EVIDENCE_FILE_BYTES:
                    raise ConfigurationError(
                        f"evidence file exceeds size limit: {entry_relative}",
                        reason_code="evidence_limit_exceeded",
                    )
                total_bytes += entry_stat.st_size
                if total_bytes > MAX_EVIDENCE_TOTAL_BYTES:
                    raise ConfigurationError(
                        "evidence exceeds aggregate size limit",
                        reason_code="evidence_limit_exceeded",
                    )
                sources.setdefault(entry_relative, entry_source)
                owners.setdefault(entry_relative, set()).add(owner)
                if len(sources) > MAX_EVIDENCE_FILES:
                    raise ConfigurationError(
                        "evidence file count limit exceeded",
                        reason_code="evidence_limit_exceeded",
                    )

    return tuple(
        EvidenceFile(
            relative_path=relative,
            source_path=sources[relative],
            size=sources[relative].lstat().st_size,
            executable=bool(sources[relative].lstat().st_mode & stat.S_IXUSR),
            declared_by=tuple(sorted(owners[relative])),
        )
        for relative in sorted(sources, key=lambda item: item.as_posix().encode())
    )


def _walk_directory(root: Path, relative: PurePosixPath, source: Path):
    try:
        entries = sorted(os.scandir(source), key=lambda entry: os.fsencode(entry.name))
    except OSError as exc:
        raise ConfigurationError(
            f"unable to inventory evidence directory: {relative}",
            reason_code="evidence_path_invalid",
        ) from exc
    for entry in entries:
        entry_relative = relative / entry.name
        entry_path = source / entry.name
        _assert_beneath(root, entry_path)
        entry_stat = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(entry_stat.st_mode):
            raise ConfigurationError(
                f"evidence symlink is not allowed: {entry_relative}",
                reason_code="evidence_type_unsupported",
            )
        if stat.S_ISDIR(entry_stat.st_mode):
            yield from _walk_directory(root, entry_relative, entry_path)
        elif stat.S_ISREG(entry_stat.st_mode):
            yield entry_relative, entry_path, entry_stat
        else:
            raise ConfigurationError(
                f"unsupported evidence type: {entry_relative}",
                reason_code="evidence_type_unsupported",
            )


def _relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ConfigurationError(
            f"invalid evidence path: {value!r}", reason_code="evidence_path_invalid"
        )
    return path


def _assert_beneath(root: Path, path: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ConfigurationError(
            f"path escapes evidence root: {path}", reason_code="evidence_path_escape"
        ) from exc
