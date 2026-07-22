"""Immutable evidence capture and YAML manifests."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from mendrune.errors import ConfigurationError
from mendrune.paths import EvidenceFile


@dataclass(frozen=True)
class CapturedEvidence:
    relative_path: PurePosixPath
    snapshot_path: Path
    size: int
    sha256: str
    executable: bool
    declared_by: tuple[str, ...]


def capture_evidence(
    files: tuple[EvidenceFile, ...],
    destination: Path,
) -> tuple[CapturedEvidence, ...]:
    if destination.exists():
        raise ConfigurationError(
            f"evidence snapshot already exists: {destination}",
            reason_code="evidence_manifest_mismatch",
        )
    destination.mkdir(parents=True, mode=0o700)
    captured: list[CapturedEvidence] = []
    try:
        for item in files:
            target = destination.joinpath(*item.relative_path.parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            before = item.source_path.lstat()
            _validate_source(before, item)
            digest = hashlib.sha256()
            with item.source_path.open("rb") as source, target.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            after = item.source_path.lstat()
            if _identity(before) != _identity(after):
                raise ConfigurationError(
                    f"evidence changed during capture: {item.relative_path}",
                    reason_code="evidence_capture_race",
                )
            target.chmod(0o500 if item.executable else 0o400)
            captured.append(
                CapturedEvidence(
                    relative_path=item.relative_path,
                    snapshot_path=target,
                    size=before.st_size,
                    sha256=digest.hexdigest(),
                    executable=item.executable,
                    declared_by=item.declared_by,
                )
            )
        _make_directories_read_only(destination)
        return tuple(captured)
    except Exception:
        _make_tree_writable(destination)
        shutil.rmtree(destination, ignore_errors=True)
        raise


def write_evidence_manifest(path: Path, captured: tuple[CapturedEvidence, ...]) -> None:
    document = {
        "schema_version": 1,
        "algorithm": "sha256",
        "files": [
            {
                "path": item.relative_path.as_posix(),
                "size": item.size,
                "sha256": item.sha256,
                "executable": item.executable,
                "declared_by": list(item.declared_by),
            }
            for item in captured
        ],
    }
    _write_yaml_atomic(path, document)


def _write_yaml_atomic(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            yaml.safe_dump(document, stream, sort_keys=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _validate_source(value: os.stat_result, item: EvidenceFile) -> None:
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_size != item.size:
        raise ConfigurationError(
            f"evidence changed before capture: {item.relative_path}",
            reason_code="evidence_capture_race",
        )


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns


def _make_directories_read_only(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for path in reversed(directories):
        path.chmod(0o500)
    root.chmod(0o500)


def _make_tree_writable(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o700)
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
        elif path.is_file():
            path.chmod(0o600)
