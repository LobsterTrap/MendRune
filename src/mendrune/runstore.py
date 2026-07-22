"""Confined run directory and atomic YAML records."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from secrets import token_hex

import yaml

from mendrune.errors import MendRuneError

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True)
class Artifact:
    relative_path: PurePosixPath
    path: Path
    sha256: str
    size: int


class RunStore:
    def __init__(self, root: Path, run_id: str) -> None:
        if not _RUN_ID.fullmatch(run_id):
            raise MendRuneError("invalid run ID", reason_code="unsafe_path")
        self.root = root.resolve(strict=False)
        self.run_id = run_id
        self.path = self.root / run_id

    @classmethod
    def create(cls, root: Path, campaign_id: str, run_id: str | None = None) -> RunStore:
        if run_id is None:
            timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            run_id = f"{timestamp}-{campaign_id}-{token_hex(4)}"
        store = cls(root, run_id)
        try:
            store.path.mkdir(parents=True, mode=0o700, exist_ok=False)
        except OSError as exc:
            raise MendRuneError(
                f"unable to create run directory: {exc}", reason_code="atomic_write_failed"
            ) from exc
        return store

    def write_yaml(self, relative: str, document: object) -> Artifact:
        destination = self._destination(relative)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                yaml.safe_dump(document, stream, sort_keys=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            raise MendRuneError(
                f"atomic YAML write failed: {exc}", reason_code="atomic_write_failed"
            ) from exc
        return self.artifact(relative)

    def write_hash_manifest(self, relative: str = "hashes.yaml") -> Artifact:
        files: list[dict[str, object]] = []
        for candidate in sorted(self.path.rglob("*"), key=lambda item: item.as_posix().encode()):
            if candidate == self._destination(relative):
                continue
            if candidate.is_symlink():
                raise MendRuneError(
                    f"run artifact is a symlink: {candidate}", reason_code="artifact_hash_failed"
                )
            if candidate.is_file():
                logical = candidate.relative_to(self.path).as_posix()
                artifact = self.artifact(logical)
                files.append({"path": logical, "size": artifact.size, "sha256": artifact.sha256})
        return self.write_yaml(
            relative,
            {"schema_version": 1, "algorithm": "sha256", "files": files},
        )

    def verify_hash_manifest(self, relative: str = "hashes.yaml") -> None:
        manifest_path = self._destination(relative)
        try:
            document = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            entries = document["files"]
        except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
            raise MendRuneError(
                "hash manifest is invalid", reason_code="artifact_hash_failed"
            ) from exc
        for entry in entries:
            artifact = self.artifact(entry["path"])
            if artifact.sha256 != entry["sha256"] or artifact.size != entry["size"]:
                raise MendRuneError(
                    f"artifact hash mismatch: {entry['path']}",
                    reason_code="artifact_hash_mismatch",
                )

    def artifact(self, relative: str) -> Artifact:
        destination = self._destination(relative)
        if destination.is_symlink() or not destination.is_file():
            raise MendRuneError("artifact is not a regular file", reason_code="artifact_missing")
        digest = hashlib.sha256()
        with destination.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return Artifact(
            relative_path=PurePosixPath(relative),
            path=destination,
            sha256=digest.hexdigest(),
            size=destination.stat().st_size,
        )

    def _destination(self, relative: str) -> Path:
        logical = PurePosixPath(relative)
        if (
            not relative
            or logical.is_absolute()
            or any(part in {"", ".", ".."} for part in logical.parts)
        ):
            raise MendRuneError("unsafe run artifact path", reason_code="unsafe_path")
        destination = self.path.joinpath(*logical.parts)
        current = self.path
        for part in logical.parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise MendRuneError("run path contains symlink", reason_code="unsafe_path")
        return destination
