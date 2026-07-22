"""Preflight orchestration and immutable campaign input capture."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Self

from mendrune import executor
from mendrune.errors import MendRuneError
from mendrune.repository import Worktree
from mendrune.runstore import RunStore
from mendrune.state import RunState, transition
from mendrune.storage import capture_evidence, write_evidence_manifest
from mendrune.verify import VerifiedCampaign, VerifiedPatch, verify_campaign


@dataclass(frozen=True)
class FrozenPatch:
    unit_id: str
    patch_id: str
    supplied_path: PurePosixPath
    supplied_sha256: str
    effective_path: PurePosixPath
    effective_sha256: str
    effective_kind: str = "supplied"


@dataclass
class PreflightRun:
    verified: VerifiedCampaign
    store: RunStore
    patches: tuple[FrozenPatch, ...]
    baseline: Worktree
    _workspace_parent: Path
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        cleanup_error: Exception | None = None
        try:
            self.baseline.remove()
        except Exception as exc:
            cleanup_error = exc
        try:
            self._workspace_parent.rmdir()
        except OSError as exc:
            cleanup_error = cleanup_error or exc
        self._closed = True
        if cleanup_error is not None:
            raise MendRuneError(
                f"baseline cleanup failed: {cleanup_error}", reason_code="cleanup_uncertain"
            ) from cleanup_error

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def prepare_preflight(campaign_path: Path, *, run_id: str | None = None) -> PreflightRun:
    """Validate and freeze inputs, qualify isolation, and create the Phase A worktree."""
    original_campaign = campaign_path.resolve(strict=True).read_bytes()
    verified = verify_campaign(campaign_path)
    if verified.path.read_bytes() != original_campaign:
        raise MendRuneError("campaign changed during validation", reason_code="input_capture_race")

    store = RunStore.create(verified.runs_directory, verified.config.campaign_id, run_id=run_id)
    state = RunState.CREATED
    _persist_state(store, verified, state)
    state = _advance(store, verified, state, RunState.VALIDATING)
    state = _advance(store, verified, state, RunState.PREFLIGHT)

    try:
        executor.preflight(verified.config.execution)
    except Exception:
        _advance(store, verified, state, RunState.INFRASTRUCTURE_ERROR)
        raise

    state = _advance(store, verified, state, RunState.CAPTURING_INPUTS)
    try:
        _write_bytes_atomic(store.path / "input/campaign.yaml", original_campaign)
        store.write_yaml(
            "input/repository.yaml",
            {
                "schema_version": 1,
                "path": os.fspath(verified.repository.path),
                "git_common_dir": os.fspath(verified.repository.git_common_dir),
                "base_commit": verified.repository.base_commit,
            },
        )
        frozen = _capture_patches(store, verified)
        captured = capture_evidence(verified.evidence, store.path / "input/evidence")
        write_evidence_manifest(store.path / "input/evidence-manifest.yaml", captured)
        store.write_yaml(
            "input/patches.yaml",
            {
                "schema_version": 1,
                "patches": [
                    {
                        "unit_id": item.unit_id,
                        "patch_id": item.patch_id,
                        "supplied": {
                            "path": item.supplied_path.as_posix(),
                            "sha256": item.supplied_sha256,
                        },
                        "effective": {
                            "kind": item.effective_kind,
                            "path": item.effective_path.as_posix(),
                            "sha256": item.effective_sha256,
                        },
                    }
                    for item in frozen
                ],
            },
        )
        _make_input_read_only(store.path / "input")
    except Exception:
        _advance(store, verified, state, RunState.EVIDENCE_FAILURE)
        raise

    state = _advance(store, verified, state, RunState.PHASE_A_BASELINE)
    store.write_hash_manifest()
    workspace_parent = verified.runs_directory / ".workspaces" / store.run_id
    try:
        baseline = Worktree.create(verified.repository, workspace_parent)
    except Exception:
        shutil.rmtree(workspace_parent, ignore_errors=True)
        _advance(store, verified, state, RunState.INFRASTRUCTURE_ERROR)
        raise
    return PreflightRun(verified, store, frozen, baseline, workspace_parent)


def _capture_patches(store: RunStore, verified: VerifiedCampaign) -> tuple[FrozenPatch, ...]:
    sequence_by_unit: dict[str, int] = {}
    frozen: list[FrozenPatch] = []
    patch_config = {
        (unit.id, patch.id): patch for unit in verified.config.units for patch in unit.patches
    }
    for patch in verified.patches:
        configured = patch_config[(patch.unit_id, patch.patch_id)]
        if configured.adapt_with_goose:
            raise MendRuneError(
                "Goose adaptation is outside P6-T01",
                reason_code="goose_adaptation_not_implemented",
            )
        sequence = sequence_by_unit.get(patch.unit_id, 0) + 1
        sequence_by_unit[patch.unit_id] = sequence
        data = _read_verified_patch(patch)
        relative = PurePosixPath("input", "patches", patch.unit_id, f"{sequence:02d}-supplied.diff")
        destination = store.path.joinpath(*relative.parts)
        _write_bytes_atomic(destination, data)
        destination.chmod(0o400)
        frozen.append(
            FrozenPatch(
                unit_id=patch.unit_id,
                patch_id=patch.patch_id,
                supplied_path=relative,
                supplied_sha256=patch.sha256,
                effective_path=relative,
                effective_sha256=patch.sha256,
            )
        )
    return tuple(frozen)


def _read_verified_patch(patch: VerifiedPatch) -> bytes:
    data = patch.path.read_bytes()
    if hashlib.sha256(data).hexdigest() != patch.sha256:
        raise MendRuneError(
            f"patch changed during capture: {patch.unit_id}/{patch.patch_id}",
            reason_code="input_capture_race",
        )
    return data


def _make_input_read_only(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file():
            path.chmod(0o500 if os.access(path, os.X_OK) else 0o400)
    for path in reversed([item for item in root.rglob("*") if item.is_dir()]):
        path.chmod(0o500)
    root.chmod(0o500)


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _advance(
    store: RunStore,
    verified: VerifiedCampaign,
    current: RunState,
    target: RunState,
) -> RunState:
    state = transition(current, target)
    _persist_state(store, verified, state)
    return state


def _persist_state(store: RunStore, verified: VerifiedCampaign, state: RunState) -> None:
    store.write_yaml(
        "run.yaml",
        {
            "schema_version": 1,
            "run_id": store.run_id,
            "campaign_id": verified.config.campaign_id,
            "state": state.value,
            "base_commit": verified.repository.base_commit,
        },
    )
