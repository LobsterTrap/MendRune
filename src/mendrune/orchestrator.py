"""Preflight orchestration and immutable campaign input capture."""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Self

from mendrune import executor
from mendrune.errors import MendRuneError
from mendrune.models import ExecutionConfig
from mendrune.oracle import evaluate_oracle_result
from mendrune.regression import evaluate_required_regression, select_shared_regressions
from mendrune.repository import TreeSnapshot, Worktree
from mendrune.runstore import RunStore
from mendrune.scanner import Finding, normalize_semgrep_json
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
            shutil.rmtree(self._workspace_parent)
        except FileNotFoundError:
            pass
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


Executor = Callable[[ExecutionConfig, executor.Invocation], executor.ExecutionResult]


def execute_phase_a(
    prepared: PreflightRun, *, execute: Executor = executor.execute
) -> tuple[Finding, ...]:
    """Execute and persist the complete Phase A baseline schedule."""
    config = prepared.verified.config
    snapshot = prepared.baseline.snapshot()
    findings: list[Finding] = []
    sequence = 0
    try:
        sequence += 1
        _run_command(
            prepared,
            execute,
            snapshot,
            sequence,
            "build",
            "build",
            config.commands.build.argv,
            config.commands.build.timeout_seconds,
        )
        for scheduled in select_shared_regressions(config):
            command = scheduled.command
            sequence += 1
            result, _ = _run_command(
                prepared,
                execute,
                snapshot,
                sequence,
                "regression",
                command.id,
                command.argv,
                command.timeout_seconds,
            )
            evaluated = evaluate_required_regression(
                command.id, exit_code=result.exit_code, timed_out=result.timed_out
            )
            if not evaluated.passed:
                raise MendRuneError(
                    "baseline regression failed",
                    reason_code=evaluated.reason_code or "regression_failed",
                )
        for unit in config.units:
            for vulnerability in unit.vulnerabilities:
                sequence += 1
                nonce = secrets.token_hex(16)
                result, output = _run_command(
                    prepared,
                    execute,
                    snapshot,
                    sequence,
                    "oracle",
                    vulnerability.id,
                    vulnerability.oracle.argv,
                    vulnerability.oracle.timeout_seconds,
                    environment={"MENDRUNE_ORACLE_NONCE": nonce},
                )
                result_path = _container_output_path(
                    output, config.mounts.container_output_dir, vulnerability.oracle.result_file
                )
                observation = evaluate_oracle_result(
                    output,
                    result_path,
                    expected_nonce=nonce,
                    expected_vulnerable=True,
                    exit_code=result.exit_code if result.exit_code is not None else -1,
                    timed_out=result.timed_out,
                )
                prepared.store.write_yaml(
                    f"phase-a/oracles/{sequence:04d}-{vulnerability.id}.yaml",
                    {
                        "schema_version": 1,
                        "check_id": f"phase-a-{sequence:04d}-oracle-{vulnerability.id}",
                        "status": "passed",
                        "vulnerable": observation.vulnerable,
                        "observation": observation.observation,
                    },
                )
        for scan in config.commands.scans:
            sequence += 1
            result, output = _run_command(
                prepared,
                execute,
                snapshot,
                sequence,
                "scanner",
                scan.id,
                scan.argv,
                scan.timeout_seconds,
            )
            if result.timed_out:
                raise MendRuneError("baseline scanner timed out", reason_code="command_timed_out")
            if result.exit_code != 0:
                raise MendRuneError("baseline scanner failed", reason_code="scanner_failed")
            raw_path = _container_output_path(
                output, config.mounts.container_output_dir, scan.raw_output
            )
            if scan.normalizer != "semgrep":
                raise MendRuneError(
                    "unknown scanner normalizer", reason_code="scanner_output_invalid"
                )
            normalized = normalize_semgrep_json(
                raw_path.read_bytes(), config.scan_policy.severity_order
            )
            findings.extend(normalized)
            prepared.store.write_yaml(
                f"phase-a/scans/{sequence:04d}-{scan.id}.yaml",
                {
                    "schema_version": 1,
                    "scanner_id": scan.id,
                    "findings": [_finding_record(item) for item in normalized],
                },
            )
        prepared.baseline.verify_integrity(snapshot, config.execution.allowed_generated_paths)
        prepared.store.write_hash_manifest()
        return tuple(sorted(findings, key=lambda item: item.identity))
    except Exception as exc:
        reason = exc.reason_code if isinstance(exc, MendRuneError) else "unexpected_internal_error"
        prepared.store.write_yaml(
            "phase-a/failure.yaml",
            {"schema_version": 1, "status": "failed", "reason_code": reason},
        )
        _advance(
            prepared.store, prepared.verified, RunState.PHASE_A_BASELINE, RunState.BASELINE_FAILURE
        )
        prepared.store.write_hash_manifest()
        if isinstance(exc, MendRuneError):
            raise
        raise MendRuneError("unexpected Phase A failure", reason_code=reason) from exc


def _run_command(
    prepared: PreflightRun,
    execute: Executor,
    snapshot: TreeSnapshot,
    sequence: int,
    kind: str,
    command_id: str,
    argv: tuple[str, ...],
    timeout_seconds: int,
    *,
    environment: dict[str, str] | None = None,
) -> tuple[executor.ExecutionResult, Path]:
    config = prepared.verified.config
    stem = f"{sequence:04d}-{kind}-{command_id}"
    output = prepared.store.path / "phase-a/outputs" / stem
    scratch = prepared._workspace_parent / "scratch" / stem
    output.mkdir(parents=True, mode=0o700)
    scratch.mkdir(parents=True, mode=0o700)
    invocation = executor.Invocation(
        image=config.execution.image,
        argv=argv,
        mounts=(
            executor.Mount(prepared.baseline.path, config.execution.container_workdir, False),
            executor.Mount(
                prepared.store.path / "input/evidence", config.mounts.container_evidence_dir, True
            ),
            executor.Mount(output, config.mounts.container_output_dir, False),
            executor.Mount(scratch, "/tmp", False),
        ),
        environment={**config.execution.environment, **(environment or {})},
        timeout_seconds=timeout_seconds,
    )
    result: executor.ExecutionResult | None = None
    try:
        result = execute(config.execution, invocation)
        _write_bytes_atomic(prepared.store.path / f"phase-a/logs/{stem}.stdout", result.stdout.data)
        _write_bytes_atomic(prepared.store.path / f"phase-a/logs/{stem}.stderr", result.stderr.data)
        prepared.store.write_yaml(
            f"phase-a/checks/{stem}.yaml",
            {
                "schema_version": 1,
                "check_id": f"phase-a-{stem}",
                "kind": kind,
                "command_id": command_id,
                "argv": list(argv),
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "status": "passed" if result.exit_code == 0 and not result.timed_out else "failed",
                "stdout": {
                    "total_bytes": result.stdout.total_bytes,
                    "truncated": result.stdout.truncated,
                },
                "stderr": {
                    "total_bytes": result.stderr.total_bytes,
                    "truncated": result.stderr.truncated,
                },
            },
        )
        if result.timed_out:
            raise MendRuneError(f"{kind} timed out", reason_code="command_timed_out")
        if result.exit_code != 0:
            reasons = {
                "build": "build_failed",
                "regression": "regression_failed",
                "oracle": "candidate_oracle_invalid",
                "scanner": "scanner_failed",
            }
            raise MendRuneError(f"{kind} exited unsuccessfully", reason_code=reasons[kind])
        return result, output
    finally:
        try:
            prepared.baseline.verify_integrity(snapshot, config.execution.allowed_generated_paths)
        except Exception as integrity_error:
            if result is not None:
                prepared.store.write_yaml(
                    f"phase-a/checks/{stem}-integrity.yaml",
                    {
                        "schema_version": 1,
                        "check_id": f"phase-a-{stem}-integrity",
                        "status": "failed",
                        "reason_code": "actual_diff_mismatch",
                    },
                )
            raise integrity_error
        else:
            prepared.store.write_yaml(
                f"phase-a/checks/{stem}-integrity.yaml",
                {"schema_version": 1, "check_id": f"phase-a-{stem}-integrity", "status": "passed"},
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


def _container_output_path(output: Path, container_root: str, container_path: str) -> Path:
    relative = PurePosixPath(container_path).relative_to(PurePosixPath(container_root))
    return output.joinpath(*relative.parts)


def _finding_record(finding: Finding) -> dict[str, object]:
    return {
        "scanner_id": finding.scanner_id,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "path": finding.path.as_posix(),
        "line": finding.line,
        "fingerprint": finding.fingerprint,
        "message": finding.message,
    }


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
