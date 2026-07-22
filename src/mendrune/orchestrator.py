"""Preflight orchestration and immutable campaign input capture."""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Self

import yaml

from mendrune import executor
from mendrune.errors import MendRuneError
from mendrune.goose import adapt_patch, write_evidence_bundle
from mendrune.models import ExecutionConfig
from mendrune.oracle import evaluate_oracle_result
from mendrune.patches import parse_patch
from mendrune.policy import matches_path
from mendrune.regression import (
    evaluate_required_regression,
    select_accumulated_regressions,
    select_shared_regressions,
    select_unit_regressions,
)
from mendrune.reporting import LIMITATIONS
from mendrune.repository import TreeSnapshot, Worktree
from mendrune.runstore import RunStore
from mendrune.scanner import Finding, compare_findings, normalize_semgrep_json, read_scanner_output
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
    derived_from_sha256: str | None = None
    recipe_sha256: str | None = None


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
                read_scanner_output(output, raw_path, config.execution.maximum_output_bytes),
                scan.id,
                config.scan_policy.severity_order,
            )
            findings.extend(normalized)
            prepared.store.write_yaml(
                f"phase-a/scans/{sequence:04d}-{scan.id}.yaml",
                {
                    "schema_version": 1,
                    "check_id": f"phase-a-{sequence:04d}-scanner-{scan.id}",
                    "scanner_id": scan.id,
                    "status": "passed",
                    "findings": [_finding_record(item) for item in normalized],
                },
            )
        prepared.baseline.verify_integrity(snapshot, config.execution.allowed_generated_paths)
        _write_unit_manifest(prepared.store, "phase-a")
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


def execute_phase_b(
    prepared: PreflightRun,
    phase_a_findings: tuple[Finding, ...],
    *,
    execute: Executor = executor.execute,
) -> dict[str, tuple[Finding, ...]]:
    """Verify every remediation unit independently from the frozen base commit."""
    config = prepared.verified.config
    units = {unit.id: unit for unit in config.units}
    results: dict[str, tuple[Finding, ...]] = {}
    _advance(
        prepared.store, prepared.verified, RunState.PHASE_A_BASELINE, RunState.PHASE_B_ISOLATED
    )
    for unit_id in config.composition.order:
        unit = units[unit_id]
        root = f"phase-b/{unit_id}"
        worktree: Worktree | None = None
        try:
            worktree = Worktree.create(prepared.verified.repository, prepared._workspace_parent)
            sequence = 0
            unit_patches = tuple(patch for patch in prepared.patches if patch.unit_id == unit_id)
            if tuple(patch.patch_id for patch in unit_patches) != tuple(
                patch.id for patch in unit.patches
            ):
                raise MendRuneError(
                    "frozen patch order is incomplete", reason_code="actual_diff_mismatch"
                )
            for frozen in unit_patches:
                sequence += 1
                patch_path = prepared.store.path.joinpath(*frozen.effective_path.parts)
                patch_data = patch_path.read_bytes()
                if hashlib.sha256(patch_data).hexdigest() != frozen.effective_sha256:
                    raise MendRuneError(
                        "frozen patch integrity failed", reason_code="actual_diff_mismatch"
                    )
                before = worktree.diff()
                placements = worktree.apply_patch(patch_path, config.patch_policy)
                after = worktree.diff()
                if after == before:
                    raise MendRuneError(
                        "patch produced no actual diff", reason_code="actual_diff_mismatch"
                    )
                prepared.store.write_yaml(
                    f"{root}/patches/{sequence:04d}-{frozen.patch_id}.yaml",
                    {
                        "schema_version": 1,
                        "patch_id": frozen.patch_id,
                        "effective_sha256": frozen.effective_sha256,
                        "before_diff_sha256": hashlib.sha256(before).hexdigest(),
                        "actual_diff_sha256": hashlib.sha256(after).hexdigest(),
                        "placements": [
                            {
                                "path": item.path.as_posix(),
                                "original_start": item.original_start,
                                "applied_start": item.applied_start,
                                "old_count": item.old_count,
                                "new_count": item.new_count,
                            }
                            for item in placements
                        ],
                    },
                )
                _write_bytes_atomic(
                    prepared.store.path / f"{root}/diffs/{sequence:04d}-{frozen.patch_id}.diff",
                    after,
                )
            expected = worktree.snapshot()
            sequence += 1
            _run_isolated_command(
                prepared,
                execute,
                worktree,
                expected,
                root,
                sequence,
                "build",
                "build",
                config.commands.build.argv,
                config.commands.build.timeout_seconds,
                failure_code="unit_build_failed",
            )
            for vulnerability in unit.vulnerabilities:
                sequence += 1
                nonce = secrets.token_hex(16)
                try:
                    result, output = _run_isolated_command(
                        prepared,
                        execute,
                        worktree,
                        expected,
                        root,
                        sequence,
                        "oracle",
                        vulnerability.id,
                        vulnerability.oracle.argv,
                        vulnerability.oracle.timeout_seconds,
                        environment={"MENDRUNE_ORACLE_NONCE": nonce},
                        failure_code="unit_vulnerability_not_mitigated",
                    )
                    observation = evaluate_oracle_result(
                        output,
                        _container_output_path(
                            output,
                            config.mounts.container_output_dir,
                            vulnerability.oracle.result_file,
                        ),
                        expected_nonce=nonce,
                        expected_vulnerable=False,
                        exit_code=result.exit_code if result.exit_code is not None else -1,
                        timed_out=result.timed_out,
                    )
                except MendRuneError as exc:
                    if exc.reason_code == "actual_diff_mismatch":
                        raise
                    raise MendRuneError(
                        "unit vulnerability was not mitigated",
                        reason_code="unit_vulnerability_not_mitigated",
                    ) from exc
                prepared.store.write_yaml(
                    f"{root}/oracles/{sequence:04d}-{vulnerability.id}.yaml",
                    {
                        "schema_version": 1,
                        "check_id": f"phase-b-{unit_id}-{sequence:04d}-oracle-{vulnerability.id}",
                        "status": "passed",
                        "vulnerable": observation.vulnerable,
                        "observation": observation.observation,
                    },
                )
            for scheduled in select_unit_regressions(config, unit_id):
                sequence += 1
                command = scheduled.command
                result, _ = _run_isolated_command(
                    prepared,
                    execute,
                    worktree,
                    expected,
                    root,
                    sequence,
                    "regression",
                    command.id,
                    command.argv,
                    command.timeout_seconds,
                    failure_code="unit_regression_failed",
                )
                evaluated = evaluate_required_regression(
                    command.id,
                    exit_code=result.exit_code,
                    timed_out=result.timed_out,
                    failure_reason_code="unit_regression_failed",
                )
                if not evaluated.passed:
                    raise MendRuneError(
                        "unit regression failed",
                        reason_code=evaluated.reason_code or "unit_regression_failed",
                    )
            findings: list[Finding] = []
            for scan in config.commands.scans:
                sequence += 1
                result, output = _run_isolated_command(
                    prepared,
                    execute,
                    worktree,
                    expected,
                    root,
                    sequence,
                    "scanner",
                    scan.id,
                    scan.argv,
                    scan.timeout_seconds,
                    failure_code="scanner_failed",
                )
                if scan.normalizer != "semgrep":
                    raise MendRuneError(
                        "unknown scanner normalizer", reason_code="scanner_output_invalid"
                    )
                raw_path = _container_output_path(
                    output, config.mounts.container_output_dir, scan.raw_output
                )
                normalized = normalize_semgrep_json(
                    read_scanner_output(output, raw_path, config.execution.maximum_output_bytes),
                    scan.id,
                    config.scan_policy.severity_order,
                )
                findings.extend(normalized)
                prepared.store.write_yaml(
                    f"{root}/scans/{sequence:04d}-{scan.id}.yaml",
                    {
                        "schema_version": 1,
                        "check_id": f"{root.replace('/', '-')}-{sequence:04d}-scanner-{scan.id}",
                        "scanner_id": scan.id,
                        "status": "passed",
                        "findings": [_finding_record(item) for item in normalized],
                    },
                )
            normalized_findings = tuple(sorted(findings, key=lambda item: item.identity))
            delta = compare_findings(
                phase_a_findings,
                normalized_findings,
                severity_order=config.scan_policy.severity_order,
                threshold=config.scan_policy.reject_new_findings_at_or_above,
            )
            prepared.store.write_yaml(
                f"{root}/scan-comparison.yaml",
                {
                    "schema_version": 1,
                    "status": "passed" if delta.passed else "failed",
                    "prohibited": [_finding_record(item) for item in delta.prohibited],
                    "introduced": [_finding_record(item) for item in delta.introduced],
                    "severity_increases": [
                        _finding_record(item) for item in delta.severity_increases
                    ],
                },
            )
            if not delta.passed:
                raise MendRuneError(
                    "unit introduced prohibited finding", reason_code="prohibited_new_finding"
                )
            worktree.verify_integrity(expected, config.execution.allowed_generated_paths)
            _write_unit_manifest(prepared.store, root)
            prepared.store.write_hash_manifest()
            results[unit_id] = normalized_findings
        except Exception as exc:
            reason = exc.reason_code if isinstance(exc, MendRuneError) else "unexpected_exception"
            prepared.store.write_yaml(
                f"{root}/failure.yaml",
                {"schema_version": 1, "status": "failed", "reason_code": reason},
            )
            _advance(
                prepared.store,
                prepared.verified,
                RunState.PHASE_B_ISOLATED,
                RunState.ISOLATED_UNIT_FAILURE,
            )
            prepared.store.write_hash_manifest()
            if isinstance(exc, MendRuneError):
                raise
            raise MendRuneError("unexpected isolated unit failure", reason_code=reason) from exc
        finally:
            if worktree is not None:
                try:
                    worktree.remove()
                except Exception as cleanup_error:
                    prepared.store.write_yaml(
                        f"{root}/cleanup-failure.yaml",
                        {
                            "schema_version": 1,
                            "status": "failed",
                            "reason_code": "cleanup_uncertain",
                        },
                    )
                    prepared.store.write_hash_manifest()
                    if not config.storage.keep_failed_workspaces:
                        raise MendRuneError(
                            f"isolated worktree cleanup failed: {cleanup_error}",
                            reason_code="cleanup_uncertain",
                        ) from cleanup_error
    return results


def execute_phase_c(
    prepared: PreflightRun,
    phase_a_findings: tuple[Finding, ...],
    *,
    execute: Executor = executor.execute,
) -> dict[str, tuple[Finding, ...]]:
    """Compose frozen units in one worktree with strict accumulated verification."""
    config = prepared.verified.config
    units = {unit.id: unit for unit in config.units}
    previous_findings = phase_a_findings
    results: dict[str, tuple[Finding, ...]] = {}
    applied: list[str] = []
    worktree: Worktree | None = None
    state = _advance(
        prepared.store, prepared.verified, RunState.PHASE_B_ISOLATED, RunState.PHASE_C_PREAPPLY
    )
    try:
        worktree = Worktree.create(prepared.verified.repository, prepared._workspace_parent)
        expected = worktree.snapshot()
        for stage_number, unit_id in enumerate(config.composition.order, start=1):
            unit = units[unit_id]
            root = f"phase-c/stages/{stage_number:04d}-{unit_id}"
            sequence = 0

            # Strictly reproduce every current-unit vulnerability immediately before apply.
            for vulnerability in unit.vulnerabilities:
                sequence += 1
                nonce = secrets.token_hex(16)
                try:
                    result, output = _run_isolated_command(
                        prepared,
                        execute,
                        worktree,
                        expected,
                        root,
                        sequence,
                        "preapply-oracle",
                        vulnerability.id,
                        vulnerability.oracle.argv,
                        vulnerability.oracle.timeout_seconds,
                        environment={"MENDRUNE_ORACLE_NONCE": nonce},
                        failure_code="unit_vulnerability_already_mitigated",
                    )
                    observation = evaluate_oracle_result(
                        output,
                        _container_output_path(
                            output,
                            config.mounts.container_output_dir,
                            vulnerability.oracle.result_file,
                        ),
                        expected_nonce=nonce,
                        expected_vulnerable=True,
                        exit_code=result.exit_code if result.exit_code is not None else -1,
                        timed_out=result.timed_out,
                    )
                except MendRuneError as exc:
                    if exc.reason_code == "actual_diff_mismatch":
                        raise
                    raise MendRuneError(
                        "current unit vulnerability is already mitigated",
                        reason_code="unit_vulnerability_already_mitigated",
                    ) from exc
                prepared.store.write_yaml(
                    f"{root}/oracles/{sequence:04d}-preapply-{vulnerability.id}.yaml",
                    {
                        "schema_version": 1,
                        "check_id": f"phase-c-{stage_number:04d}-preapply-{vulnerability.id}",
                        "status": "passed",
                        "vulnerable": observation.vulnerable,
                        "observation": observation.observation,
                    },
                )

            state = _advance(prepared.store, prepared.verified, state, RunState.PHASE_C_APPLY)
            unit_patches = tuple(patch for patch in prepared.patches if patch.unit_id == unit_id)
            if tuple(patch.patch_id for patch in unit_patches) != tuple(
                patch.id for patch in unit.patches
            ):
                raise MendRuneError(
                    "frozen patch order is incomplete", reason_code="actual_diff_mismatch"
                )
            for frozen in unit_patches:
                sequence += 1
                patch_path = prepared.store.path.joinpath(*frozen.effective_path.parts)
                patch_data = patch_path.read_bytes()
                if hashlib.sha256(patch_data).hexdigest() != frozen.effective_sha256:
                    raise MendRuneError(
                        "frozen patch integrity failed", reason_code="actual_diff_mismatch"
                    )
                before = worktree.diff()
                try:
                    placements = worktree.apply_patch(patch_path, config.patch_policy)
                except Exception as exc:
                    raise MendRuneError(
                        "cumulative patch failed", reason_code="cumulative_patch_failed"
                    ) from exc
                after = worktree.diff()
                if after == before:
                    raise MendRuneError(
                        "patch produced no actual diff", reason_code="actual_diff_mismatch"
                    )
                prepared.store.write_yaml(
                    f"{root}/patches/{sequence:04d}-{frozen.patch_id}.yaml",
                    {
                        "schema_version": 1,
                        "patch_id": frozen.patch_id,
                        "effective_sha256": frozen.effective_sha256,
                        "before_diff_sha256": hashlib.sha256(before).hexdigest(),
                        "actual_diff_sha256": hashlib.sha256(after).hexdigest(),
                        "placements": [
                            {
                                "path": item.path.as_posix(),
                                "original_start": item.original_start,
                                "applied_start": item.applied_start,
                                "old_count": item.old_count,
                                "new_count": item.new_count,
                            }
                            for item in placements
                        ],
                    },
                )
                _write_bytes_atomic(
                    prepared.store.path / f"{root}/diffs/{sequence:04d}-{frozen.patch_id}.diff",
                    after,
                )
            expected = worktree.snapshot()
            state = _advance(prepared.store, prepared.verified, state, RunState.PHASE_C_VERIFY)
            sequence += 1
            _run_isolated_command(
                prepared,
                execute,
                worktree,
                expected,
                root,
                sequence,
                "build",
                "build",
                config.commands.build.argv,
                config.commands.build.timeout_seconds,
                failure_code="cumulative_build_failed",
            )

            applied.append(unit_id)
            for applied_unit_id in applied:
                for vulnerability in units[applied_unit_id].vulnerabilities:
                    sequence += 1
                    nonce = secrets.token_hex(16)
                    reason = (
                        "current_vulnerability_not_mitigated"
                        if applied_unit_id == unit_id
                        else "prior_vulnerability_reopened"
                    )
                    try:
                        result, output = _run_isolated_command(
                            prepared,
                            execute,
                            worktree,
                            expected,
                            root,
                            sequence,
                            "oracle",
                            vulnerability.id,
                            vulnerability.oracle.argv,
                            vulnerability.oracle.timeout_seconds,
                            environment={"MENDRUNE_ORACLE_NONCE": nonce},
                            failure_code=reason,
                        )
                        observation = evaluate_oracle_result(
                            output,
                            _container_output_path(
                                output,
                                config.mounts.container_output_dir,
                                vulnerability.oracle.result_file,
                            ),
                            expected_nonce=nonce,
                            expected_vulnerable=False,
                            exit_code=result.exit_code if result.exit_code is not None else -1,
                            timed_out=result.timed_out,
                        )
                    except MendRuneError as exc:
                        if exc.reason_code == "actual_diff_mismatch":
                            raise
                        raise MendRuneError(
                            "cumulative vulnerability check failed", reason_code=reason
                        ) from exc
                    prepared.store.write_yaml(
                        f"{root}/oracles/{sequence:04d}-{vulnerability.id}.yaml",
                        {
                            "schema_version": 1,
                            "check_id": (
                                f"phase-c-{stage_number:04d}-{sequence:04d}"
                                f"-oracle-{vulnerability.id}"
                            ),
                            "status": "passed",
                            "vulnerable": observation.vulnerable,
                            "observation": observation.observation,
                        },
                    )

            for scheduled in select_accumulated_regressions(config, applied):
                sequence += 1
                command = scheduled.command
                result, _ = _run_isolated_command(
                    prepared,
                    execute,
                    worktree,
                    expected,
                    root,
                    sequence,
                    "regression",
                    command.id,
                    command.argv,
                    command.timeout_seconds,
                    failure_code="accumulated_regression_failed",
                )
                evaluated = evaluate_required_regression(
                    command.id,
                    exit_code=result.exit_code,
                    timed_out=result.timed_out,
                    failure_reason_code="accumulated_regression_failed",
                )
                if not evaluated.passed:
                    raise MendRuneError(
                        "accumulated regression failed",
                        reason_code=evaluated.reason_code or "accumulated_regression_failed",
                    )

            findings: list[Finding] = []
            for scan in config.commands.scans:
                sequence += 1
                _, output = _run_isolated_command(
                    prepared,
                    execute,
                    worktree,
                    expected,
                    root,
                    sequence,
                    "scanner",
                    scan.id,
                    scan.argv,
                    scan.timeout_seconds,
                    failure_code="scanner_failed",
                )
                if scan.normalizer != "semgrep":
                    raise MendRuneError(
                        "unknown scanner normalizer", reason_code="scanner_output_invalid"
                    )
                raw_path = _container_output_path(
                    output, config.mounts.container_output_dir, scan.raw_output
                )
                normalized = normalize_semgrep_json(
                    read_scanner_output(output, raw_path, config.execution.maximum_output_bytes),
                    scan.id,
                    config.scan_policy.severity_order,
                )
                findings.extend(normalized)
                prepared.store.write_yaml(
                    f"{root}/scans/{sequence:04d}-{scan.id}.yaml",
                    {
                        "schema_version": 1,
                        "check_id": f"{root.replace('/', '-')}-{sequence:04d}-scanner-{scan.id}",
                        "scanner_id": scan.id,
                        "status": "passed",
                        "findings": [_finding_record(item) for item in normalized],
                    },
                )
            normalized_findings = tuple(sorted(findings, key=lambda item: item.identity))
            delta = compare_findings(
                previous_findings,
                normalized_findings,
                severity_order=config.scan_policy.severity_order,
                threshold=config.scan_policy.reject_new_findings_at_or_above,
            )
            prepared.store.write_yaml(
                f"{root}/scan-comparison.yaml",
                {
                    "schema_version": 1,
                    "baseline": "phase-a" if stage_number == 1 else "previous-cumulative-stage",
                    "status": "passed" if delta.passed else "failed",
                    "prohibited": [_finding_record(item) for item in delta.prohibited],
                    "introduced": [_finding_record(item) for item in delta.introduced],
                    "severity_increases": [
                        _finding_record(item) for item in delta.severity_increases
                    ],
                },
            )
            if not delta.passed:
                raise MendRuneError(
                    "cumulative stage introduced prohibited finding",
                    reason_code="prohibited_new_finding",
                )
            worktree.verify_integrity(expected, config.execution.allowed_generated_paths)
            _write_unit_manifest(prepared.store, root)
            prepared.store.write_hash_manifest()
            previous_findings = normalized_findings
            results[unit_id] = normalized_findings
            if stage_number < len(config.composition.order):
                state = _advance(
                    prepared.store, prepared.verified, state, RunState.PHASE_C_PREAPPLY
                )
        state = _advance(prepared.store, prepared.verified, state, RunState.FINAL_VERIFICATION)
        _execute_final_verification(prepared, execute, worktree, expected, previous_findings, state)
        return results
    except Exception as exc:
        reason = exc.reason_code if isinstance(exc, MendRuneError) else "unexpected_exception"
        root = locals().get("root", "phase-c")
        prepared.store.write_yaml(
            f"{root}/failure.yaml",
            {"schema_version": 1, "status": "failed", "reason_code": reason},
        )
        target = (
            RunState.AMBIGUOUS_OVERLAP
            if reason == "unit_vulnerability_already_mitigated"
            else RunState.CUMULATIVE_FAILURE
        )
        _advance(prepared.store, prepared.verified, state, target)
        prepared.store.write_hash_manifest()
        if isinstance(exc, MendRuneError):
            raise
        raise MendRuneError("unexpected cumulative failure", reason_code=reason) from exc
    finally:
        if worktree is not None:
            try:
                worktree.remove()
            except Exception as cleanup_error:
                prepared.store.write_yaml(
                    "phase-c/cleanup-failure.yaml",
                    {"schema_version": 1, "status": "failed", "reason_code": "cleanup_uncertain"},
                )
                prepared.store.write_hash_manifest()
                if not config.storage.keep_failed_workspaces:
                    raise MendRuneError(
                        f"cumulative worktree cleanup failed: {cleanup_error}",
                        reason_code="cleanup_uncertain",
                    ) from cleanup_error


def _execute_final_verification(
    prepared: PreflightRun,
    execute: Executor,
    worktree: Worktree,
    expected: TreeSnapshot,
    previous_findings: tuple[Finding, ...],
    state: RunState,
) -> None:
    """Repeat the complete stack and persist evidence without accepting the run."""
    config = prepared.verified.config
    units = {unit.id: unit for unit in config.units}
    root = "final"
    sequence = 1

    # Establish that the final repetition starts from the exact accepted cumulative stage.
    worktree.verify_integrity(expected, config.execution.allowed_generated_paths)
    prepared.store.write_yaml(
        f"{root}/checks/0000-initial-integrity.yaml",
        {
            "schema_version": 1,
            "check_id": "final-0000-initial-integrity",
            "status": "passed",
        },
    )
    _run_isolated_command(
        prepared,
        execute,
        worktree,
        expected,
        root,
        sequence,
        "build",
        "build",
        config.commands.build.argv,
        config.commands.build.timeout_seconds,
        failure_code="final_build_failed",
    )
    for unit_id in config.composition.order:
        for vulnerability in units[unit_id].vulnerabilities:
            sequence += 1
            nonce = secrets.token_hex(16)
            result, output = _run_isolated_command(
                prepared,
                execute,
                worktree,
                expected,
                root,
                sequence,
                "oracle",
                vulnerability.id,
                vulnerability.oracle.argv,
                vulnerability.oracle.timeout_seconds,
                environment={"MENDRUNE_ORACLE_NONCE": nonce},
                failure_code="final_vulnerability_not_mitigated",
            )
            observation = evaluate_oracle_result(
                output,
                _container_output_path(
                    output,
                    config.mounts.container_output_dir,
                    vulnerability.oracle.result_file,
                ),
                expected_nonce=nonce,
                expected_vulnerable=False,
                exit_code=result.exit_code if result.exit_code is not None else -1,
                timed_out=result.timed_out,
            )
            prepared.store.write_yaml(
                f"{root}/oracles/{sequence:04d}-{vulnerability.id}.yaml",
                {
                    "schema_version": 1,
                    "check_id": f"final-{sequence:04d}-oracle-{vulnerability.id}",
                    "status": "passed",
                    "vulnerable": observation.vulnerable,
                    "observation": observation.observation,
                },
            )

    for scheduled in select_accumulated_regressions(config, config.composition.order):
        sequence += 1
        command = scheduled.command
        result, _ = _run_isolated_command(
            prepared,
            execute,
            worktree,
            expected,
            root,
            sequence,
            "regression",
            command.id,
            command.argv,
            command.timeout_seconds,
            failure_code="final_regression_failed",
        )
        evaluated = evaluate_required_regression(
            command.id,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            failure_reason_code="final_regression_failed",
        )
        if not evaluated.passed:
            raise MendRuneError(
                "final regression failed",
                reason_code=evaluated.reason_code or "final_regression_failed",
            )

    findings: list[Finding] = []
    for scan in config.commands.scans:
        sequence += 1
        _, output = _run_isolated_command(
            prepared,
            execute,
            worktree,
            expected,
            root,
            sequence,
            "scanner",
            scan.id,
            scan.argv,
            scan.timeout_seconds,
            failure_code="scanner_failed",
        )
        if scan.normalizer != "semgrep":
            raise MendRuneError("unknown scanner normalizer", reason_code="scanner_output_invalid")
        raw_path = _container_output_path(
            output, config.mounts.container_output_dir, scan.raw_output
        )
        normalized = normalize_semgrep_json(
            read_scanner_output(output, raw_path, config.execution.maximum_output_bytes),
            scan.id,
            config.scan_policy.severity_order,
        )
        findings.extend(normalized)
        prepared.store.write_yaml(
            f"{root}/scans/{sequence:04d}-{scan.id}.yaml",
            {
                "schema_version": 1,
                "check_id": f"final-{sequence:04d}-scanner-{scan.id}",
                "scanner_id": scan.id,
                "status": "passed",
                "findings": [_finding_record(item) for item in normalized],
            },
        )
    final_findings = tuple(sorted(findings, key=lambda item: item.identity))
    delta = compare_findings(
        previous_findings,
        final_findings,
        severity_order=config.scan_policy.severity_order,
        threshold=config.scan_policy.reject_new_findings_at_or_above,
    )
    prepared.store.write_yaml(
        f"{root}/scan-comparison.yaml",
        {
            "schema_version": 1,
            "baseline": "last-cumulative-stage",
            "status": "passed" if delta.passed else "failed",
            "prohibited": [_finding_record(item) for item in delta.prohibited],
            "introduced": [_finding_record(item) for item in delta.introduced],
            "severity_increases": [_finding_record(item) for item in delta.severity_increases],
        },
    )
    if not delta.passed:
        raise MendRuneError(
            "final scan introduced prohibited finding", reason_code="prohibited_new_finding"
        )

    worktree.verify_integrity(expected, config.execution.allowed_generated_paths)
    _remove_allowed_generated(worktree, expected, config.execution.allowed_generated_paths)
    worktree.verify_integrity(expected)
    prepared.store.write_yaml(
        f"{root}/checks/{sequence + 1:04d}-final-integrity.yaml",
        {
            "schema_version": 1,
            "check_id": f"final-{sequence + 1:04d}-final-integrity",
            "status": "passed",
        },
    )

    combined = worktree.diff()
    _write_bytes_atomic(prepared.store.path / f"{root}/combined.diff", combined)
    combined_sha256 = hashlib.sha256(combined).hexdigest()
    series = []
    patch_by_unit = {unit_id: [] for unit_id in config.composition.order}
    for patch in prepared.patches:
        patch_by_unit[patch.unit_id].append(patch)
    for unit_id in config.composition.order:
        for patch in patch_by_unit[unit_id]:
            supplied = prepared.store.path.joinpath(*patch.supplied_path.parts).read_bytes()
            effective = prepared.store.path.joinpath(*patch.effective_path.parts).read_bytes()
            if (
                hashlib.sha256(supplied).hexdigest() != patch.supplied_sha256
                or hashlib.sha256(effective).hexdigest() != patch.effective_sha256
            ):
                raise MendRuneError(
                    "frozen patch provenance is incomplete", reason_code="provenance_incomplete"
                )
            series.append(
                {
                    "sequence": len(series) + 1,
                    "unit_id": unit_id,
                    "patch_id": patch.patch_id,
                    "supplied_path": patch.supplied_path.as_posix(),
                    "supplied_sha256": patch.supplied_sha256,
                    "effective_kind": patch.effective_kind,
                    "effective_path": patch.effective_path.as_posix(),
                    "effective_sha256": patch.effective_sha256,
                }
            )
    prepared.store.write_yaml(
        f"{root}/supplied-series.yaml",
        {
            "schema_version": 1,
            "base_commit": prepared.verified.repository.base_commit,
            "composition_order": list(config.composition.order),
            "patches": series,
            "combined_diff": {"path": "combined.diff", "sha256": combined_sha256},
        },
    )
    _write_unit_manifest(prepared.store, root)
    prepared.store.write_hash_manifest()
    prepared.store.verify_hash_manifest()
    _advance(prepared.store, prepared.verified, state, RunState.ASSEMBLING_EVIDENCE)
    prepared.store.write_yaml(
        f"{root}/verdict-prep.yaml",
        {
            "schema_version": 1,
            "status": "ready",
            "acceptance_evaluated": False,
            "base_commit": prepared.verified.repository.base_commit,
            "units_verified": list(config.composition.order),
            "combined_diff_sha256": combined_sha256,
            "evidence_hashes_verified": True,
        },
    )
    _write_unit_manifest(prepared.store, root)
    prepared.store.write_hash_manifest()
    prepared.store.verify_hash_manifest()


def _remove_allowed_generated(
    worktree: Worktree, expected: TreeSnapshot, allowed: tuple[str, ...]
) -> None:
    tracked = {entry.path.as_posix() for entry in expected.tracked}
    for path in sorted(worktree.path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        relative = path.relative_to(worktree.path).as_posix()
        if relative == ".git" or relative in tracked:
            continue
        if path.is_file() and not path.is_symlink():
            if not any(matches_path(pattern, relative) for pattern in allowed):
                raise MendRuneError(
                    f"unexpected generated path: {relative}", reason_code="actual_diff_mismatch"
                )
            path.unlink()
        elif path.is_dir():
            with contextlib.suppress(OSError):
                path.rmdir()


def _verify_final_evidence(prepared: PreflightRun) -> None:
    """Require the exact successful evidence schedule from the frozen campaign."""
    config = prepared.verified.config
    units = {unit.id: unit for unit in config.units}
    expected: dict[str, dict[str, object]] = {}
    manifests = ["phase-a/manifest.yaml", "final/manifest.yaml"]

    def add(path: str, check_id: str, **mapping: object) -> None:
        expected[path] = {"schema_version": 1, "status": "passed", "check_id": check_id, **mapping}

    def command(root: str, sequence: int, kind: str, command_id: str) -> None:
        stem = f"{sequence:04d}-{kind}-{command_id}"
        check_id = f"{root.replace('/', '-')}-{stem}"
        add(f"{root}/checks/{stem}.yaml", check_id, kind=kind, command_id=command_id)
        add(f"{root}/checks/{stem}-integrity.yaml", f"{check_id}-integrity")

    sequence = 1
    command("phase-a", sequence, "build", "build")
    for scheduled in select_shared_regressions(config):
        sequence += 1
        command("phase-a", sequence, "regression", scheduled.command.id)
    for unit in config.units:
        for vulnerability in unit.vulnerabilities:
            sequence += 1
            command("phase-a", sequence, "oracle", vulnerability.id)
            add(
                f"phase-a/oracles/{sequence:04d}-{vulnerability.id}.yaml",
                f"phase-a-{sequence:04d}-oracle-{vulnerability.id}",
            )
    for scan in config.commands.scans:
        sequence += 1
        command("phase-a", sequence, "scanner", scan.id)
        add(
            f"phase-a/scans/{sequence:04d}-{scan.id}.yaml",
            f"phase-a-{sequence:04d}-scanner-{scan.id}",
            scanner_id=scan.id,
        )

    applied: list[str] = []
    for stage, unit_id in enumerate(config.composition.order, 1):
        unit = units[unit_id]
        root = f"phase-b/{unit_id}"
        manifests.append(f"{root}/manifest.yaml")
        sequence = len(unit.patches) + 1
        command(root, sequence, "build", "build")
        for vulnerability in unit.vulnerabilities:
            sequence += 1
            command(root, sequence, "oracle", vulnerability.id)
            add(
                f"{root}/oracles/{sequence:04d}-{vulnerability.id}.yaml",
                f"phase-b-{unit_id}-{sequence:04d}-oracle-{vulnerability.id}",
            )
        for scheduled in select_unit_regressions(config, unit_id):
            sequence += 1
            command(root, sequence, "regression", scheduled.command.id)
        for scan in config.commands.scans:
            sequence += 1
            command(root, sequence, "scanner", scan.id)
            add(
                f"{root}/scans/{sequence:04d}-{scan.id}.yaml",
                f"phase-b-{unit_id}-{sequence:04d}-scanner-{scan.id}",
                scanner_id=scan.id,
            )

        root = f"phase-c/stages/{stage:04d}-{unit_id}"
        manifests.append(f"{root}/manifest.yaml")
        sequence = 0
        for vulnerability in unit.vulnerabilities:
            sequence += 1
            command(root, sequence, "preapply-oracle", vulnerability.id)
            add(
                f"{root}/oracles/{sequence:04d}-preapply-{vulnerability.id}.yaml",
                f"phase-c-{stage:04d}-preapply-{vulnerability.id}",
            )
        sequence += len(unit.patches) + 1
        command(root, sequence, "build", "build")
        applied.append(unit_id)
        for prior_id in applied:
            for vulnerability in units[prior_id].vulnerabilities:
                sequence += 1
                command(root, sequence, "oracle", vulnerability.id)
                add(
                    f"{root}/oracles/{sequence:04d}-{vulnerability.id}.yaml",
                    f"phase-c-{stage:04d}-{sequence:04d}-oracle-{vulnerability.id}",
                )
        for scheduled in select_accumulated_regressions(config, applied):
            sequence += 1
            command(root, sequence, "regression", scheduled.command.id)
        for scan in config.commands.scans:
            sequence += 1
            command(root, sequence, "scanner", scan.id)
            add(
                f"{root}/scans/{sequence:04d}-{scan.id}.yaml",
                f"{root.replace('/', '-')}-{sequence:04d}-scanner-{scan.id}",
                scanner_id=scan.id,
            )

    add("final/checks/0000-initial-integrity.yaml", "final-0000-initial-integrity")
    sequence = 1
    command("final", sequence, "build", "build")
    for unit_id in config.composition.order:
        for vulnerability in units[unit_id].vulnerabilities:
            sequence += 1
            command("final", sequence, "oracle", vulnerability.id)
            add(
                f"final/oracles/{sequence:04d}-{vulnerability.id}.yaml",
                f"final-{sequence:04d}-oracle-{vulnerability.id}",
            )
    for scheduled in select_accumulated_regressions(config, config.composition.order):
        sequence += 1
        command("final", sequence, "regression", scheduled.command.id)
    for scan in config.commands.scans:
        sequence += 1
        command("final", sequence, "scanner", scan.id)
        add(
            f"final/scans/{sequence:04d}-{scan.id}.yaml",
            f"final-{sequence:04d}-scanner-{scan.id}",
            scanner_id=scan.id,
        )
    add(
        f"final/checks/{sequence + 1:04d}-final-integrity.yaml",
        f"final-{sequence + 1:04d}-final-integrity",
    )

    try:
        required = [
            "input/campaign.yaml",
            "input/repository.yaml",
            "input/patches.yaml",
            "input/evidence-manifest.yaml",
            "final/combined.diff",
            "final/supplied-series.yaml",
            "final/scan-comparison.yaml",
            *manifests,
        ]
        for relative in required:
            prepared.store.artifact(relative)
        actual = {
            path.relative_to(prepared.store.path).as_posix()
            for pattern in ("**/checks/*.yaml", "**/oracles/*.yaml", "**/scans/*.yaml")
            for path in prepared.store.path.glob(pattern)
        }
        if actual != set(expected):
            raise ValueError("evidence record set differs from frozen schedule")
        for relative, mapping in expected.items():
            document = yaml.safe_load((prepared.store.path / relative).read_text())
            if not isinstance(document, dict) or any(
                document.get(k) != v for k, v in mapping.items()
            ):
                raise ValueError(f"invalid required record: {relative}")
        comparisons = [f"phase-b/{u}/scan-comparison.yaml" for u in config.composition.order]
        comparisons += [
            f"phase-c/stages/{i:04d}-{u}/scan-comparison.yaml"
            for i, u in enumerate(config.composition.order, 1)
        ]
        comparisons.append("final/scan-comparison.yaml")
        for relative in comparisons:
            if (
                yaml.safe_load((prepared.store.path / relative).read_text()).get("status")
                != "passed"
            ):
                raise ValueError(f"nonpassing comparison: {relative}")
        for relative in manifests:
            path = prepared.store.path / relative
            document = yaml.safe_load(path.read_text())
            files = document.get("files") if isinstance(document, dict) else None
            if (
                document.get("schema_version") != 1
                or document.get("algorithm") != "sha256"
                or not isinstance(files, list)
            ):
                raise ValueError(f"invalid manifest: {relative}")
            mapped = [item.get("path") for item in files if isinstance(item, dict)]
            actual_files = sorted(
                x.relative_to(path.parent).as_posix()
                for x in path.parent.rglob("*")
                if x.is_file() and x.name != "manifest.yaml"
            )
            if sorted(mapped) != actual_files or len(mapped) != len(set(mapped)):
                raise ValueError(f"incomplete manifest: {relative}")
            for item in files:
                artifact = prepared.store.artifact(
                    (path.parent / item["path"]).relative_to(prepared.store.path).as_posix()
                )
                if (item.get("size"), item.get("sha256")) != (artifact.size, artifact.sha256):
                    raise ValueError(f"invalid manifest mapping: {relative}")
    except Exception as exc:
        raise MendRuneError(
            "required campaign evidence is missing or invalid", reason_code="required_check_missing"
        ) from exc


def _run_isolated_command(
    prepared: PreflightRun,
    execute: Executor,
    worktree: Worktree,
    snapshot: TreeSnapshot,
    root: str,
    sequence: int,
    kind: str,
    command_id: str,
    argv: tuple[str, ...],
    timeout_seconds: int,
    *,
    failure_code: str,
    environment: dict[str, str] | None = None,
) -> tuple[executor.ExecutionResult, Path]:
    config = prepared.verified.config
    stem = f"{sequence:04d}-{kind}-{command_id}"
    output = prepared.store.path / root / "outputs" / stem
    scratch = prepared._workspace_parent / "scratch" / root.replace("/", "-") / stem
    output.mkdir(parents=True, mode=0o700)
    scratch.mkdir(parents=True, mode=0o700)
    invocation = executor.Invocation(
        image=config.execution.image,
        argv=argv,
        mounts=(
            executor.Mount(worktree.path, config.execution.container_workdir, False),
            executor.Mount(
                prepared.store.path / "input/evidence", config.mounts.container_evidence_dir, True
            ),
            executor.Mount(
                output,
                config.mounts.container_output_dir,
                False,
                tmpfs_limit_bytes=config.execution.maximum_output_bytes,
                capture_to_source=True,
            ),
            executor.Mount(
                scratch,
                "/tmp",
                False,
                tmpfs_limit_bytes=config.execution.maximum_output_bytes,
            ),
        ),
        environment={**config.execution.environment, **(environment or {})},
        timeout_seconds=timeout_seconds,
    )
    result: executor.ExecutionResult | None = None
    try:
        result = execute(config.execution, invocation)
        _write_bytes_atomic(
            prepared.store.path / root / "logs" / f"{stem}.stdout", result.stdout.data
        )
        _write_bytes_atomic(
            prepared.store.path / root / "logs" / f"{stem}.stderr", result.stderr.data
        )
        prepared.store.write_yaml(
            f"{root}/checks/{stem}.yaml",
            {
                "schema_version": 1,
                "check_id": f"{root.replace('/', '-')}-{stem}",
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
        if result.timed_out or result.exit_code != 0:
            raise MendRuneError(f"isolated {kind} failed", reason_code=failure_code)
        return result, output
    finally:
        try:
            worktree.verify_integrity(snapshot, config.execution.allowed_generated_paths)
        except Exception as integrity_error:
            prepared.store.write_yaml(
                f"{root}/checks/{stem}-integrity.yaml",
                {
                    "schema_version": 1,
                    "check_id": f"{root.replace('/', '-')}-{stem}-integrity",
                    "status": "failed",
                    "reason_code": "actual_diff_mismatch",
                },
            )
            raise integrity_error
        else:
            prepared.store.write_yaml(
                f"{root}/checks/{stem}-integrity.yaml",
                {
                    "schema_version": 1,
                    "check_id": f"{root.replace('/', '-')}-{stem}-integrity",
                    "status": "passed",
                },
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


def _write_unit_manifest(store: RunStore, root: str) -> None:
    base = store.path / root
    records = []
    for path in sorted(base.rglob("*"), key=lambda item: item.as_posix().encode()):
        if path.is_file() and path.name != "manifest.yaml":
            artifact = store.artifact(path.relative_to(store.path).as_posix())
            records.append(
                {
                    "path": path.relative_to(base).as_posix(),
                    "size": artifact.size,
                    "sha256": artifact.sha256,
                }
            )
    store.write_yaml(
        f"{root}/manifest.yaml", {"schema_version": 1, "algorithm": "sha256", "files": records}
    )


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
            executor.Mount(
                output,
                config.mounts.container_output_dir,
                False,
                tmpfs_limit_bytes=config.execution.maximum_output_bytes,
                capture_to_source=True,
            ),
            executor.Mount(
                scratch,
                "/tmp",
                False,
                tmpfs_limit_bytes=config.execution.maximum_output_bytes,
            ),
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


def run_campaign(
    campaign_path: Path,
    *,
    run_id: str | None = None,
    execute: Executor = executor.execute,
) -> dict[str, object]:
    """Execute the complete campaign and return its persisted accepted verdict."""
    prepared: PreflightRun | None = None
    try:
        prepared = prepare_preflight(campaign_path, run_id=run_id)
        phase_a = execute_phase_a(prepared, execute=execute)
        execute_phase_b(prepared, phase_a, execute=execute)
        execute_phase_c(prepared, phase_a, execute=execute)
        # Cleanup is acceptance-relevant: an uncertain workspace must never be accepted.
        prepared.close()
        return _accept_campaign(prepared)
    except Exception as exc:
        failure: Exception = exc
        if prepared is not None:
            if not prepared._closed:
                try:
                    prepared.close()
                except Exception as cleanup_error:
                    failure = cleanup_error
            _persist_terminal_failure(prepared, failure)
        if failure is exc and isinstance(exc, MendRuneError):
            raise
        if isinstance(failure, MendRuneError):
            raise failure from exc
        raise MendRuneError(
            "unexpected campaign failure", reason_code="unexpected_exception"
        ) from failure


def _accept_campaign(prepared: PreflightRun) -> dict[str, object]:
    """Evaluate the fail-closed acceptance conjunction from assembled evidence."""
    store = prepared.store
    try:
        run = yaml.safe_load(store.artifact("run.yaml").path.read_text(encoding="utf-8"))
        if not isinstance(run, dict) or run.get("state") != RunState.ASSEMBLING_EVIDENCE.value:
            raise MendRuneError(
                "acceptance requires assembled evidence", reason_code="required_check_missing"
            )
        _verify_final_evidence(prepared)
        store.verify_hash_manifest()

        series = yaml.safe_load(
            store.artifact("final/supplied-series.yaml").path.read_text(encoding="utf-8")
        )
        if not isinstance(series, dict) or not isinstance(series.get("combined_diff"), dict):
            raise MendRuneError(
                "final provenance is incomplete", reason_code="provenance_incomplete"
            )
        combined = store.artifact("final/combined.diff")
        if (
            series["combined_diff"].get("path") != "combined.diff"
            or series["combined_diff"].get("sha256") != combined.sha256
        ):
            raise MendRuneError(
                "final combined diff does not match", reason_code="combined_diff_mismatch"
            )

        patches = series.get("patches")
        if not isinstance(patches, list) or len(patches) != len(prepared.patches):
            raise MendRuneError(
                "patch provenance is incomplete", reason_code="provenance_incomplete"
            )
        for item in patches:
            if not isinstance(item, dict):
                raise MendRuneError(
                    "patch provenance is incomplete", reason_code="provenance_incomplete"
                )
            for path_key, hash_key in (
                ("supplied_path", "supplied_sha256"),
                ("effective_path", "effective_sha256"),
            ):
                path = item.get(path_key)
                digest = item.get(hash_key)
                if not isinstance(path, str) or not isinstance(digest, str):
                    raise MendRuneError(
                        "patch provenance is incomplete", reason_code="provenance_incomplete"
                    )
                if store.artifact(path).sha256 != digest:
                    raise MendRuneError(
                        "patch provenance hash does not match", reason_code="provenance_incomplete"
                    )

        verdict: dict[str, object] = {
            "schema_version": 1,
            "run_id": store.run_id,
            "outcome": "accepted",
            "reason_code": "all_required_checks_passed",
            "base_commit": prepared.verified.repository.base_commit,
            "units_verified": list(prepared.verified.config.composition.order),
            "limitations": list(LIMITATIONS),
        }
        store.write_yaml("final/verdict.yaml", verdict)
        store.write_yaml(
            "final/report.yaml",
            {
                "schema_version": 1,
                "run_id": store.run_id,
                "outcome": "accepted",
                "reason_code": "all_required_checks_passed",
                "verdict": verdict,
                "limitations": list(LIMITATIONS),
            },
        )
        _advance(store, prepared.verified, RunState.ASSEMBLING_EVIDENCE, RunState.ACCEPTED)
        accepted = yaml.safe_load(store.artifact("run.yaml").path.read_text(encoding="utf-8"))
        accepted["outcome"] = "accepted"
        accepted["reason_code"] = "all_required_checks_passed"
        store.write_yaml("run.yaml", accepted)
        store.write_hash_manifest()
        store.verify_hash_manifest()
        return verdict
    except Exception as exc:
        reason = exc.reason_code if isinstance(exc, MendRuneError) else "provenance_incomplete"
        # Acceptance failures are evidence failures and cannot leave a partial verdict.
        (store.path / "final/verdict.yaml").unlink(missing_ok=True)
        (store.path / "final/report.yaml").unlink(missing_ok=True)
        _persist_failure_record(prepared, RunState.EVIDENCE_FAILURE, reason)
        store.write_hash_manifest()
        if isinstance(exc, MendRuneError):
            raise
        raise MendRuneError("acceptance evidence is invalid", reason_code=reason) from exc


def _persist_terminal_failure(prepared: PreflightRun, exc: Exception) -> None:
    reason = exc.reason_code if isinstance(exc, MendRuneError) else "unexpected_exception"
    infrastructure = {
        "rootless_required",
        "podman_unavailable",
        "runtime_unavailable",
        "runtime_unqualified",
        "image_digest_mismatch",
        "isolation_control_unavailable",
        "container_launch_failed",
        "cleanup_uncertain",
    }
    internal = {
        "illegal_state_transition",
        "unexpected_exception",
        "unexpected_internal_error",
        "atomic_write_failed",
    }
    current = yaml.safe_load(prepared.store.artifact("run.yaml").path.read_text(encoding="utf-8"))
    state_value = current.get("state") if isinstance(current, dict) else None
    terminal = {state.value for state in RunState if state.value.endswith("failure")} | {
        RunState.CONFIGURATION_ERROR.value,
        RunState.AMBIGUOUS_OVERLAP.value,
        RunState.INFRASTRUCTURE_ERROR.value,
        RunState.INTERNAL_ERROR.value,
    }
    if state_value in terminal:
        target = RunState(state_value)
    elif reason in infrastructure:
        target = RunState.INFRASTRUCTURE_ERROR
    elif reason in internal:
        target = RunState.INTERNAL_ERROR
    else:
        target = RunState.EVIDENCE_FAILURE
    _persist_failure_record(prepared, target, reason)
    prepared.store.write_hash_manifest()


def _persist_failure_record(prepared: PreflightRun, state: RunState, reason: str) -> None:
    _persist_state(prepared.store, prepared.verified, state)
    document = yaml.safe_load(prepared.store.artifact("run.yaml").path.read_text(encoding="utf-8"))
    document["outcome"] = state.value
    document["reason_code"] = reason
    prepared.store.write_yaml("run.yaml", document)


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
                        **(
                            {
                                "derived_from_sha256": item.derived_from_sha256,
                                "recipe_sha256": item.recipe_sha256,
                                "accepted_by": "deterministic_campaign_verifier",
                            }
                            if item.effective_kind == "goose_adapted"
                            else {}
                        ),
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
        sequence = sequence_by_unit.get(patch.unit_id, 0) + 1
        sequence_by_unit[patch.unit_id] = sequence
        data = _read_verified_patch(patch)
        relative = PurePosixPath("input", "patches", patch.unit_id, f"{sequence:02d}-supplied.diff")
        destination = store.path.joinpath(*relative.parts)
        _write_bytes_atomic(destination, data)
        if configured.adapt_with_goose:
            frozen.append(_capture_adaptation(store, verified, patch, relative, data))
        else:
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
        destination.chmod(0o400)
    return tuple(frozen)


def _capture_adaptation(
    store: RunStore,
    verified: VerifiedCampaign,
    patch: VerifiedPatch,
    supplied_path: PurePosixPath,
    supplied: bytes,
) -> FrozenPatch:
    config = verified.config.goose
    assert config.enabled and verified.goose_recipe is not None
    assert verified.goose_recipe_sha256 is not None
    recipe_bytes = verified.goose_recipe.read_bytes()
    if hashlib.sha256(recipe_bytes).hexdigest() != verified.goose_recipe_sha256:
        raise MendRuneError(
            "Goose recipe changed after validation", reason_code="input_capture_race"
        )
    frozen_recipe = store.path / "input/recipes/adapt-patch.yaml"
    if not frozen_recipe.exists():
        _write_bytes_atomic(frozen_recipe, recipe_bytes)
        frozen_recipe.chmod(0o400)
    recipe = frozen_recipe
    recipe_sha256 = verified.goose_recipe_sha256
    parsed_supplied = parse_patch(supplied, verified.config.patch_policy)
    workspace_parent = store.path / ".adaptation-workspaces"
    with Worktree.create(verified.repository, workspace_parent) as worktree:
        contexts: list[bytes] = []
        for changed_file in parsed_supplied.files:
            path = changed_file.old_path or changed_file.new_path
            assert path is not None
            source = worktree.path.joinpath(*path.parts)
            if source.is_file() and not source.is_symlink():
                contexts.append(f"\n--- {path.as_posix()} ---\n".encode() + source.read_bytes())
        evidence = (
            store.path / "adaptations" / patch.unit_id / patch.patch_id / "evidence-bundle.md"
        )
        write_evidence_bundle(
            evidence,
            unit_id=patch.unit_id,
            patch_id=patch.patch_id,
            supplied_patch=supplied,
            supplied_sha256=patch.sha256,
            policy=verified.config.patch_policy,
            source_context=b"".join(contexts),
            application_diagnostic="adaptation explicitly requested by campaign",
            maximum_bytes=config.maximum_bundle_bytes,
        )
        adapted = adapt_patch(
            recipe,
            evidence,
            maximum_response_bytes=config.maximum_response_bytes,
            timeout_seconds=config.timeout_seconds,
        )
        adapted_relative = PurePosixPath(
            "adaptations", patch.unit_id, patch.patch_id, "adapted.diff"
        )
        adapted_path = store.path.joinpath(*adapted_relative.parts)
        _write_bytes_atomic(adapted_path, adapted)
        try:
            parse_patch(adapted, verified.config.patch_policy)
            worktree.apply_patch(adapted_path, verified.config.patch_policy)
        except Exception as exc:
            raise MendRuneError(
                f"Goose adapted patch failed deterministic validation: {exc}",
                reason_code="goose_adaptation_failed",
            ) from exc
        adapted_path.chmod(0o400)
    shutil.rmtree(workspace_parent, ignore_errors=True)
    return FrozenPatch(
        unit_id=patch.unit_id,
        patch_id=patch.patch_id,
        supplied_path=supplied_path,
        supplied_sha256=patch.sha256,
        effective_path=adapted_relative,
        effective_sha256=hashlib.sha256(adapted).hexdigest(),
        effective_kind="goose_adapted",
        derived_from_sha256=patch.sha256,
        recipe_sha256=recipe_sha256,
    )


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
