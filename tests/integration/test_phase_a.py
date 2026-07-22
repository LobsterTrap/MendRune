from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from mendrune.errors import MendRuneError
from mendrune.executor import CapturedOutput, ExecutionResult
from mendrune.orchestrator import PreflightRun, execute_phase_a, prepare_preflight
from tests.integration.test_verify_cli import create_campaign


@pytest.fixture
def phase_a_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[PreflightRun]:
    campaign = create_campaign(tmp_path)
    monkeypatch.setattr("mendrune.orchestrator.executor.preflight", lambda config: None)
    prepared = prepare_preflight(campaign, run_id="phase-a-integration")
    yield prepared
    prepared.close()


def _result(invocation, *, exit_code: int = 0) -> ExecutionResult:
    empty = CapturedOutput(b"", 0, False)
    return ExecutionResult(
        invocation.argv,
        exit_code,
        False,
        datetime(2026, 1, 1, tzinfo=UTC),
        1,
        "container",
        invocation.image,
        "crun-krun",
        empty,
        empty,
    )


class FakeExecutor:
    def __init__(self, failure: str | None = None) -> None:
        self.failure = failure
        self.calls = []

    def __call__(self, config, invocation) -> ExecutionResult:
        self.calls.append(invocation)
        sequence = len(self.calls)
        output = next(mount.source for mount in invocation.mounts if mount.destination == "/output")

        if self.failure == "source_mutation" and sequence == 1:
            workspace = next(
                mount.source for mount in invocation.mounts if mount.destination == "/workspace"
            )
            (workspace / "file.txt").write_text("mutated by command\n")
        if sequence == 3:
            nonce = invocation.environment["MENDRUNE_ORACLE_NONCE"]
            vulnerable = self.failure != "non_reproducing_oracle"
            (output / "oracle.yaml").write_text(
                "schema_version: 1\n"
                f"nonce: {nonce}\n"
                f"vulnerable: {str(vulnerable).lower()}\n"
                "observation: integration fixture\n"
            )
        if sequence == 4 and self.failure != "scanner_failure":
            (output / "scan.json").write_text('{"version":"1","results":[],"errors":[],"paths":{}}')

        exit_code = (
            1
            if (
                (self.failure == "regression_failure" and sequence == 2)
                or (self.failure == "scanner_failure" and sequence == 4)
            )
            else 0
        )
        return _result(invocation, exit_code=exit_code)


def test_phase_a_valid_baseline_persists_evidence(phase_a_run: PreflightRun) -> None:
    execute = FakeExecutor()

    assert execute_phase_a(phase_a_run, execute=execute) == ()
    assert [invocation.argv for invocation in execute.calls] == [
        ("python", "-m", "build"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
    ]

    run = phase_a_run.store.path
    assert yaml.safe_load((run / "run.yaml").read_text())["state"] == "phase_a_baseline"
    assert len(list((run / "phase-a/checks").glob("*.yaml"))) == 8
    oracle = yaml.safe_load(next((run / "phase-a/oracles").glob("*.yaml")).read_text())
    scan = yaml.safe_load(next((run / "phase-a/scans").glob("*.yaml")).read_text())
    assert oracle["status"] == "passed"
    assert oracle["vulnerable"] is True
    assert scan["findings"] == []
    phase_a_run.store.verify_hash_manifest()


@pytest.mark.parametrize(
    ("failure", "reason_code"),
    [
        ("non_reproducing_oracle", "vulnerability_not_reproduced"),
        ("source_mutation", "actual_diff_mismatch"),
        ("scanner_failure", "scanner_failed"),
        ("regression_failure", "regression_failed"),
    ],
)
def test_phase_a_failure_matrix_persists_stable_terminal_codes(
    phase_a_run: PreflightRun, failure: str, reason_code: str
) -> None:
    with pytest.raises(MendRuneError) as raised:
        execute_phase_a(phase_a_run, execute=FakeExecutor(failure))

    assert raised.value.reason_code == reason_code
    run = phase_a_run.store.path
    state = yaml.safe_load((run / "run.yaml").read_text())
    failure_record = yaml.safe_load((run / "phase-a/failure.yaml").read_text())
    assert state["state"] == "baseline_failure"
    assert failure_record == {
        "schema_version": 1,
        "status": "failed",
        "reason_code": reason_code,
    }
    phase_a_run.store.verify_hash_manifest()
