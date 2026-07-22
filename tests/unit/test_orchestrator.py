import hashlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from mendrune.errors import MendRuneError
from mendrune.executor import CapturedOutput, ExecutionResult
from mendrune.orchestrator import execute_phase_a, execute_phase_b, prepare_preflight
from tests.integration.test_verify_cli import create_campaign


def _prepare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    campaign = create_campaign(tmp_path)
    repository = Path(yaml.safe_load(campaign.read_text())["repository"]["path"])
    (repository / "src").mkdir()
    (repository / "src/a.py").write_text("old\n")
    subprocess.run(["git", "-C", repository, "add", "src/a.py"], check=True)
    subprocess.run(["git", "-C", repository, "commit", "-qm", "fixture source"], check=True)
    monkeypatch.setattr("mendrune.orchestrator.executor.preflight", lambda config: None)
    return campaign, prepare_preflight(campaign, run_id="run-1")


def test_preflight_captures_frozen_inputs_and_creates_clean_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, prepared = _prepare(tmp_path, monkeypatch)
    supplied = campaign.parent / "patches/a.diff"

    assert prepared.baseline.status() == ""
    assert prepared.baseline.path.exists()
    assert prepared.patches[0].effective_kind == "supplied"
    assert prepared.patches[0].effective_path == prepared.patches[0].supplied_path

    captured_patch = prepared.store.path / prepared.patches[0].supplied_path
    assert captured_patch.read_bytes() == supplied.read_bytes()
    assert prepared.patches[0].effective_sha256 == hashlib.sha256(supplied.read_bytes()).hexdigest()
    assert (prepared.store.path / "input/evidence/check.py").read_text() == "print('check')\n"
    assert (prepared.store.path / "input/campaign.yaml").read_bytes() == campaign.read_bytes()

    repository = yaml.safe_load((prepared.store.path / "input/repository.yaml").read_text())
    assert repository["base_commit"] == prepared.verified.repository.base_commit
    patches = yaml.safe_load((prepared.store.path / "input/patches.yaml").read_text())
    assert patches["patches"][0]["effective"]["kind"] == "supplied"
    state = yaml.safe_load((prepared.store.path / "run.yaml").read_text())
    assert state["state"] == "phase_a_baseline"
    prepared.store.verify_hash_manifest()

    baseline_path = prepared.baseline.path
    workspace_parent = prepared._workspace_parent
    prepared.close()
    assert not baseline_path.exists()
    assert not workspace_parent.exists()


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


def test_phase_a_executes_schedule_and_persists_normalized_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, prepared = _prepare(tmp_path, monkeypatch)
    calls = []

    def execute(config, invocation):
        calls.append(invocation)
        output = next(mount.source for mount in invocation.mounts if mount.destination == "/output")
        if "MENDRUNE_ORACLE_NONCE" in invocation.environment:
            nonce = invocation.environment["MENDRUNE_ORACLE_NONCE"]
            (output / "oracle.yaml").write_text(
                f"schema_version: 1\nnonce: {nonce}\nvulnerable: true\nobservation: reproduced\n"
            )
        elif len(calls) == 4:
            (output / "scan.json").write_text('{"version":"1","results":[],"errors":[],"paths":{}}')
        return _result(invocation)

    assert execute_phase_a(prepared, execute=execute) == ()
    assert [call.argv for call in calls] == [
        ("python", "-m", "build"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
    ]
    assert len(list((prepared.store.path / "phase-a/checks").glob("*.yaml"))) == 8
    assert (
        yaml.safe_load(next((prepared.store.path / "phase-a/oracles").glob("*.yaml")).read_text())[
            "vulnerable"
        ]
        is True
    )
    assert (
        yaml.safe_load(next((prepared.store.path / "phase-a/scans").glob("*.yaml")).read_text())[
            "findings"
        ]
        == []
    )
    prepared.store.verify_hash_manifest()
    prepared.close()


def test_phase_b_applies_unit_in_fresh_worktree_and_persists_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, prepared = _prepare(tmp_path, monkeypatch)
    baseline_path = prepared.baseline.path
    created_paths = []
    from mendrune.repository import Worktree

    original_create = Worktree.create

    def create(*args, **kwargs):
        worktree = original_create(*args, **kwargs)
        created_paths.append(worktree.path)
        return worktree

    monkeypatch.setattr("mendrune.orchestrator.Worktree.create", create)
    calls = []

    def execute(config, invocation):
        calls.append(invocation)
        output = next(mount.source for mount in invocation.mounts if mount.destination == "/output")
        if "MENDRUNE_ORACLE_NONCE" in invocation.environment:
            nonce = invocation.environment["MENDRUNE_ORACLE_NONCE"]
            (output / "oracle.yaml").write_text(
                f"schema_version: 1\nnonce: {nonce}\nvulnerable: false\nobservation: mitigated\n"
            )
        elif len(calls) == 5:
            (output / "scan.json").write_text('{"version":"1","results":[],"errors":[],"paths":{}}')
        return _result(invocation)

    assert execute_phase_b(prepared, (), execute=execute) == {"fix-a": ()}
    assert created_paths and created_paths[0] != baseline_path
    assert not created_paths[0].exists()
    assert [call.argv for call in calls] == [
        ("python", "-m", "build"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
    ]
    patch_record = yaml.safe_load(
        next((prepared.store.path / "phase-b/fix-a/patches").glob("*.yaml")).read_text()
    )
    assert patch_record["placements"][0]["path"] == "src/a.py"
    assert (prepared.store.path / "phase-b/fix-a/manifest.yaml").is_file()
    prepared.store.verify_hash_manifest()
    prepared.close()


def test_phase_b_partial_mitigation_has_stable_failure_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, prepared = _prepare(tmp_path, monkeypatch)
    worktree_paths = []
    from mendrune.repository import Worktree

    original_create = Worktree.create

    def create(*args, **kwargs):
        worktree = original_create(*args, **kwargs)
        worktree_paths.append(worktree.path)
        return worktree

    monkeypatch.setattr("mendrune.orchestrator.Worktree.create", create)

    def execute(config, invocation):
        output = next(mount.source for mount in invocation.mounts if mount.destination == "/output")
        if "MENDRUNE_ORACLE_NONCE" in invocation.environment:
            nonce = invocation.environment["MENDRUNE_ORACLE_NONCE"]
            (output / "oracle.yaml").write_text(
                f"schema_version: 1\nnonce: {nonce}\nvulnerable: true\n"
                "observation: still vulnerable\n"
            )
        return _result(invocation)

    with pytest.raises(MendRuneError) as raised:
        execute_phase_b(prepared, (), execute=execute)

    assert raised.value.reason_code == "unit_vulnerability_not_mitigated"
    assert not worktree_paths[0].exists()
    assert (
        yaml.safe_load((prepared.store.path / "run.yaml").read_text())["state"]
        == "isolated_unit_failure"
    )
    failure = yaml.safe_load((prepared.store.path / "phase-b/fix-a/failure.yaml").read_text())
    assert failure["reason_code"] == "unit_vulnerability_not_mitigated"
    prepared.close()


def test_phase_a_mutation_fails_closed_and_persists_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, prepared = _prepare(tmp_path, monkeypatch)

    def mutate(config, invocation):
        (prepared.baseline.path / "file.txt").write_text("mutated\n")
        return _result(invocation)

    with pytest.raises(MendRuneError) as raised:
        execute_phase_a(prepared, execute=mutate)

    assert raised.value.reason_code == "actual_diff_mismatch"
    assert (
        yaml.safe_load((prepared.store.path / "run.yaml").read_text())["state"]
        == "baseline_failure"
    )
    failure = yaml.safe_load((prepared.store.path / "phase-a/failure.yaml").read_text())
    assert failure["reason_code"] == "actual_diff_mismatch"
    prepared.close()


def test_adaptation_disabled_never_invokes_goose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "mendrune.goose.validate_recipe",
        lambda *args, **kwargs: pytest.fail("Goose must not be invoked"),
    )
    _, prepared = _prepare(tmp_path, monkeypatch)
    prepared.close()


def test_executor_failure_is_persisted_and_no_worktree_is_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = create_campaign(tmp_path)

    def reject(config) -> None:
        raise MendRuneError("unqualified", reason_code="runtime_unqualified")

    monkeypatch.setattr("mendrune.orchestrator.executor.preflight", reject)
    worktree_called = False

    def create_worktree(*args, **kwargs):
        nonlocal worktree_called
        worktree_called = True

    monkeypatch.setattr("mendrune.orchestrator.Worktree.create", create_worktree)

    with pytest.raises(MendRuneError, match="unqualified"):
        prepare_preflight(campaign, run_id="run-1")

    run = tmp_path / "runs/run-1"
    assert yaml.safe_load((run / "run.yaml").read_text())["state"] == "infrastructure_error"
    assert not (run / "input/evidence").exists()
    assert worktree_called is False


def test_patch_capture_race_fails_before_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = create_campaign(tmp_path)
    monkeypatch.setattr("mendrune.orchestrator.executor.preflight", lambda config: None)
    from mendrune import orchestrator

    original_verify = orchestrator.verify_campaign

    def verify_then_tamper(path: Path):
        verified = original_verify(path)
        verified.patches[0].path.write_bytes(verified.patches[0].path.read_bytes() + b"tampered")
        return verified

    monkeypatch.setattr("mendrune.orchestrator.verify_campaign", verify_then_tamper)

    with pytest.raises(MendRuneError) as raised:
        prepare_preflight(campaign, run_id="run-1")

    assert raised.value.reason_code == "input_capture_race"
    assert not any((tmp_path / "runs/.workspaces").glob("**/mendrune-worktree-*"))
