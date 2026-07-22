import hashlib
import subprocess
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from mendrune.errors import MendRuneError
from mendrune.executor import CapturedOutput, ExecutionResult
from mendrune.orchestrator import (
    execute_phase_a,
    execute_phase_b,
    execute_phase_c,
    prepare_preflight,
    run_campaign,
)
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


def test_phase_c_strict_preapply_and_accumulated_checks_use_one_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, prepared = _prepare(tmp_path, monkeypatch)
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
            vulnerable = invocation.argv == ("python", "/evidence/check.py") and len(calls) == 1
            (output / "oracle.yaml").write_text(
                f"schema_version: 1\nnonce: {nonce}\nvulnerable: "
                f"{'true' if vulnerable else 'false'}\nobservation: checked\n"
            )
        elif invocation.argv == ("python", "/evidence/check.py"):
            (output / "scan.json").write_text('{"version":"1","results":[],"errors":[],"paths":{}}')
        return _result(invocation)

    assert execute_phase_c(prepared, (), execute=execute) == {"fix-a": ()}
    assert len(created_paths) == 1
    assert not created_paths[0].exists()
    assert [call.argv for call in calls] == [
        ("python", "/evidence/check.py"),
        ("python", "-m", "build"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
        ("python", "-m", "build"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
        ("python", "/evidence/check.py"),
    ]
    stage = prepared.store.path / "phase-c/stages/0001-fix-a"
    assert (
        yaml.safe_load(next((stage / "oracles").glob("*preapply*.yaml")).read_text())["vulnerable"]
        is True
    )
    assert (stage / "manifest.yaml").is_file()
    final = prepared.store.path / "final"
    assert b"-old\n+new\n" in (final / "combined.diff").read_bytes()
    series = yaml.safe_load((final / "supplied-series.yaml").read_text())
    assert series["patches"][0]["effective_kind"] == "supplied"
    assert (
        series["combined_diff"]["sha256"]
        == hashlib.sha256((final / "combined.diff").read_bytes()).hexdigest()
    )
    verdict_prep = yaml.safe_load((final / "verdict-prep.yaml").read_text())
    assert verdict_prep["acceptance_evaluated"] is False
    assert not (final / "verdict.yaml").exists()
    assert (
        yaml.safe_load((prepared.store.path / "run.yaml").read_text())["state"]
        == "assembling_evidence"
    )
    prepared.store.verify_hash_manifest()
    prepared.close()


def test_run_campaign_accepts_only_after_full_conjunction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, initial = _prepare(tmp_path, monkeypatch)
    initial.close()
    # The helper pre-created run-1; use a distinct full-run identifier.
    calls = []

    def execute(config, invocation):
        calls.append(invocation)
        output = next(mount.source for mount in invocation.mounts if mount.destination == "/output")
        if "MENDRUNE_ORACLE_NONCE" in invocation.environment:
            nonce = invocation.environment["MENDRUNE_ORACLE_NONCE"]
            # Phase A and cumulative preapply reproduce; all post-patch checks mitigate.
            vulnerable = len(calls) in {3, 10}
            (output / "oracle.yaml").write_text(
                f"schema_version: 1\nnonce: {nonce}\nvulnerable: "
                f"{'true' if vulnerable else 'false'}\nobservation: checked\n"
            )
        elif invocation.argv == ("python", "/evidence/check.py"):
            (output / "scan.json").write_text('{"version":"1","results":[],"errors":[],"paths":{}}')
        return _result(invocation)

    verdict = run_campaign(campaign, run_id="full-run", execute=execute)
    runs_directory = Path(yaml.safe_load(campaign.read_text())["storage"]["runs_directory"])
    run_root = runs_directory / "full-run"
    run = yaml.safe_load((run_root / "run.yaml").read_text())
    report = yaml.safe_load((run_root / "final/report.yaml").read_text())

    assert verdict["outcome"] == "accepted"
    assert verdict["limitations"]
    assert run["state"] == run["outcome"] == "accepted"
    assert run["reason_code"] == "all_required_checks_passed"
    assert report["limitations"] == verdict["limitations"]
    assert not (campaign.parent / "runs/.workspaces/full-run").exists()


def test_acceptance_rejects_missing_required_phase_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, initial = _prepare(tmp_path, monkeypatch)
    initial.close()
    calls = []

    def execute(config, invocation):
        calls.append(invocation)
        output = next(mount.source for mount in invocation.mounts if mount.destination == "/output")
        if "MENDRUNE_ORACLE_NONCE" in invocation.environment:
            nonce = invocation.environment["MENDRUNE_ORACLE_NONCE"]
            vulnerable = len(calls) in {3, 10}
            (output / "oracle.yaml").write_text(
                f"schema_version: 1\nnonce: {nonce}\nvulnerable: "
                f"{'true' if vulnerable else 'false'}\nobservation: checked\n"
            )
        elif invocation.argv == ("python", "/evidence/check.py"):
            (output / "scan.json").write_text('{"version":"1","results":[],"errors":[],"paths":{}}')
        return _result(invocation)

    from mendrune import orchestrator

    original_accept = orchestrator._accept_campaign

    def delete_then_accept(prepared):
        next((prepared.store.path / "phase-a/checks").glob("*.yaml")).unlink()
        return original_accept(prepared)

    monkeypatch.setattr(orchestrator, "_accept_campaign", delete_then_accept)
    with pytest.raises(MendRuneError) as raised:
        run_campaign(campaign, run_id="missing-evidence", execute=execute)

    assert raised.value.reason_code == "required_check_missing"


def test_acceptance_rejects_tampered_combined_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, prepared = _prepare(tmp_path, monkeypatch)
    prepared.store.write_yaml(
        "final/supplied-series.yaml",
        {"combined_diff": {"path": "combined.diff", "sha256": "0"}, "patches": []},
    )
    (prepared.store.path / "final/combined.diff").parent.mkdir(exist_ok=True)
    (prepared.store.path / "final/combined.diff").write_bytes(b"tampered")
    prepared.store.write_yaml("final/scan-comparison.yaml", {"status": "passed"})
    prepared.store.write_yaml("final/manifest.yaml", {})
    from mendrune.orchestrator import _accept_campaign, _persist_state

    _persist_state(
        prepared.store,
        prepared.verified,
        __import__("mendrune.state", fromlist=["RunState"]).RunState.ASSEMBLING_EVIDENCE,
    )
    prepared.store.write_hash_manifest()

    with pytest.raises(MendRuneError):
        _accept_campaign(prepared)
    run = yaml.safe_load((prepared.store.path / "run.yaml").read_text())
    assert run["state"] == run["outcome"] == "evidence_failure"
    assert not (prepared.store.path / "final/verdict.yaml").exists()
    prepared.close()


def test_phase_c_already_mitigated_has_stable_overlap_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, prepared = _prepare(tmp_path, monkeypatch)
    paths = []
    from mendrune.repository import Worktree

    original_create = Worktree.create

    def create(*args, **kwargs):
        worktree = original_create(*args, **kwargs)
        paths.append(worktree.path)
        return worktree

    monkeypatch.setattr("mendrune.orchestrator.Worktree.create", create)

    def execute(config, invocation):
        output = next(mount.source for mount in invocation.mounts if mount.destination == "/output")
        nonce = invocation.environment["MENDRUNE_ORACLE_NONCE"]
        (output / "oracle.yaml").write_text(
            f"schema_version: 1\nnonce: {nonce}\nvulnerable: false\nobservation: overlap\n"
        )
        return _result(invocation)

    with pytest.raises(MendRuneError) as raised:
        execute_phase_c(prepared, (), execute=execute)

    assert raised.value.reason_code == "unit_vulnerability_already_mitigated"
    assert not paths[0].exists()
    assert (
        yaml.safe_load((prepared.store.path / "run.yaml").read_text())["state"]
        == "ambiguous_overlap"
    )
    failure = yaml.safe_load(
        (prepared.store.path / "phase-c/stages/0001-fix-a/failure.yaml").read_text()
    )
    assert failure["reason_code"] == "unit_vulnerability_already_mitigated"
    prepared.store.verify_hash_manifest()
    prepared.close()


def test_phase_c_detects_reopened_prior_vulnerability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = create_campaign(tmp_path)
    repository = Path(yaml.safe_load(campaign.read_text())["repository"]["path"])
    (repository / "src").mkdir()
    (repository / "src/a.py").write_text("old\n")
    subprocess.run(["git", "-C", repository, "add", "src/a.py"], check=True)
    subprocess.run(["git", "-C", repository, "commit", "-qm", "fixture source"], check=True)
    second_patch = campaign.parent / "patches/b.diff"
    second_patch.write_bytes(b"--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-new\n+old\n")
    document = yaml.safe_load(campaign.read_text())
    second_unit = {
        "id": "fix-b",
        "vulnerabilities": [
            {
                "id": "CVE-2026-2",
                "oracle": deepcopy(document["units"][0]["vulnerabilities"][0]["oracle"]),
            }
        ],
        "patches": [
            {
                "id": "patch-b",
                "path": "patches/b.diff",
                "sha256": hashlib.sha256(second_patch.read_bytes()).hexdigest(),
            }
        ],
        "regressions": [],
    }
    document["units"].append(second_unit)
    document["composition"]["order"].append("fix-b")
    campaign.write_text(yaml.safe_dump(document, sort_keys=False))
    monkeypatch.setattr("mendrune.orchestrator.executor.preflight", lambda config: None)
    prepared = prepare_preflight(campaign, run_id="run-1")
    oracle_calls = 0

    def execute(config, invocation):
        nonlocal oracle_calls
        output = next(mount.source for mount in invocation.mounts if mount.destination == "/output")
        if "MENDRUNE_ORACLE_NONCE" in invocation.environment:
            oracle_calls += 1
            nonce = invocation.environment["MENDRUNE_ORACLE_NONCE"]
            # Stage-two's first accumulated check reopens the stage-one vulnerability.
            vulnerable = oracle_calls in {1, 3, 4}
            (output / "oracle.yaml").write_text(
                f"schema_version: 1\nnonce: {nonce}\nvulnerable: "
                f"{'true' if vulnerable else 'false'}\nobservation: checked\n"
            )
        elif invocation.argv == ("python", "/evidence/check.py"):
            (output / "scan.json").write_text('{"version":"1","results":[],"errors":[],"paths":{}}')
        return _result(invocation)

    with pytest.raises(MendRuneError) as raised:
        execute_phase_c(prepared, (), execute=execute)

    assert raised.value.reason_code == "prior_vulnerability_reopened"
    assert yaml.safe_load((prepared.store.path / "run.yaml").read_text())["state"] == (
        "cumulative_failure"
    )
    failure = yaml.safe_load(
        (prepared.store.path / "phase-c/stages/0002-fix-b/failure.yaml").read_text()
    )
    assert failure["reason_code"] == "prior_vulnerability_reopened"
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
