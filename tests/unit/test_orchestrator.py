import hashlib
from pathlib import Path

import pytest
import yaml

from mendrune.errors import MendRuneError
from mendrune.orchestrator import prepare_preflight
from tests.integration.test_verify_cli import create_campaign


def _prepare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    campaign = create_campaign(tmp_path)
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
