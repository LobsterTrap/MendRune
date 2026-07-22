from pathlib import Path

import pytest
import yaml

from mendrune.errors import MendRuneError
from mendrune.reporting import LIMITATIONS, render_report, render_status, report, status
from mendrune.runstore import RunStore


def _store(tmp_path: Path) -> RunStore:
    store = RunStore.create(tmp_path, "campaign", run_id="run-1")
    store.write_yaml(
        "run.yaml",
        {
            "schema_version": 1,
            "run_id": "run-1",
            "campaign_id": "campaign",
            "state": "accepted",
            "outcome": "accepted",
        },
    )
    return store


def test_status_reads_and_deterministically_renders_stored_run(tmp_path: Path) -> None:
    store = _store(tmp_path)

    first = render_status(store)
    second = status(tmp_path, "run-1")

    assert first == second
    assert yaml.safe_load(first) == yaml.safe_load((store.path / "run.yaml").read_text())


def test_report_reads_stored_evidence_and_has_mandatory_limitations(tmp_path: Path) -> None:
    store = _store(tmp_path)
    verdict = {
        "schema_version": 1,
        "run_id": "run-1",
        "outcome": "accepted",
        "reason_code": "all_required_checks_passed",
        "limitations": list(LIMITATIONS),
    }
    store.write_yaml("final/verdict.yaml", verdict)

    first = render_report(store)
    second = report(tmp_path, "run-1")
    document = yaml.safe_load(first)

    assert first == second
    assert document["verdict"] == verdict
    assert document["limitations"] == list(LIMITATIONS)


def test_report_is_available_before_a_verdict_without_inferring_one(tmp_path: Path) -> None:
    store = _store(tmp_path)

    document = yaml.safe_load(render_report(store))

    assert document["verdict"] is None
    assert document["limitations"] == list(LIMITATIONS)


def test_reporting_rejects_missing_or_invalid_run_record(tmp_path: Path) -> None:
    missing = RunStore.create(tmp_path, "campaign", run_id="missing")
    with pytest.raises(MendRuneError) as raised:
        render_status(missing)
    assert raised.value.reason_code == "artifact_missing"

    invalid = RunStore.create(tmp_path, "campaign", run_id="invalid")
    (invalid.path / "run.yaml").write_text("- not\n- a\n- record\n")
    with pytest.raises(MendRuneError) as raised:
        render_report(invalid)
    assert raised.value.reason_code == "provenance_incomplete"


def test_reporting_does_not_read_unstored_repository_evidence(tmp_path: Path) -> None:
    store = _store(tmp_path)
    outside = tmp_path / "repository-result.yaml"
    outside.write_text("outcome: rejected\n")

    rendered = render_report(store)

    assert str(outside) not in rendered
    assert "rejected" not in rendered
