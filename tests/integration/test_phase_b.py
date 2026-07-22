import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from mendrune.errors import MendRuneError
from mendrune.executor import CapturedOutput, ExecutionResult
from mendrune.orchestrator import PreflightRun, execute_phase_a, execute_phase_b, prepare_preflight
from tests.unit.test_config import write_campaign
from tests.unit.test_models import campaign_data
from tests.unit.test_repository import create_repository, git


def _patch(old: str, new: str, path: str) -> bytes:
    return f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-{old}\n+{new}\n".encode()


@pytest.fixture
def phase_b_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[PreflightRun]:
    repository = tmp_path / "repo"
    create_repository(repository)
    (repository / "src").mkdir()
    (repository / "src/a.py").write_text("old-a\n")
    (repository / "src/b.py").write_text("old-b\n")
    git(repository, "add", "src/a.py", "src/b.py")
    git(repository, "commit", "-qm", "integration sources")

    campaign_root = tmp_path / "campaign"
    evidence = campaign_root / "evidence"
    patches = campaign_root / "patches"
    evidence.mkdir(parents=True)
    patches.mkdir()
    (evidence / "check.py").write_text("print('fixture')\n")
    patch_data = {
        "a.diff": _patch("old-a", "fixed-a", "src/a.py"),
        "b.diff": _patch("old-b", "fixed-b", "src/b.py"),
    }
    for name, content in patch_data.items():
        (patches / name).write_bytes(content)

    data = campaign_data()
    data["campaign_id"] = "phase-b-integration"
    data["repository"] = {"path": str(repository), "base_ref": "HEAD"}
    data["storage"]["runs_directory"] = str(tmp_path / "runs")
    data["commands"]["build"]["argv"] = ["fixture", "build"]
    data["commands"]["shared_regressions"][0]["argv"] = ["fixture", "shared-regression"]
    data["commands"]["scans"][0]["argv"] = ["fixture", "scan"]
    unit = data["units"][0]
    unit["vulnerabilities"][0]["oracle"]["argv"] = ["fixture", "oracle-a"]
    unit["vulnerabilities"].append(
        {
            "id": "CVE-2026-2",
            "oracle": {
                **unit["vulnerabilities"][0]["oracle"],
                "argv": ["fixture", "oracle-b"],
            },
        }
    )
    unit["patches"] = [
        {
            "id": "patch-a",
            "path": "patches/a.diff",
            "sha256": hashlib.sha256(patch_data["a.diff"]).hexdigest(),
        },
        {
            "id": "patch-b",
            "path": "patches/b.diff",
            "sha256": hashlib.sha256(patch_data["b.diff"]).hexdigest(),
        },
    ]
    unit["regressions"][0]["argv"] = ["fixture", "unit-regression"]
    campaign = campaign_root / "campaign.yaml"
    write_campaign(campaign, data)

    monkeypatch.setattr("mendrune.orchestrator.executor.preflight", lambda config: None)
    prepared = prepare_preflight(campaign, run_id="phase-b-integration")
    execute_phase_a(prepared, execute=FakeExecutor(vulnerable=True))
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


def _semgrep_finding() -> dict[str, object]:
    return {
        "check_id": "python.security.new-risk",
        "path": "src/a.py",
        "start": {"line": 1, "col": 1, "offset": 0},
        "end": {"line": 1, "col": 5, "offset": 4},
        "extra": {
            "message": "new prohibited finding",
            "severity": "WARNING",
            "fingerprint": "phase-b-new-finding",
        },
    }


class FakeExecutor:
    def __init__(self, *, vulnerable: bool = False, failure: str | None = None) -> None:
        self.vulnerable = vulnerable
        self.failure = failure
        self.calls = []
        self.workspaces: list[Path] = []

    def __call__(self, config, invocation) -> ExecutionResult:
        self.calls.append(invocation)
        command = invocation.argv[1]
        output = next(mount.source for mount in invocation.mounts if mount.destination == "/output")
        workspace = next(
            mount.source for mount in invocation.mounts if mount.destination == "/workspace"
        )
        self.workspaces.append(workspace)

        if self.failure == "source_mutation" and command == "build":
            (workspace / "src/a.py").write_text("mutated by isolated command\n")
        if command.startswith("oracle-"):
            vulnerable = self.vulnerable or (
                self.failure == "partial_mitigation" and command == "oracle-b"
            )
            (output / "oracle.yaml").write_text(
                "schema_version: 1\n"
                f"nonce: {invocation.environment['MENDRUNE_ORACLE_NONCE']}\n"
                f"vulnerable: {str(vulnerable).lower()}\n"
                "observation: phase B integration fixture\n"
            )
        if command == "scan":
            results = [_semgrep_finding()] if self.failure == "prohibited_finding" else []
            (output / "scan.json").write_text(
                json.dumps({"version": "1", "results": results, "errors": [], "paths": {}})
            )

        exit_code = int(self.failure == "regression_failure" and command == "unit-regression")
        return _result(invocation, exit_code=exit_code)


def test_multi_patch_multi_vulnerability_unit_executes_in_isolation(
    phase_b_run: PreflightRun,
) -> None:
    execute = FakeExecutor()

    assert execute_phase_b(phase_b_run, (), execute=execute) == {"fix-a": ()}
    assert [call.argv[1] for call in execute.calls] == [
        "build",
        "oracle-a",
        "oracle-b",
        "shared-regression",
        "unit-regression",
        "scan",
    ]
    assert len(set(execute.workspaces)) == 1
    isolated = execute.workspaces[0]
    assert isolated != phase_b_run.baseline.path
    assert not isolated.exists()

    root = phase_b_run.store.path / "phase-b/fix-a"
    patch_records = sorted((root / "patches").glob("*.yaml"))
    oracle_records = sorted((root / "oracles").glob("*.yaml"))
    assert [yaml.safe_load(path.read_text())["patch_id"] for path in patch_records] == [
        "patch-a",
        "patch-b",
    ]
    assert [yaml.safe_load(path.read_text())["vulnerable"] for path in oracle_records] == [
        False,
        False,
    ]
    assert (root / "manifest.yaml").is_file()
    phase_b_run.store.verify_hash_manifest()


@pytest.mark.parametrize(
    ("failure", "reason_code"),
    [
        ("partial_mitigation", "unit_vulnerability_not_mitigated"),
        ("regression_failure", "unit_regression_failed"),
        ("source_mutation", "actual_diff_mismatch"),
        ("prohibited_finding", "prohibited_new_finding"),
    ],
)
def test_isolated_unit_failure_matrix_persists_stable_evidence(
    phase_b_run: PreflightRun, failure: str, reason_code: str
) -> None:
    execute = FakeExecutor(failure=failure)

    with pytest.raises(MendRuneError) as raised:
        execute_phase_b(phase_b_run, (), execute=execute)

    assert raised.value.reason_code == reason_code
    root = phase_b_run.store.path / "phase-b/fix-a"
    assert yaml.safe_load((phase_b_run.store.path / "run.yaml").read_text())["state"] == (
        "isolated_unit_failure"
    )
    assert yaml.safe_load((root / "failure.yaml").read_text()) == {
        "schema_version": 1,
        "status": "failed",
        "reason_code": reason_code,
    }
    assert execute.workspaces and not execute.workspaces[0].exists()
    if failure == "prohibited_finding":
        comparison = yaml.safe_load((root / "scan-comparison.yaml").read_text())
        assert comparison["status"] == "failed"
        assert comparison["prohibited"][0]["fingerprint"] == "phase-b-new-finding"
    phase_b_run.store.verify_hash_manifest()
