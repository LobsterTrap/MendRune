from copy import deepcopy

import pytest
from pydantic import ValidationError

from mendrune.models import CampaignConfig


def campaign_data() -> dict:
    command = {
        "argv": ["python", "/evidence/check.py"],
        "evidence_paths": ["check.py"],
        "timeout_seconds": 60,
    }
    return {
        "schema_version": 1,
        "campaign_id": "example",
        "title": "Example",
        "repository": {"path": "/tmp/repo", "base_ref": "HEAD"},
        "composition": {"order": ["fix-a"]},
        "units": [
            {
                "id": "fix-a",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-1",
                        "oracle": {**command, "result_file": "/output/oracle.yaml"},
                    }
                ],
                "patches": [{"id": "patch-a", "path": "patches/a.diff", "sha256": "a" * 64}],
                "regressions": [{"id": "unit-regression", **command}],
            }
        ],
        "commands": {
            "build": {"argv": ["python", "-m", "build"], "timeout_seconds": 60},
            "shared_regressions": [{"id": "shared-regression", **command}],
            "scans": [
                {
                    "id": "semgrep",
                    **command,
                    "required": True,
                    "raw_output": "/output/scan.json",
                    "normalizer": "semgrep",
                }
            ],
        },
        "execution": {
            "image": "localhost/example@sha256:" + "b" * 64,
            "runtime": "crun-krun",
            "network": "none",
            "container_workdir": "/workspace",
            "default_timeout_seconds": 60,
            "cpus": 1,
            "memory_mib": 512,
            "pids_limit": 128,
            "maximum_output_bytes": 1024,
            "allowed_generated_paths": ["build/**"],
            "environment": {"LANG": "C.UTF-8"},
        },
        "mounts": {
            "evidence_source": "evidence",
            "container_evidence_dir": "/evidence",
            "container_output_dir": "/output",
        },
        "patch_policy": {
            "allowed_paths": ["src/**"],
            "denied_paths": ["tests/**"],
            "max_files_changed_per_patch": 3,
            "max_changed_lines_per_patch": 100,
            "max_changed_lines_campaign": 200,
        },
        "scan_policy": {
            "severity_order": ["low", "medium", "high"],
            "reject_new_findings_at_or_above": "medium",
        },
        "goose": {"enabled": False},
        "storage": {"runs_directory": "/tmp/runs"},
    }


def test_rejects_patch_features_not_accounted_by_v1() -> None:
    for field in (
        "allow_binary",
        "allow_renames",
        "allow_new_files",
        "allow_deleted_files",
        "allow_mode_changes",
    ):
        data = campaign_data()
        data["patch_policy"][field] = True
        with pytest.raises(ValueError, match="v1 does not support"):
            CampaignConfig.model_validate(data)


def test_complete_campaign_is_valid() -> None:
    campaign = CampaignConfig.model_validate(campaign_data())
    assert campaign.composition.order == ("fix-a",)
    assert campaign.goose.enabled is False


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.update(unknown=True), "Extra inputs"),
        (lambda data: data["composition"].update(order=["other"]), "every unit ID"),
        (
            lambda data: data["units"][0]["patches"][0].update(adapt_with_goose=True),
            "requires goose.enabled",
        ),
        (
            lambda data: data["execution"].update(allowed_generated_paths=["../build/**"]),
            "dot components",
        ),
        (
            lambda data: data["commands"]["scans"][0].update(required=False),
            "optional scanners",
        ),
    ],
)
def test_campaign_rejects_invalid_relationships(mutate, message: str) -> None:
    data = deepcopy(campaign_data())
    mutate(data)
    with pytest.raises(ValidationError, match=message):
        CampaignConfig.model_validate(data)


def test_duplicate_vulnerability_owner_is_rejected() -> None:
    data = campaign_data()
    second = deepcopy(data["units"][0])
    second["id"] = "fix-b"
    second["patches"][0]["id"] = "patch-b"
    data["units"].append(second)
    data["composition"]["order"].append("fix-b")

    with pytest.raises(ValidationError, match="vulnerability IDs must be unique"):
        CampaignConfig.model_validate(data)
