#!/usr/bin/env python3
"""Generate the self-contained MendRune example campaign."""

from __future__ import annotations

import copy
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
GENERATED = ROOT / "generated"
REPOSITORY = GENERATED / "repository"
EVIDENCE = GENERATED / "evidence"
PATCHES = GENERATED / "patches"
CAMPAIGN = GENERATED / "campaign.yaml"
DEFAULT_DIGEST = "sha256:" + "0" * 64


def run(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def main() -> None:
    digest = os.environ.get("MENDRUNE_EXAMPLE_IMAGE_DIGEST", DEFAULT_DIGEST)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SystemExit(
            "MENDRUNE_EXAMPLE_IMAGE_DIGEST must be sha256: followed by 64 lowercase hex digits"
        )

    shutil.rmtree(GENERATED, ignore_errors=True)
    write(
        REPOSITORY / "src" / "tokens.py",
        'def accepts_token(token: str) -> bool:\n    return token == ""\n',
    )
    run("git", "init", "-q", str(REPOSITORY))
    run("git", "-C", str(REPOSITORY), "config", "user.name", "MendRune Example")
    run("git", "-C", str(REPOSITORY), "config", "user.email", "example@invalid.local")
    run("git", "-C", str(REPOSITORY), "add", "src/tokens.py")
    run("git", "-C", str(REPOSITORY), "commit", "-q", "-m", "vulnerable base")
    base_commit = run("git", "-C", str(REPOSITORY), "rev-parse", "HEAD")

    patch = (
        b"--- a/src/tokens.py\n"
        b"+++ b/src/tokens.py\n"
        b"@@ -1,2 +1,2 @@\n"
        b" def accepts_token(token: str) -> bool:\n"
        b'-    return token == ""\n'
        b'+    return token != ""\n'
    )
    PATCHES.mkdir(parents=True)
    patch_path = PATCHES / "reject-empty-token.diff"
    patch_path.write_bytes(patch)
    patch_digest = hashlib.sha256(patch).hexdigest()

    write(
        EVIDENCE / "oracle.py",
        """import os
from pathlib import Path

import yaml

source = Path("src/tokens.py").read_text()
result = {
    "schema_version": 1,
    "nonce": os.environ["MENDRUNE_ORACLE_NONCE"],
    "vulnerable": 'return token == ""' in source,
    "observation": (
        "empty-token acceptance is present"
        if 'return token == ""' in source
        else "empty tokens are rejected"
    ),
}
Path("/output/oracle.yaml").write_text(yaml.safe_dump(result, sort_keys=False))
""",
    )
    write(
        EVIDENCE / "regression.py",
        """from pathlib import Path

source = Path("src/tokens.py").read_text()
assert "def accepts_token" in source
""",
    )
    write(
        EVIDENCE / "scanner.py",
        """import json
from pathlib import Path

result = {
    "version": "example",
    "results": [],
    "errors": [],
    "paths": {"scanned": ["src/tokens.py"]},
}
Path("/output/scan.json").write_text(json.dumps(result))
""",
    )

    command = {
        "argv": ["python", "/evidence/regression.py"],
        "evidence_paths": ["regression.py"],
        "timeout_seconds": 30,
    }
    campaign = {
        "schema_version": 1,
        "campaign_id": "documented-example",
        "title": "Reject an empty authentication token",
        "repository": {"path": str(REPOSITORY), "base_ref": base_commit},
        "composition": {"order": ["reject-empty-token"]},
        "units": [
            {
                "id": "reject-empty-token",
                "vulnerabilities": [
                    {
                        "id": "EXAMPLE-EMPTY-TOKEN",
                        "oracle": {
                            "argv": ["python", "/evidence/oracle.py"],
                            "evidence_paths": ["oracle.py"],
                            "result_file": "/output/oracle.yaml",
                            "timeout_seconds": 30,
                        },
                    }
                ],
                "patches": [
                    {
                        "id": "reject-empty-token",
                        "path": "patches/reject-empty-token.diff",
                        "sha256": patch_digest,
                        "adapt_with_goose": False,
                    }
                ],
                "regressions": [{"id": "unit-regression", **copy.deepcopy(command)}],
            }
        ],
        "commands": {
            "build": {"argv": ["python", "-m", "compileall", "-q", "src"], "timeout_seconds": 30},
            "shared_regressions": [{"id": "shared-regression", **copy.deepcopy(command)}],
            "scans": [
                {
                    "id": "example-scan",
                    "argv": ["python", "/evidence/scanner.py"],
                    "evidence_paths": ["scanner.py"],
                    "timeout_seconds": 30,
                    "required": True,
                    "raw_output": "/output/scan.json",
                    "normalizer": "semgrep",
                }
            ],
        },
        "execution": {
            "image": f"localhost/mendrune-example@{digest}",
            "runtime": "crun-krun",
            "network": "none",
            "container_workdir": "/workspace",
            "default_timeout_seconds": 30,
            "cpus": 1,
            "memory_mib": 512,
            "pids_limit": 128,
            "maximum_output_bytes": 1048576,
            "allowed_generated_paths": ["src/__pycache__/**"],
            "environment": {"LANG": "C.UTF-8"},
        },
        "mounts": {
            "evidence_source": "evidence",
            "container_evidence_dir": "/evidence",
            "container_output_dir": "/output",
        },
        "patch_policy": {
            "allowed_paths": ["src/**"],
            "denied_paths": [".git/**"],
            "max_files_changed_per_patch": 1,
            "max_changed_lines_per_patch": 2,
            "max_changed_lines_campaign": 2,
            "allow_binary": False,
            "allow_renames": False,
            "allow_new_files": False,
            "allow_deleted_files": False,
            "allow_mode_changes": False,
        },
        "scan_policy": {
            "severity_order": ["info", "low", "medium", "high", "critical"],
            "reject_new_findings_at_or_above": "medium",
        },
        "goose": {"enabled": False},
        "storage": {"runs_directory": str(GENERATED / "runs"), "keep_failed_workspaces": False},
    }
    CAMPAIGN.write_text(yaml.safe_dump(campaign, sort_keys=False))
    print(f"wrote {CAMPAIGN}")
    print(f"base commit: {base_commit}")
    print(f"patch sha256: {patch_digest}")


if __name__ == "__main__":
    main()
