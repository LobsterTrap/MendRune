import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from mendrune.errors import ConfigurationError, MendRuneError
from mendrune.goose import adapt_patch, validate_recipe, write_evidence_bundle
from mendrune.models import PatchPolicyConfig


def test_validate_recipe_invokes_documented_command(tmp_path: Path) -> None:
    recipe = tmp_path / "recipe.yaml"
    recipe.write_text("title: test\n")
    with patch("mendrune.goose.subprocess.run") as run:
        run.return_value.returncode = 0
        validate_recipe(recipe, timeout_seconds=10)
    assert run.call_args.args[0] == ["goose", "recipe", "validate", str(recipe)]
    assert run.call_args.kwargs["timeout"] == 10


def test_validate_recipe_rejects_failure(tmp_path: Path) -> None:
    recipe = tmp_path / "recipe.yaml"
    recipe.write_text("invalid")
    with patch("mendrune.goose.subprocess.run") as run:
        run.return_value.returncode = 1
        run.return_value.stderr = "bad recipe"
        run.return_value.stdout = ""
        with pytest.raises(ConfigurationError) as raised:
            validate_recipe(recipe, timeout_seconds=10)
    assert raised.value.reason_code == "goose_recipe_invalid"


def test_adapt_patch_invokes_once_and_parses_only_final_line(tmp_path: Path) -> None:
    recipe = tmp_path / "recipe.yaml"
    evidence = tmp_path / "bundle.md"
    recipe.write_text("recipe")
    evidence.write_text("evidence")
    diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+new\n"
    with patch("mendrune.goose.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess(
            [], 0, json.dumps({"adapted_patch": diff}).encode() + b"\n", b""
        )
        assert (
            adapt_patch(recipe, evidence, maximum_response_bytes=1000, timeout_seconds=7)
            == diff.encode()
        )
    assert run.call_count == 1
    command = run.call_args.args[0]
    assert command == [
        "goose",
        "run",
        "--recipe",
        str(recipe),
        "--params",
        f"evidence_bundle={evidence.resolve()}",
        "--no-session",
        "--quiet",
    ]


@pytest.mark.parametrize(
    "stdout,stderr",
    [
        (b"", b'{"adapted_patch":"stolen"}'),
        (b'```json\n{"adapted_patch":"x"}\n```\n', b""),
        (b'{"adapted_patch":""}\n', b""),
        (b'{"adapted_patch":"x","verdict":"accept"}\n', b""),
        (b'{"adapted_patch":7}\n', b""),
    ],
)
def test_adapt_patch_rejects_malformed_empty_extra_and_stderr(
    tmp_path: Path, stdout: bytes, stderr: bytes
) -> None:
    with patch("mendrune.goose.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, stdout, stderr)
        with pytest.raises(MendRuneError) as raised:
            adapt_patch(
                tmp_path / "recipe",
                tmp_path / "evidence",
                maximum_response_bytes=1000,
                timeout_seconds=1,
            )
    assert raised.value.reason_code == "goose_adaptation_failed"


def test_adapt_patch_rejects_timeout(tmp_path: Path) -> None:
    with (
        patch("mendrune.goose.subprocess.run", side_effect=subprocess.TimeoutExpired([], 1)),
        pytest.raises(MendRuneError) as raised,
    ):
        adapt_patch(
            tmp_path / "recipe",
            tmp_path / "evidence",
            maximum_response_bytes=1000,
            timeout_seconds=1,
        )
    assert raised.value.reason_code == "goose_adaptation_failed"


def test_evidence_bundle_is_bounded(tmp_path: Path) -> None:
    policy = PatchPolicyConfig(
        allowed_paths=("src/**",),
        denied_paths=("secrets/**",),
        max_files_changed_per_patch=1,
        max_changed_lines_per_patch=2,
        max_changed_lines_campaign=2,
    )
    with pytest.raises(MendRuneError) as raised:
        write_evidence_bundle(
            tmp_path / "bundle",
            unit_id="u",
            patch_id="p",
            supplied_patch=b"x" * 20,
            supplied_sha256="0" * 64,
            policy=policy,
            source_context=b"y" * 20,
            application_diagnostic="failed",
            maximum_bytes=10,
        )
    assert raised.value.reason_code == "goose_adaptation_failed"
