from copy import deepcopy

import pytest

from mendrune.errors import ConfigurationError
from mendrune.models import PatchPolicyConfig
from mendrune.patches import locate_hunks, parse_patch
from tests.unit.test_models import campaign_data


def policy(**updates) -> PatchPolicyConfig:
    data = deepcopy(campaign_data()["patch_policy"])
    data.update(updates)
    return PatchPolicyConfig.model_validate(data)


def test_parses_text_patch() -> None:
    parsed = parse_patch(
        b"--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-old\n+new\n",
        policy(),
    )
    assert parsed.changed_lines == 2
    assert parsed.files[0].old_path is not None
    assert parsed.files[0].old_path.as_posix() == "src/a.py"
    assert parsed.files[0].hunks[0].old_lines == (b"old",)


@pytest.mark.parametrize(
    ("patch", "reason"),
    [
        (b"", "patch_format_unsupported"),
        (b"GIT binary patch\n", "patch_format_unsupported"),
        (
            b"--- a/../secret\n+++ b/../secret\n@@ -1 +1 @@\n-a\n+b\n",
            "patch_policy_violation",
        ),
        (
            b"--- /dev/null\n+++ b/src/new.py\n@@ -0,0 +1 @@\n+x\n",
            "patch_policy_violation",
        ),
        (
            b"--- a/src/a.py\n+++ b/src/a.py\n@@ -1,2 +1 @@\n-a\n+b\n",
            "patch_format_unsupported",
        ),
    ],
)
def test_rejects_unsupported_patch(patch: bytes, reason: str) -> None:
    with pytest.raises(ConfigurationError) as raised:
        parse_patch(patch, policy())
    assert raised.value.reason_code == reason


def test_locates_exact_context_relocation(tmp_path) -> None:
    target = tmp_path / "src" / "a.py"
    target.parent.mkdir()
    target.write_bytes(b"prefix\nold\nsuffix\n")
    parsed = parse_patch(b"--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-old\n+new\n", policy())

    placements = locate_hunks(tmp_path, parsed)

    assert placements[0].original_start == 1
    assert placements[0].applied_start == 2


def test_rejects_ambiguous_context_relocation(tmp_path) -> None:
    target = tmp_path / "src" / "a.py"
    target.parent.mkdir()
    target.write_bytes(b"prefix\nold\nold\n")
    parsed = parse_patch(b"--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-old\n+new\n", policy())

    with pytest.raises(ConfigurationError) as raised:
        locate_hunks(tmp_path, parsed)

    assert raised.value.reason_code == "patch_check_failed"


def test_rejects_patch_line_limit() -> None:
    patch = b"--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-old\n+new\n"
    with pytest.raises(ConfigurationError) as raised:
        parse_patch(patch, policy(max_changed_lines_per_patch=1))
    assert raised.value.reason_code == "patch_policy_violation"
