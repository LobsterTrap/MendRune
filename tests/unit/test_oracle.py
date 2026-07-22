from pathlib import Path

import pytest
import yaml

from mendrune.errors import MendRuneError
from mendrune.oracle import evaluate_oracle_result

NONCE = "a" * 32


def result_file(root: Path, **updates) -> Path:
    document = {
        "schema_version": 1,
        "nonce": NONCE,
        "vulnerable": True,
        "observation": "exploit reproduced",
    }
    document.update(updates)
    path = root / "oracle.yaml"
    path.write_text(yaml.safe_dump(document))
    return path


def test_evaluates_valid_oracle(tmp_path: Path) -> None:
    path = result_file(tmp_path)
    result = evaluate_oracle_result(
        tmp_path,
        path,
        expected_nonce=NONCE,
        expected_vulnerable=True,
        exit_code=0,
        timed_out=False,
    )
    assert result.vulnerable is True


@pytest.mark.parametrize(
    ("updates", "expected", "reason"),
    [
        ({"nonce": "b" * 32}, True, "candidate_oracle_invalid"),
        ({"vulnerable": "true"}, True, "candidate_oracle_invalid"),
        ({"vulnerable": False}, True, "vulnerability_not_reproduced"),
        ({"vulnerable": True}, False, "exploit_still_effective"),
    ],
)
def test_rejects_invalid_or_unexpected_result(
    tmp_path: Path, updates: dict, expected: bool, reason: str
) -> None:
    path = result_file(tmp_path, **updates)
    with pytest.raises(MendRuneError) as raised:
        evaluate_oracle_result(
            tmp_path,
            path,
            expected_nonce=NONCE,
            expected_vulnerable=expected,
            exit_code=0,
            timed_out=False,
        )
    assert raised.value.reason_code == reason


def test_crash_is_not_mitigation(tmp_path: Path) -> None:
    path = result_file(tmp_path, vulnerable=False)
    with pytest.raises(MendRuneError) as raised:
        evaluate_oracle_result(
            tmp_path,
            path,
            expected_nonce=NONCE,
            expected_vulnerable=False,
            exit_code=1,
            timed_out=False,
        )
    assert raised.value.reason_code == "candidate_oracle_invalid"
