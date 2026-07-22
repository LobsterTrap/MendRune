"""Structured YAML vulnerability-oracle evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from mendrune.errors import MendRuneError

_NONCE = re.compile(r"^[0-9a-f]{32,128}$")
MAX_ORACLE_BYTES = 65_536
MAX_OBSERVATION_BYTES = 4096


@dataclass(frozen=True)
class OracleObservation:
    vulnerable: bool
    observation: str


def evaluate_oracle_result(
    output_root: Path,
    result_path: Path,
    *,
    expected_nonce: str,
    expected_vulnerable: bool,
    exit_code: int,
    timed_out: bool,
) -> OracleObservation:
    if not _NONCE.fullmatch(expected_nonce):
        raise MendRuneError("invalid controller nonce", reason_code="unexpected_internal_error")
    if timed_out:
        raise MendRuneError("oracle timed out", reason_code="command_timed_out")
    if exit_code != 0:
        raise MendRuneError("oracle exited unsuccessfully", reason_code="candidate_oracle_invalid")

    root = output_root.resolve(strict=True)
    try:
        result = result_path.resolve(strict=True)
        result.relative_to(root)
    except (OSError, ValueError) as exc:
        raise MendRuneError(
            "oracle result is missing or escapes output root",
            reason_code="candidate_oracle_invalid",
        ) from exc
    if result_path.is_symlink() or not result.is_file() or result.stat().st_nlink != 1:
        raise MendRuneError(
            "oracle result must be one regular non-symlink file",
            reason_code="candidate_oracle_invalid",
        )
    data = result.read_bytes()
    if len(data) > MAX_ORACLE_BYTES:
        raise MendRuneError("oracle result is too large", reason_code="candidate_oracle_invalid")
    try:
        document = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise MendRuneError(
            "oracle result is invalid YAML", reason_code="candidate_oracle_invalid"
        ) from exc
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "nonce",
        "vulnerable",
        "observation",
    }:
        raise MendRuneError(
            "oracle result has an invalid schema", reason_code="candidate_oracle_invalid"
        )
    if document["schema_version"] != 1 or type(document["vulnerable"]) is not bool:
        raise MendRuneError(
            "oracle result has invalid field types", reason_code="candidate_oracle_invalid"
        )
    if document["nonce"] != expected_nonce:
        raise MendRuneError("oracle nonce mismatch", reason_code="candidate_oracle_invalid")
    observation = document["observation"]
    if not isinstance(observation, str) or len(observation.encode()) > MAX_OBSERVATION_BYTES:
        raise MendRuneError("oracle observation is invalid", reason_code="candidate_oracle_invalid")
    if document["vulnerable"] != expected_vulnerable:
        reason = (
            "vulnerability_not_reproduced" if expected_vulnerable else "exploit_still_effective"
        )
        raise MendRuneError(
            "oracle returned the unexpected vulnerability state", reason_code=reason
        )
    return OracleObservation(document["vulnerable"], observation)
