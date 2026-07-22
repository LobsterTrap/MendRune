"""Deterministic normalized scanner findings and comparison."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from mendrune.errors import MendRuneError

_SEMGREP_SEVERITIES = {"INFO": "info", "WARNING": "medium", "ERROR": "high"}
_SEMGREP_TOP_LEVEL_FIELDS = {
    "version",
    "results",
    "errors",
    "paths",
    "time",
    "engine_requested",
    "skipped_rules",
    "interfile_languages_used",
}


@dataclass(frozen=True)
class Finding:
    scanner_id: str
    rule_id: str
    severity: str
    path: PurePosixPath
    line: int | None
    fingerprint: str
    message: str

    @property
    def identity(self) -> tuple[str, str, str]:
        return self.scanner_id, self.rule_id, self.fingerprint


@dataclass(frozen=True)
class FindingDelta:
    prohibited: tuple[Finding, ...]
    introduced: tuple[Finding, ...]
    severity_increases: tuple[Finding, ...]

    @property
    def passed(self) -> bool:
        return not self.prohibited


def derive_fingerprint(
    scanner_id: str,
    rule_id: str,
    path: PurePosixPath,
    semantic_location: str,
    code_fingerprint: str,
) -> str:
    values = (scanner_id, rule_id, path.as_posix(), semantic_location, code_fingerprint)
    digest = hashlib.sha256()
    digest.update("\x00".join(values).encode("utf-8"))
    return digest.hexdigest()


def normalize_semgrep_json(
    output: bytes | str, severity_order: tuple[str, ...]
) -> tuple[Finding, ...]:
    """Strictly adapt Semgrep's native JSON output to canonical findings."""
    try:
        document: Any = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MendRuneError(
            "Semgrep output is invalid JSON", reason_code="scanner_output_invalid"
        ) from exc
    if (
        not isinstance(document, dict)
        or not {"version", "results", "errors", "paths"} <= document.keys()
        or set(document) - _SEMGREP_TOP_LEVEL_FIELDS
        or not isinstance(document["version"], str)
        or not isinstance(document["paths"], dict)
    ):
        raise MendRuneError(
            "Semgrep output has an invalid schema", reason_code="scanner_output_invalid"
        )
    results = document.get("results")
    errors = document.get("errors")
    if not isinstance(results, list) or not isinstance(errors, list) or errors:
        raise MendRuneError(
            "Semgrep output reports errors or has an invalid schema",
            reason_code="scanner_output_invalid",
        )
    findings = [_semgrep_finding(result) for result in results]
    return normalize_findings(findings, severity_order)


def normalize_findings(
    findings: list[Finding], severity_order: tuple[str, ...]
) -> tuple[Finding, ...]:
    ranks = _severity_ranks(severity_order)
    selected: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        _validate_finding(finding, ranks)
        current = selected.get(finding.identity)
        if current is None or _preference(finding, ranks) > _preference(current, ranks):
            selected[finding.identity] = finding
    return tuple(selected[key] for key in sorted(selected))


def compare_findings(
    previous: tuple[Finding, ...],
    current: tuple[Finding, ...],
    *,
    severity_order: tuple[str, ...],
    threshold: str,
) -> FindingDelta:
    ranks = _severity_ranks(severity_order)
    if threshold not in ranks:
        raise MendRuneError("unknown scan threshold", reason_code="scanner_output_invalid")
    old = {finding.identity: finding for finding in previous}
    introduced: list[Finding] = []
    increases: list[Finding] = []
    for finding in current:
        prior = old.get(finding.identity)
        if prior is None:
            introduced.append(finding)
        elif ranks[finding.severity] > ranks[prior.severity]:
            increases.append(finding)
    candidates = introduced + increases
    prohibited = [finding for finding in candidates if ranks[finding.severity] >= ranks[threshold]]

    def identity_key(finding: Finding) -> tuple[str, str, str]:
        return finding.identity

    return FindingDelta(
        prohibited=tuple(sorted(prohibited, key=identity_key)),
        introduced=tuple(sorted(introduced, key=identity_key)),
        severity_increases=tuple(sorted(increases, key=identity_key)),
    )


def _semgrep_finding(value: Any) -> Finding:
    if not isinstance(value, dict) or set(value) != {"check_id", "path", "start", "end", "extra"}:
        raise MendRuneError(
            "Semgrep result has an invalid schema", reason_code="scanner_output_invalid"
        )
    check_id, raw_path, start, extra = (
        value["check_id"],
        value["path"],
        value["start"],
        value["extra"],
    )
    if (
        not isinstance(check_id, str)
        or not check_id
        or not isinstance(raw_path, str)
        or not isinstance(start, dict)
        or set(start) != {"line", "col", "offset"}
        or type(start["line"]) is not int
        or start["line"] <= 0
        or not isinstance(extra, dict)
        or not {"message", "severity", "fingerprint"} <= extra.keys()
        or not isinstance(extra["message"], str)
        or not isinstance(extra["severity"], str)
        or not isinstance(extra["fingerprint"], str)
        or not extra["fingerprint"]
    ):
        raise MendRuneError(
            "Semgrep result has invalid field types", reason_code="scanner_output_invalid"
        )
    severity = _SEMGREP_SEVERITIES.get(extra["severity"])
    path = PurePosixPath(raw_path)
    if (
        severity is None
        or not raw_path
        or "\\" in raw_path
        or path.as_posix() != raw_path
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
    ):
        raise MendRuneError(
            "Semgrep result has invalid severity or path", reason_code="scanner_output_invalid"
        )
    return Finding(
        "semgrep",
        check_id,
        severity,
        path,
        start["line"],
        extra["fingerprint"],
        extra["message"],
    )


def _severity_ranks(order: tuple[str, ...]) -> dict[str, int]:
    if not order or len(order) != len(set(order)):
        raise MendRuneError("invalid severity order", reason_code="scanner_output_invalid")
    return {value: rank for rank, value in enumerate(order)}


def _validate_finding(finding: Finding, ranks: dict[str, int]) -> None:
    if finding.severity not in ranks or not finding.scanner_id or not finding.rule_id:
        raise MendRuneError("invalid normalized finding", reason_code="scanner_output_invalid")
    if not finding.fingerprint or finding.path.is_absolute() or ".." in finding.path.parts:
        raise MendRuneError("invalid finding identity", reason_code="scanner_output_invalid")
    if finding.line is not None and finding.line <= 0:
        raise MendRuneError("invalid finding line", reason_code="scanner_output_invalid")


def _preference(finding: Finding, ranks: dict[str, int]) -> tuple[int, int, str]:
    line_preference = -(finding.line or 2**31)
    return ranks[finding.severity], line_preference, finding.message
