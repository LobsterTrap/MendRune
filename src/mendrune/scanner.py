"""Deterministic normalized scanner findings and comparison."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import PurePosixPath

from mendrune.errors import MendRuneError


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
