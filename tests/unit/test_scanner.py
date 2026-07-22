from pathlib import PurePosixPath

from mendrune.scanner import Finding, compare_findings, derive_fingerprint, normalize_findings

ORDER = ("info", "low", "medium", "high", "critical")


def finding(fingerprint: str, severity: str = "medium", line: int = 10) -> Finding:
    return Finding(
        scanner_id="semgrep",
        rule_id="rule",
        severity=severity,
        path=PurePosixPath("src/a.py"),
        line=line,
        fingerprint=fingerprint,
        message="finding",
    )


def test_fingerprint_is_stable() -> None:
    first = derive_fingerprint("s", "r", PurePosixPath("a.py"), "function:f", "code")
    second = derive_fingerprint("s", "r", PurePosixPath("a.py"), "function:f", "code")
    assert first == second
    assert len(first) == 64


def test_normalization_deduplicates_to_highest_severity() -> None:
    normalized = normalize_findings(
        [finding("same", "low", 20), finding("same", "high", 40)], ORDER
    )
    assert len(normalized) == 1
    assert normalized[0].severity == "high"


def test_comparison_rejects_new_finding_at_threshold() -> None:
    delta = compare_findings(
        (), (finding("new", "medium"),), severity_order=ORDER, threshold="medium"
    )
    assert not delta.passed
    assert delta.prohibited[0].fingerprint == "new"


def test_comparison_allows_new_finding_below_threshold() -> None:
    delta = compare_findings((), (finding("new", "low"),), severity_order=ORDER, threshold="medium")
    assert delta.passed
    assert delta.introduced


def test_severity_increase_counts_as_new() -> None:
    delta = compare_findings(
        (finding("same", "low"),),
        (finding("same", "high"),),
        severity_order=ORDER,
        threshold="medium",
    )
    assert not delta.passed
    assert delta.severity_increases[0].severity == "high"
