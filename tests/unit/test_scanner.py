import json
import os
from pathlib import PurePosixPath

import pytest

from mendrune.errors import MendRuneError
from mendrune.scanner import (
    Finding,
    compare_findings,
    derive_fingerprint,
    normalize_findings,
    normalize_semgrep_json,
    read_scanner_output,
)

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


def semgrep_result(
    *, path: str = "src/a.py", severity: str = "WARNING", fingerprint: str = "stable"
) -> dict[str, object]:
    return {
        "check_id": "python.security.rule",
        "path": path,
        "start": {"line": 12, "col": 1, "offset": 100},
        "end": {"line": 12, "col": 5, "offset": 104},
        "extra": {
            "message": "unsafe call",
            "severity": severity,
            "fingerprint": fingerprint,
            "lines": "unsafe()",
            "metadata": {},
        },
    }


def semgrep_output(results: list[dict[str, object]]) -> str:
    return json.dumps({"version": "1.100.0", "results": results, "errors": [], "paths": {}})


def test_semgrep_adapter_produces_deterministic_canonical_findings() -> None:
    low = semgrep_result(severity="INFO", fingerprint="z")
    duplicate = semgrep_result(severity="ERROR", fingerprint="z")
    first = semgrep_result(path="src/z.py", fingerprint="a")
    normalized = normalize_semgrep_json(
        semgrep_output([low, duplicate, first]), "configured", ORDER
    )
    assert [(item.fingerprint, item.severity, item.path.as_posix()) for item in normalized] == [
        ("a", "medium", "src/z.py"),
        ("z", "high", "src/a.py"),
    ]
    assert normalized[0].scanner_id == "configured"
    assert normalized[0].rule_id == "python.security.rule"
    assert normalized[0].line == 12


@pytest.mark.parametrize("output", [b"not JSON", "[]", '{"results": [], "errors": []}'])
def test_semgrep_adapter_rejects_malformed_output(output: bytes | str) -> None:
    with pytest.raises(MendRuneError, match="Semgrep output") as error:
        normalize_semgrep_json(output, "configured", ORDER)
    assert error.value.reason_code == "scanner_output_invalid"


@pytest.mark.parametrize(
    ("field", "value"),
    [("path", "/tmp/a.py"), ("path", "../a.py"), ("severity", "CRITICAL")],
)
def test_semgrep_adapter_rejects_invalid_path_or_severity(field: str, value: str) -> None:
    result = semgrep_result()
    if field == "severity":
        extra = result["extra"]
        assert isinstance(extra, dict)
        result["extra"] = {**extra, "severity": value}
    else:
        result[field] = value
    with pytest.raises(MendRuneError, match="invalid severity or path") as error:
        normalize_semgrep_json(semgrep_output([result]), "configured", ORDER)
    assert error.value.reason_code == "scanner_output_invalid"


def test_semgrep_adapter_rejects_reported_errors_and_result_schema() -> None:
    reported_error = json.dumps(
        {
            "version": "1.100.0",
            "results": [],
            "errors": [{"message": "parse failed"}],
            "paths": {},
        }
    )
    with pytest.raises(MendRuneError, match="reports errors"):
        normalize_semgrep_json(reported_error, "configured", ORDER)
    result = semgrep_result()
    del result["end"]
    with pytest.raises(MendRuneError, match="invalid schema"):
        normalize_semgrep_json(semgrep_output([result]), "configured", ORDER)


def test_semgrep_adapter_preserves_configured_scanner_identity() -> None:
    output = semgrep_output([semgrep_result()])
    first = normalize_semgrep_json(output, "first", ORDER)
    second = normalize_semgrep_json(output, "second", ORDER)
    combined = normalize_findings([*first, *second], ORDER)
    assert [item.scanner_id for item in combined] == ["first", "second"]


def test_scanner_output_reader_rejects_links_and_oversize(tmp_path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    result = output / "result.json"
    result.write_bytes(b"{}")
    assert read_scanner_output(output, result, 2) == b"{}"

    result.unlink()
    target = tmp_path / "target"
    target.write_bytes(b"{}")
    result.symlink_to(target)
    with pytest.raises(MendRuneError, match="unsafe"):
        read_scanner_output(output, result, 2)

    result.unlink()
    result.write_bytes(b"too large")
    with pytest.raises(MendRuneError, match="byte cap"):
        read_scanner_output(output, result, 2)


def test_scanner_output_reader_rejects_hard_links(tmp_path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    result = output / "result.json"
    result.write_bytes(b"{}")
    os.link(result, output / "second.json")
    with pytest.raises(MendRuneError, match="unsafe"):
        read_scanner_output(output, result, 2)


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
