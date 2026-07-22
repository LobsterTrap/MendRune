"""Deterministic rendering of persisted run evidence."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from mendrune.errors import MendRuneError
from mendrune.runstore import RunStore

LIMITATIONS = (
    "Acceptance does not prove the absence of all vulnerabilities or regressions.",
    "Oracles, tests, scanners, toolchains, and isolation may have blind spots or defects.",
)
_MAX_RECORD_BYTES = 4 * 1024 * 1024


def render_status(store: RunStore) -> str:
    """Render the persisted run record without performing verification work."""
    return _dump(_read_record(store, "run.yaml"))


def render_report(store: RunStore) -> str:
    """Render a report derived exclusively from persisted run and verdict records."""
    run = _read_record(store, "run.yaml")
    verdict = _read_optional_record(store, "final/verdict.yaml")
    report: dict[str, Any] = {
        "schema_version": 1,
        "run": run,
        "verdict": verdict,
        "limitations": list(LIMITATIONS),
    }
    return _dump(report)


def status(runs_root: Path, run_id: str) -> str:
    """Convenience entry point for a future CLI status command."""
    return render_status(RunStore(runs_root, run_id))


def report(runs_root: Path, run_id: str) -> str:
    """Convenience entry point for a future CLI report command."""
    return render_report(RunStore(runs_root, run_id))


def _read_optional_record(store: RunStore, relative: str) -> dict[str, Any] | None:
    try:
        return _read_record(store, relative)
    except MendRuneError as exc:
        if exc.reason_code == "artifact_missing":
            return None
        raise


def _read_record(store: RunStore, relative: str) -> dict[str, Any]:
    artifact = store.artifact(relative)
    if artifact.size > _MAX_RECORD_BYTES:
        raise MendRuneError(
            f"stored record exceeds reporting limit: {relative}",
            reason_code="provenance_incomplete",
        )
    try:
        document = yaml.safe_load(artifact.path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise MendRuneError(
            f"stored record is unreadable or invalid: {relative}",
            reason_code="provenance_incomplete",
        ) from exc
    if not isinstance(document, Mapping) or not _has_string_keys(document):
        raise MendRuneError(
            f"stored record is invalid: {relative}",
            reason_code="provenance_incomplete",
        )
    return dict(document)


def _has_string_keys(value: object) -> bool:
    if isinstance(value, Mapping):
        return all(isinstance(key, str) and _has_string_keys(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_has_string_keys(item) for item in value)
    return True


def _dump(document: object) -> str:
    return yaml.safe_dump(document, sort_keys=True, allow_unicode=True)
