"""Stable MendRune errors and process outcomes."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    CONFIGURATION_ERROR = 2
    VERIFICATION_FAILURE = 3
    INFRASTRUCTURE_ERROR = 4
    INTERNAL_ERROR = 5


class Outcome(StrEnum):
    ACCEPTED = "accepted"
    CONFIGURATION_ERROR = "configuration_error"
    BASELINE_FAILURE = "baseline_failure"
    ISOLATED_UNIT_FAILURE = "isolated_unit_failure"
    AMBIGUOUS_OVERLAP = "ambiguous_overlap"
    CUMULATIVE_FAILURE = "cumulative_failure"
    EVIDENCE_FAILURE = "evidence_failure"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    INTERNAL_ERROR = "internal_error"


class MendRuneError(Exception):
    """Base exception carrying a stable machine-readable reason code."""

    def __init__(self, message: str, *, reason_code: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class ConfigurationError(MendRuneError):
    """Campaign input is invalid before untrusted execution."""
