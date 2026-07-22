"""Explicit persisted run-state transitions."""

from __future__ import annotations

from enum import StrEnum

from mendrune.errors import MendRuneError


class RunState(StrEnum):
    CREATED = "created"
    VALIDATING = "validating"
    PREFLIGHT = "preflight"
    CAPTURING_INPUTS = "capturing_inputs"
    PHASE_A_BASELINE = "phase_a_baseline"
    PHASE_B_ISOLATED = "phase_b_isolated"
    PHASE_C_PREAPPLY = "phase_c_preapply"
    PHASE_C_APPLY = "phase_c_apply"
    PHASE_C_VERIFY = "phase_c_verify"
    FINAL_VERIFICATION = "final_verification"
    ASSEMBLING_EVIDENCE = "assembling_evidence"
    ACCEPTED = "accepted"
    CONFIGURATION_ERROR = "configuration_error"
    BASELINE_FAILURE = "baseline_failure"
    ISOLATED_UNIT_FAILURE = "isolated_unit_failure"
    AMBIGUOUS_OVERLAP = "ambiguous_overlap"
    CUMULATIVE_FAILURE = "cumulative_failure"
    EVIDENCE_FAILURE = "evidence_failure"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    INTERNAL_ERROR = "internal_error"


_FAILURES = {
    RunState.CONFIGURATION_ERROR,
    RunState.BASELINE_FAILURE,
    RunState.ISOLATED_UNIT_FAILURE,
    RunState.AMBIGUOUS_OVERLAP,
    RunState.CUMULATIVE_FAILURE,
    RunState.EVIDENCE_FAILURE,
    RunState.INFRASTRUCTURE_ERROR,
    RunState.INTERNAL_ERROR,
}
TERMINAL_STATES = _FAILURES | {RunState.ACCEPTED}

_ALLOWED: dict[RunState, set[RunState]] = {
    RunState.CREATED: {RunState.VALIDATING, RunState.CONFIGURATION_ERROR},
    RunState.VALIDATING: {RunState.PREFLIGHT, RunState.CONFIGURATION_ERROR},
    RunState.PREFLIGHT: {RunState.CAPTURING_INPUTS, RunState.INFRASTRUCTURE_ERROR},
    RunState.CAPTURING_INPUTS: {
        RunState.PHASE_A_BASELINE,
        RunState.EVIDENCE_FAILURE,
        RunState.INTERNAL_ERROR,
    },
    RunState.PHASE_A_BASELINE: {
        RunState.PHASE_B_ISOLATED,
        RunState.BASELINE_FAILURE,
        RunState.INFRASTRUCTURE_ERROR,
    },
    RunState.PHASE_B_ISOLATED: {
        RunState.PHASE_B_ISOLATED,
        RunState.PHASE_C_PREAPPLY,
        RunState.ISOLATED_UNIT_FAILURE,
        RunState.INFRASTRUCTURE_ERROR,
    },
    RunState.PHASE_C_PREAPPLY: {
        RunState.PHASE_C_APPLY,
        RunState.AMBIGUOUS_OVERLAP,
        RunState.CUMULATIVE_FAILURE,
    },
    RunState.PHASE_C_APPLY: {
        RunState.PHASE_C_VERIFY,
        RunState.CUMULATIVE_FAILURE,
    },
    RunState.PHASE_C_VERIFY: {
        RunState.PHASE_C_PREAPPLY,
        RunState.FINAL_VERIFICATION,
        RunState.CUMULATIVE_FAILURE,
        RunState.INFRASTRUCTURE_ERROR,
    },
    RunState.FINAL_VERIFICATION: {
        RunState.ASSEMBLING_EVIDENCE,
        RunState.CUMULATIVE_FAILURE,
        RunState.EVIDENCE_FAILURE,
    },
    RunState.ASSEMBLING_EVIDENCE: {
        RunState.ACCEPTED,
        RunState.EVIDENCE_FAILURE,
        RunState.INTERNAL_ERROR,
    },
}


def transition(current: RunState, target: RunState) -> RunState:
    if current in TERMINAL_STATES or target not in _ALLOWED.get(current, set()):
        raise MendRuneError(
            f"illegal state transition: {current} -> {target}",
            reason_code="illegal_state_transition",
        )
    return target
