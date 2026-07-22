import pytest

from mendrune.errors import MendRuneError
from mendrune.state import TERMINAL_STATES, RunState, transition


def test_normal_state_path() -> None:
    states = [
        RunState.CREATED,
        RunState.VALIDATING,
        RunState.PREFLIGHT,
        RunState.CAPTURING_INPUTS,
        RunState.PHASE_A_BASELINE,
        RunState.PHASE_B_ISOLATED,
        RunState.PHASE_C_PREAPPLY,
        RunState.PHASE_C_APPLY,
        RunState.PHASE_C_VERIFY,
        RunState.FINAL_VERIFICATION,
        RunState.ASSEMBLING_EVIDENCE,
        RunState.ACCEPTED,
    ]
    current = states[0]
    for target in states[1:]:
        current = transition(current, target)
    assert current is RunState.ACCEPTED


def test_phase_loops_are_explicit() -> None:
    assert transition(RunState.PHASE_B_ISOLATED, RunState.PHASE_B_ISOLATED)
    assert transition(RunState.PHASE_C_VERIFY, RunState.PHASE_C_PREAPPLY)


@pytest.mark.parametrize("state", sorted(TERMINAL_STATES, key=str))
def test_terminal_states_cannot_transition(state: RunState) -> None:
    with pytest.raises(MendRuneError) as raised:
        transition(state, RunState.VALIDATING)
    assert raised.value.reason_code == "illegal_state_transition"


def test_illegal_transition_fails() -> None:
    with pytest.raises(MendRuneError):
        transition(RunState.CREATED, RunState.ACCEPTED)
