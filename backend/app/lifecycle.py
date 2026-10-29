"""
Test Lifecycle State Machine for Bayora Systems.
States: Draft -> Ready -> Running -> Closed -> Results Released
Valid transitions:
- Draft -> Ready
- Ready -> Running
- Running -> Closed
- Closed -> Results Released

Rejected transitions fail safely without mutating state and are logged.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, Set, Tuple


class TestState(str, Enum):
    DRAFT = "Draft"
    READY = "Ready"
    RUNNING = "Running"
    CLOSED = "Closed"
    RESULTS_RELEASED = "Results Released"


VALID_TRANSITIONS: Dict[TestState, Set[TestState]] = {
    TestState.DRAFT: {TestState.READY},
    TestState.READY: {TestState.RUNNING},
    TestState.RUNNING: {TestState.CLOSED},
    TestState.CLOSED: {TestState.RESULTS_RELEASED},
    TestState.RESULTS_RELEASED: set(),
}


def validate_state_transition(current_state_raw: str, target_state: TestState) -> Tuple[bool, str, str]:
    """
    Validates whether transitioning from current_state_raw to target_state is allowed.
    Returns (is_valid, transition_label, reason_code).
    """
    transition_label = f"{current_state_raw}->{target_state.value}"
    try:
        current_state = TestState(current_state_raw)
    except ValueError:
        return False, transition_label, "STATE_UNKNOWN_CURRENT_STATE"

    allowed_targets = VALID_TRANSITIONS.get(current_state, set())
    if target_state not in allowed_targets:
        return False, transition_label, f"STATE_INVALID_TRANSITION_{current_state.name}_TO_{target_state.name}"

    return True, transition_label, "STATE_TRANSITION_VALID"
