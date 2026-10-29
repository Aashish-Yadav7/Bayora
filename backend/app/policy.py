"""
Access Control & Disclosure Policy Engine for Bayora Systems.
Enforces:
- Role-based access control (RBAC) for RED_TEAM, BLUE_TEAM, EVALUATOR
- Artifact isolation (SEC-01: Red cannot read Blue defenses; SEC-02: Blue cannot read Red payloads)
- Evaluator-only result release (SEC-03)
- Pre-release vs post-release result field disclosure (DATA-01, POS-02)
- Immutability of Closed / Results Released tests
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Set, Tuple

from .auth import Role
from .lifecycle import TestState


PERMITTED_CREATOR_ROLES: Set[Role] = {Role.EVALUATOR, Role.RED_TEAM}
PERMITTED_READY_ROLES: Set[Role] = {Role.EVALUATOR, Role.RED_TEAM, Role.BLUE_TEAM}
PERMITTED_START_ROLES: Set[Role] = {Role.EVALUATOR, Role.RED_TEAM}
PERMITTED_CLOSE_ROLES: Set[Role] = {Role.EVALUATOR}
PERMITTED_RELEASE_ROLES: Set[Role] = {Role.EVALUATOR}


def check_can_create_test(role: Role) -> Tuple[bool, str]:
    if role in PERMITTED_CREATOR_ROLES:
        return True, "POLICY_ALLOW_CREATE_TEST"
    return False, "POLICY_DENY_CREATE_TEST_ROLE"


def check_can_submit_red_payload(role: Role, current_state: str) -> Tuple[bool, str]:
    if role != Role.RED_TEAM:
        return False, "POLICY_DENY_NOT_RED_TEAM"
    if current_state in (TestState.CLOSED.value, TestState.RESULTS_RELEASED.value):
        return False, "POLICY_DENY_TEST_IMMUTABLE_WHEN_CLOSED"
    if current_state not in (TestState.DRAFT.value, TestState.READY.value):
        return False, "POLICY_DENY_INVALID_STATE_FOR_PAYLOAD_SUBMISSION"
    return True, "POLICY_ALLOW_RED_PAYLOAD_WRITE"


def check_can_read_red_payloads(role: Role, current_state: str) -> Tuple[bool, str]:
    """
    SEC-02: Blue Team (and any non-Red role) must NEVER read raw Red Team payloads.
    Fail closed without returning the payload in the error body.
    """
    if role == Role.RED_TEAM:
        return True, "POLICY_ALLOW_RED_PAYLOAD_READ"
    if role == Role.BLUE_TEAM:
        return False, "SEC_02_BLUE_READ_RED_PAYLOAD_DENIED"
    return False, "SEC_02_NON_RED_READ_PAYLOAD_DENIED"


def check_can_submit_blue_defense(role: Role, current_state: str) -> Tuple[bool, str]:
    if role != Role.BLUE_TEAM:
        return False, "POLICY_DENY_NOT_BLUE_TEAM"
    if current_state in (TestState.CLOSED.value, TestState.RESULTS_RELEASED.value):
        return False, "POLICY_DENY_TEST_IMMUTABLE_WHEN_CLOSED"
    if current_state not in (TestState.DRAFT.value, TestState.READY.value):
        return False, "POLICY_DENY_INVALID_STATE_FOR_DEFENSE_SUBMISSION"
    return True, "POLICY_ALLOW_BLUE_DEFENSE_WRITE"


def check_can_read_blue_defenses(role: Role, current_state: str) -> Tuple[bool, str]:
    """
    SEC-01: Red Team (and any non-Blue role) must NEVER read unreleased Blue defense artifacts.
    Fail closed without returning the defense artifact in the error body.
    """
    if role == Role.BLUE_TEAM:
        return True, "POLICY_ALLOW_BLUE_DEFENSE_READ"
    if role == Role.RED_TEAM:
        return False, "SEC_01_RED_READ_BLUE_DEFENSE_DENIED"
    return False, "SEC_01_NON_BLUE_READ_DEFENSE_DENIED"


def check_can_ready_test(role: Role) -> Tuple[bool, str]:
    if role in PERMITTED_READY_ROLES:
        return True, "POLICY_ALLOW_READY_TEST"
    return False, "POLICY_DENY_READY_TEST_ROLE"


def check_can_start_test(role: Role) -> Tuple[bool, str]:
    if role in PERMITTED_START_ROLES:
        return True, "POLICY_ALLOW_START_TEST"
    return False, "POLICY_DENY_START_TEST_ROLE"


def check_can_close_test(role: Role) -> Tuple[bool, str]:
    if role in PERMITTED_CLOSE_ROLES:
        return True, "POLICY_ALLOW_CLOSE_TEST"
    return False, "POLICY_DENY_CLOSE_TEST_ROLE"


def check_can_release_results(role: Role) -> Tuple[bool, str]:
    """
    SEC-03: Only EVALUATOR can release results.
    """
    if role in PERMITTED_RELEASE_ROLES:
        return True, "POLICY_ALLOW_RELEASE_RESULTS"
    return False, "SEC_03_NON_EVALUATOR_RELEASE_DENIED"


def filter_result_fields_by_disclosure_policy(
    test_row: Dict[str, Any],
    result_row: Dict[str, Any] | None,
    requester_role: Role,
) -> Dict[str, Any]:
    """
    DATA-01 & POS-02:
    Before state == 'Results Released', only policy-allowed non-sensitive status fields are returned.
    After state == 'Results Released', approved evaluation metrics are returned while raw Red payloads
    and raw Blue defense secrets remain permanently withheld.
    """
    state = test_row["state"]
    is_released = state == TestState.RESULTS_RELEASED.value

    if not is_released or result_row is None:
        return {
            "test_id": test_row["id"],
            "test_name": test_row["name"],
            "state": state,
            "results_released": False,
            "run_id": test_row.get("current_run_id"),
            "adapter_mode": test_row["adapter_mode"],
            "is_mock_adapter": "MOCK" in str(test_row["adapter_mode"]),
            "disclosure_policy": "WITHHELD_PENDING_EVALUATOR_RELEASE",
            "disclosure_notice": (
                "Evaluation metrics and probe outcomes are withheld by policy until "
                "the test reaches 'Results Released' state via EVALUATOR approval."
            ),
            "approved_metrics": None,
        }

    target_config = json.loads(result_row["target_config_json"])
    probe_outcomes = json.loads(result_row["probe_outcomes_json"])

    return {
        "test_id": test_row["id"],
        "test_name": test_row["name"],
        "state": state,
        "results_released": True,
        "run_id": result_row["run_id"],
        "session_id": result_row["session_id"],
        "context_hash": result_row["context_hash"],
        "adapter_type": result_row["adapter_type"],
        "is_mock_adapter": bool(result_row["is_mock"]),
        "adapter_label": ("MOCK_LLM_ADAPTER (DETERMINISTIC — NOT A REAL MODEL)" if result_row["is_mock"] else f"REAL ADAPTER: {result_row['adapter_type']}"),
        "target_config": target_config,
        "disclosure_policy": "APPROVED_SUMMARY_RELEASED_SECRETS_WITHHELD",
        "approved_metrics": {
            "total_probes": result_row["total_probes"],
            "blocked_count": result_row["blocked_count"],
            "bypassed_count": result_row["bypassed_count"],
            "resilience_score": result_row["resilience_score"],
            "execution_ms": result_row["execution_ms"],
            "run_status": result_row["run_status"],
            "summary_notes": result_row["summary_notes"],
            "probe_outcomes": probe_outcomes,
        },
    }
