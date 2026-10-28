"""Original managed-transition predicates; no app, API, Journal or host call."""

from __future__ import annotations

from typing import Any

import pytest

from ops_deploy.services.daybook_operations_runtime.guards import (
    RuntimeGuardError,
    TransitionStatus,
    parse_transition_status,
    require_start_status,
    require_transition_status,
)


def response(**values: Any) -> dict[str, Any]:
    return {"enabled": False, "status": "idle", "server": {"enabled": True, "active_state": None}, **values}


def test_parser_keeps_only_the_original_four_transition_fields() -> None:
    body = response(private="UNUSABLE-OWNED-DISCARD")
    state = parse_transition_status(body)
    assert state == TransitionStatus(False, "idle", None, True)
    assert "UNUSABLE" not in repr(state)


@pytest.mark.parametrize(
    "value",
    [
        response(enabled="false"),
        response(server={"enabled": "true", "active_state": None}),
        response(server={"enabled": True, "active_state": "PRIVATE-UNEXPECTED"}),
        response(server={}),
        response(status=[]),
        response(status="PRIVATE-UNEXPECTED"),
        {},
    ],
)
def test_invalid_aggregate_metadata_fails_with_fixed_category(value: dict[str, Any]) -> None:
    with pytest.raises(RuntimeGuardError, match=r"^runtime_transition_status_invalid$"):
        parse_transition_status(value)


@pytest.mark.parametrize("status", ["idle", "awaiting", "blocked"])
def test_original_cutover_preserves_reconciled_intermediate_states(status: str) -> None:
    require_transition_status("cutover", TransitionStatus(False, status, None, True))


@pytest.mark.parametrize(
    "state",
    [
        TransitionStatus(True, "idle", None, True),
        TransitionStatus(False, "unknown", None, True),
        TransitionStatus(False, "idle", "assigned", True),
        TransitionStatus(False, "idle", "awaiting_apply", True),
    ],
)
def test_cutover_refuses_original_active_or_unreconciled_state(state: TransitionStatus) -> None:
    with pytest.raises(RuntimeGuardError, match=r"^runtime_existing_state_not_reconciled$"):
        require_transition_status("cutover", state)


def test_rollback_preserves_original_server_disabled_requirement() -> None:
    require_transition_status("rollback", TransitionStatus(True, "idle", None, False))
    with pytest.raises(RuntimeGuardError, match="existing_state_not_reconciled"):
        require_transition_status("rollback", TransitionStatus(True, "idle", None, True))


@pytest.mark.parametrize(
    ("action", "state"),
    [
        ("cutover", TransitionStatus(True, "idle", None, True)),
        ("rollback", TransitionStatus(False, "blocked", None, False)),
    ],
)
def test_original_start_ready_aggregate(action: str, state: TransitionStatus) -> None:
    require_start_status(action, state)


@pytest.mark.parametrize(
    ("action", "state"),
    [
        ("cutover", TransitionStatus(True, "blocked", None, True)),
        ("cutover", TransitionStatus(True, "idle", "pending", True)),
        ("cutover", TransitionStatus(True, "idle", None, False)),
        ("rollback", TransitionStatus(False, "idle", None, True)),
    ],
)
def test_start_refuses_without_all_original_local_remote_readiness(action: str, state: TransitionStatus) -> None:
    with pytest.raises(RuntimeGuardError, match=r"^runtime_start_not_reconciled$"):
        require_start_status(action, state)
