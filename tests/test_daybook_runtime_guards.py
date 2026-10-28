"""Original same-day windows, quiet-stop, profile identity and drain predicates."""

from __future__ import annotations

import importlib
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.daybook_operations_runtime.guards import (
    JournalEvidence,
    RuntimeGuardError,
    StopState,
    require_profile_transition,
    require_stop_ready,
    require_stop_window,
)
from ops_deploy.services.daybook_operations_runtime.render import render_resource
from ops_deploy.services.daybook_operations_runtime.status import SourceStatus
from tests.test_daybook_runtime_contract import config

WINDOWS = [{"start": "07:15", "end": "08:45"}, {"start": "19:15", "end": "20:45"}]


@pytest.mark.parametrize(
    ("clock", "blocked"),
    [
        ("06:54", False),
        ("06:55", True),
        ("07:15", True),
        ("08:44", True),
        ("08:45", False),
        ("18:54", False),
        ("18:55", True),
        ("20:44", True),
        ("20:45", False),
        ("unavailable", True),
    ],
)
def test_original_twenty_minute_lead_and_end_exclusion(clock: str, blocked: bool) -> None:
    if blocked:
        with pytest.raises(RuntimeGuardError):
            require_stop_window(WINDOWS, 20, clock, running=True)
    else:
        require_stop_window(WINDOWS, 20, clock, running=True)
    require_stop_window(WINDOWS, 20, clock, running=False)


@pytest.mark.parametrize(
    ("windows", "lead"),
    [
        ([{"start": "00:15", "end": "01:00"}], 20),
        ([{"start": "23:00", "end": "01:00"}], 0),
        ([{"start": "07:00", "end": "07:00"}], 0),
        ([{"start": "7:00", "end": "08:00"}], 0),
        (WINDOWS, -1),
        (WINDOWS, True),
    ],
)
def test_bad_window_refused_even_for_stopped_recovery(windows: list[dict[str, str]], lead: int) -> None:
    with pytest.raises(RuntimeGuardError):
        require_stop_window(windows, lead, "06:00", running=False)


def quiet() -> StopState:
    source = SourceStatus("regular", True, None, False, 0, False)
    return StopState(True, True, True, True, True, True, 0, 0, (source,))


def test_stop_requires_quiet_owned_keeper_and_original_capability_host() -> None:
    cfg = config(mode="host", action="stop", confirmed=True)
    require_stop_ready(cfg, quiet())
    for state in (
        replace(quiet(), aqua=False),
        replace(quiet(), label_runs_keeper=False),
        replace(quiet(), capability_host=False),
        replace(quiet(), store_readable=False),
        replace(quiet(), halts=1),
        replace(quiet(), deliveries=1),
        replace(quiet(), sources=()),
        replace(quiet(), sources=quiet().sources * 2),
        replace(quiet(), sources=(replace(quiet().sources[0], active_state="assigned"),)),
        replace(quiet(), sources=(replace(quiet().sources[0], active_state="awaiting_apply"),)),
    ):
        with pytest.raises(RuntimeGuardError):
            require_stop_ready(cfg, state)
    with pytest.raises(RuntimeGuardError, match="host_mode"):
        require_stop_ready(config(action="stop", confirmed=True), quiet())


def test_stopped_recovery_can_finish_but_preflight_still_reports_busy() -> None:
    cfg = config(mode="host", action="stop", confirmed=True)
    stopped = replace(quiet(), label_loaded=False, serving=False, capability_host=False, deliveries=1, sources=())
    require_stop_ready(cfg, stopped)
    with pytest.raises(RuntimeGuardError, match="unanswered"):
        require_stop_ready(cfg, stopped, preflight=True)
    with pytest.raises(RuntimeGuardError, match="halted"):
        require_stop_ready(cfg, replace(stopped, halts=1))


def previous(**values: Any) -> dict[str, Any]:
    return {**json.loads(render_resource(config(), "policy.json.j2")), **values}


def test_current_profile_identity_kinds_store_and_disabled_install() -> None:
    cfg = config()
    require_profile_transition(cfg, None, closed_out=False, label_loaded=False, serving=False)
    require_profile_transition(cfg, previous(), closed_out=False, label_loaded=False, serving=False)
    for profile in (
        previous(enabled=True),
        previous(enabled="false"),
        previous(schema=6),
        previous(schema=True),
        previous(api_url="https://other.test"),
        previous(journal="/another/store"),
        previous(kinds=[{"adapter": "sessions.ship.v1"}]),
        previous(schema=3),
    ):
        with pytest.raises(RuntimeGuardError):
            require_profile_transition(cfg, profile, closed_out=False, label_loaded=False, serving=False)
    with pytest.raises(RuntimeGuardError, match="closed_out"):
        require_profile_transition(
            config(action="rollback", confirmed=True), previous(), closed_out=True, label_loaded=False, serving=False
        )


def test_replace_proves_old_directory_and_every_record_and_halt_drained() -> None:
    cfg = config(action="replace", confirmed=True)
    journal = JournalEvidence(str(cfg.journal), True, deliveries_directory_exists=True, halts_directory_exists=True)
    require_profile_transition(
        cfg, previous(enabled=True), closed_out=False, label_loaded=False, serving=False, journals=[journal]
    )
    for evidence in (
        [],
        [replace(journal, directory_exists=False)],
        [replace(journal, deliveries_directory_exists=False)],
        [replace(journal, halts_directory_exists=False)],
        [replace(journal, json_entries=1)],
    ):
        with pytest.raises(RuntimeGuardError):
            require_profile_transition(
                cfg, previous(), closed_out=False, label_loaded=False, serving=False, journals=evidence
            )
    with pytest.raises(RuntimeGuardError, match="quiescence"):
        require_profile_transition(
            cfg, previous(), closed_out=False, label_loaded=False, serving=True, journals=[journal]
        )


def test_legacy_slot_idle_lock_halt_and_missing_evidence_exact_contract() -> None:
    cfg = config(action="replace", confirmed=True)
    profile = {"schema": 1, "enabled": False, "api_url": cfg.api_url, "journal": "/legacy"}
    for evidence in (JournalEvidence("/legacy", True), JournalEvidence("/legacy", True, True, True, True)):
        require_profile_transition(
            cfg, profile, closed_out=False, label_loaded=False, serving=False, journals=[evidence]
        )
    for evidence in (
        JournalEvidence("/legacy", False),
        JournalEvidence("/legacy", True, lock_exists=True),
        JournalEvidence("/legacy", True, True, False),
        JournalEvidence("/legacy", True, halt_exists=True),
    ):
        with pytest.raises(RuntimeGuardError):
            require_profile_transition(
                cfg, profile, closed_out=False, label_loaded=False, serving=False, journals=[evidence]
            )


def test_window_predicate_matches_actual_original_role_expression() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Actual paired role oracle is run explicitly during qualification")
    import jinja2
    import yaml

    role = Path(source) / "roles/daybook_operations_runtime_deploy"
    tasks = yaml.safe_load((role / "tasks/stop_window.yml").read_text())
    expression = next(
        t["ansible.builtin.set_fact"]["daybook_operations_runtime_stop_window"]
        for t in tasks
        if "ansible.builtin.set_fact" in t
    )
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters.update(importlib.import_module("ansible.plugins.filter.core").FilterModule().filters())
    env.tests.update(importlib.import_module("ansible.plugins.test.core").TestModule().tests())
    for clock in ("06:54", "06:55", "08:45", "18:55", "20:45", "unavailable"):
        original = env.from_string(expression).render(
            daybook_operations_runtime_stop_windows=WINDOWS,
            daybook_operations_runtime_stop_window_lead_minutes=20,
            daybook_operations_runtime_stop_window_timezone="Europe/Berlin",
            daybook_operations_runtime_stop_clock={"stdout": clock},
        )
        if original:
            with pytest.raises(RuntimeGuardError):
                require_stop_window(WINDOWS, 20, clock, running=True)
        else:
            require_stop_window(WINDOWS, 20, clock, running=True)
