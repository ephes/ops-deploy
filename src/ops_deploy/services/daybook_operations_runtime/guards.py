"""Original transition predicates, separated from mutation and application I/O.

These guards consume observations made by the runtime adapter. They never open a
Journal, poll the server, signal a process or modify a profile. A later operation
must recheck the run window immediately before the original keeper bootout.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .config import DaybookRuntimeConfig
    from .status import SourceStatus


class RuntimeGuardError(RuntimeError):
    """Fixed operational category; no profile, record or response body is exposed."""


def minute(value: str) -> int:
    if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value):
        raise RuntimeGuardError("runtime_clock_or_window_invalid")
    hour, part = value.split(":")
    return int(hour) * 60 + int(part)


def require_stop_window(windows: Sequence[Mapping[str, str]], lead: int, clock: str, *, running: bool) -> None:
    """Original same-day minute guard, including the already-stopped recovery.

    Clock is supplied by the machine's date command with the declared timezone.
    Even a stopped recovery refuses a malformed declaration; it can ignore an
    unavailable clock because it will not stop a running process.
    """
    if type(lead) is not int or lead < 0:
        raise RuntimeGuardError("runtime_window_lead_invalid")
    intervals = []
    for window in windows:
        if set(window) != {"start", "end"}:
            raise RuntimeGuardError("runtime_window_invalid")
        start, end = minute(window["start"]), minute(window["end"])
        if start - lead < 0 or start >= end:
            raise RuntimeGuardError("runtime_window_must_fit_one_day")
        intervals.append((start - lead, end))
    if not running or not intervals:
        return
    current = minute(clock)
    if any(start <= current < end for start, end in intervals):
        raise RuntimeGuardError("runtime_run_window_near_or_active")


@dataclass(frozen=True)
class StopState:
    aqua: bool
    label_loaded: bool
    label_runs_keeper: bool
    serving: bool
    capability_host: bool
    store_readable: bool
    halts: int
    deliveries: int
    sources: tuple[SourceStatus, ...]

    @property
    def running(self) -> bool:
        return self.label_loaded or self.serving


def require_stop_prerequisites(cfg: DaybookRuntimeConfig, state: StopState) -> None:
    """Original checks before quiet waits, without claiming readiness yet."""
    if cfg.mode != "host":
        raise RuntimeGuardError("runtime_stop_requires_host_mode")
    if not state.aqua:
        raise RuntimeGuardError("runtime_aqua_unavailable")
    if state.label_loaded and not state.label_runs_keeper:
        raise RuntimeGuardError("runtime_loaded_label_not_keeper")
    if state.running and not state.capability_host:
        raise RuntimeGuardError("runtime_capability_host_unavailable")
    if not state.store_readable or state.halts != 0:
        raise RuntimeGuardError("runtime_store_halted_or_unreadable")


def require_stop_ready(cfg: DaybookRuntimeConfig, state: StopState, *, preflight: bool = False) -> None:
    """Original pre-mutation quiescence requirements, not a stop implementation.

    Sources supplied here come from the explicitly accounted original transition
    observation. Pure monitor data must not silently replace its expiry semantics.
    The observation is never inferred read-only merely because this predicate is.
    """
    require_stop_prerequisites(cfg, state)
    if state.running or preflight:
        names = [source.binding for source in state.sources]
        if len(names) != len(set(names)) or set(names) != set(cfg.status_sources):
            raise RuntimeGuardError("runtime_transition_sources_unanswered")
        if state.deliveries != 0 or any(s.active_state in {"assigned", "awaiting_apply"} for s in state.sources):
            raise RuntimeGuardError("runtime_machine_holds_work")


@dataclass(frozen=True)
class JournalEvidence:
    """Directory/slot metadata only, never delivery contents in a report.

    Legacy slot_idle is evaluated in memory by the transition reader. The pure
    verifier uses only current store directory metadata and never opens a slot.
    """

    path: str
    directory_exists: bool
    slot_exists: bool = False
    slot_idle: bool = False
    lock_exists: bool = False
    halt_exists: bool = False
    deliveries_directory_exists: bool = False
    halts_directory_exists: bool = False
    json_entries: int = 0


def require_profile_transition(
    cfg: DaybookRuntimeConfig,
    previous: Mapping[str, Any] | None,
    *,
    closed_out: bool,
    label_loaded: bool,
    serving: bool,
    journals: Sequence[JournalEvidence] = (),
    check_journals: bool = True,
) -> None:
    """Preserve original profile identity, store, kinds and replace drain proof."""
    if cfg.action == "rollback" and closed_out:
        raise RuntimeGuardError("runtime_closed_out_rollback_refused")
    if previous is None:
        if cfg.action != "install":
            raise RuntimeGuardError("runtime_disabled_staging_required")
        return
    try:
        schema = previous["schema"]
        if type(schema) is not int or schema not in {1, 2, 3, 4, 5}:
            raise RuntimeGuardError("runtime_previous_schema_unknown")
        enabled = previous["enabled"]
        if type(enabled) is not bool:
            raise RuntimeGuardError("runtime_previous_profile_invalid")
        if cfg.action == "install" and enabled:
            raise RuntimeGuardError("runtime_install_over_enabled_refused")
        if previous["api_url"] != cfg.api_url:
            raise RuntimeGuardError("runtime_profile_identity_changed")
        if "kinds" in previous:
            kinds = {kind["adapter"] for kind in previous["kinds"]}
        elif "bindings" in previous:
            kinds = {binding["adapter"] for binding in previous["bindings"]}
        else:
            kinds = {"voice_memos.ingest.v1"}
        paths = (
            [binding["journal"] for binding in previous["bindings"]]
            if schema < 3 and "bindings" in previous
            else [previous["journal"]]
        )
        if kinds - {kind.adapter for kind in cfg.kinds}:
            raise RuntimeGuardError("runtime_kind_removal_refused")
        if schema >= 3 and paths != [str(cfg.journal)]:
            raise RuntimeGuardError("runtime_store_move_refused")
        if schema not in {4, 5} and cfg.action != "replace":
            raise RuntimeGuardError("runtime_store_shape_requires_replace")
    except (KeyError, TypeError):
        raise RuntimeGuardError("runtime_previous_profile_invalid") from None
    if cfg.action != "replace":
        return
    if label_loaded or serving:
        raise RuntimeGuardError("runtime_replace_requires_quiescence")
    if not check_journals:
        return
    if {journal.path for journal in journals} != set(paths) or len(journals) != len(set(paths)):
        raise RuntimeGuardError("runtime_journal_evidence_missing")
    for journal in journals:
        if not journal.directory_exists:
            raise RuntimeGuardError("runtime_old_store_missing")
        if schema >= 3:
            drained = (
                journal.deliveries_directory_exists and journal.halts_directory_exists and journal.json_entries == 0
            )
        else:
            drained = not journal.halt_exists and (
                journal.slot_idle if journal.slot_exists else not journal.lock_exists
            )
        if not drained:
            raise RuntimeGuardError("runtime_old_store_not_drained")


@dataclass(frozen=True)
class TransitionStatus:
    """Four whitelisted aggregate fields from ORIGINAL managed CLI status."""

    enabled: bool
    status: str
    active_state: str | None
    server_enabled: bool


def parse_transition_status(payload: Mapping[str, Any]) -> TransitionStatus:
    """No I/O; caller discards the raw app response after extracting metadata."""
    try:
        enabled, status, server = payload["enabled"], payload["status"], payload["server"]
        active, remote_enabled = server["active_state"], server["enabled"]
        if (
            type(enabled) is not bool
            or type(remote_enabled) is not bool
            or status not in {"idle", "awaiting", "blocked"}
            or (
                active is not None
                and active not in {"pending", "assigned", "awaiting_apply", "needs_reconciliation", "failed"}
            )
        ):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise RuntimeGuardError("runtime_transition_status_invalid") from None
    return TransitionStatus(enabled, status, active, remote_enabled)


def require_transition_status(action: str, state: TransitionStatus) -> None:
    """Original pre-configuration cutover/rollback reconciliation predicates."""
    if action not in {"cutover", "rollback"}:
        raise RuntimeGuardError("runtime_transition_action_invalid")
    if (
        (state.enabled and action != "rollback")
        or state.status not in {"idle", "awaiting", "blocked"}
        or state.active_state in {"assigned", "awaiting_apply"}
        or (action == "rollback" and state.server_enabled)
    ):
        raise RuntimeGuardError("runtime_existing_state_not_reconciled")


def require_start_status(action: str, state: TransitionStatus) -> None:
    """Original readiness after selected policy publication, before enable/bootstrap."""
    if action not in {"cutover", "rollback"}:
        raise RuntimeGuardError("runtime_transition_action_invalid")
    if (
        state.active_state is not None
        or (action == "cutover" and state.status != "idle")
        or state.server_enabled != (action == "cutover")
    ):
        raise RuntimeGuardError("runtime_start_not_reconciled")
