#!/usr/bin/env python3
"""Derive stable USB replication health signals from durable host-local state."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any


def load_replication_state(path: str) -> tuple[dict[str, Any], str | None]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, "state_file_missing"
    except (OSError, json.JSONDecodeError) as exc:
        return {}, f"state_file_invalid: {exc}"
    if not isinstance(payload, dict):
        return {}, "state_file_invalid: root is not an object"
    return payload, None


def _iso_epoch(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


USB_USAGE_FIELDS = (
    "last_known_used_ratio",
    "last_known_size_bytes",
    "last_known_alloc_bytes",
    "last_known_free_bytes",
    "last_known_observed_epoch",
    "last_known_observed_iso",
)


def select_usb_usage(
    current: dict[str, Any],
    durable: dict[str, Any],
    *,
    live_observed: bool,
) -> dict[str, Any]:
    """Prefer a live sample, otherwise the newest cached/durable observation."""
    if live_observed:
        return {field: current.get(field) for field in USB_USAGE_FIELDS}

    current_ratio = current.get("last_known_used_ratio")
    durable_ratio = durable.get("last_known_used_ratio")
    if not isinstance(durable_ratio, (int, float)):
        return {field: current.get(field) for field in USB_USAGE_FIELDS}
    if not isinstance(current_ratio, (int, float)):
        return {field: durable.get(field) for field in USB_USAGE_FIELDS}

    current_epoch = current.get("last_known_observed_epoch")
    durable_epoch = durable.get("last_known_observed_epoch")
    if isinstance(durable_epoch, (int, float)) and (
        not isinstance(current_epoch, (int, float)) or durable_epoch >= current_epoch
    ):
        return {field: durable.get(field) for field in USB_USAGE_FIELDS}
    return {field: current.get(field) for field in USB_USAGE_FIELDS}


def build_usb_replication_health(
    *,
    enabled: bool,
    device_present: bool | None,
    unit_ok: bool | None,
    state: dict[str, Any],
    state_error: str | None,
    selected_usage: dict[str, Any],
    warning_ratio: float,
    critical_ratio: float,
    protection_max_age_hours: float,
    now_epoch: int,
) -> dict[str, Any]:
    last_present_result = state.get("last_present_attempt_result")
    if device_present is True and unit_ok is False:
        # A current attached-drive failure is newer operational evidence than a
        # possibly stale durable success (for example if state persistence was
        # interrupted). Missing-drive skips cannot take this path.
        last_present_attempt_ok = False
        last_present_source = "live_unit_failure"
    elif last_present_result in {"success", "failed"}:
        last_present_attempt_ok: bool | None = last_present_result == "success"
        last_present_source = "durable_state"
    elif device_present is True and isinstance(unit_ok, bool):
        # Migration fallback: surface an already-failed live unit before the
        # first run has written the newly introduced durable state file.
        last_present_attempt_ok = unit_ok
        last_present_source = "live_unit_fallback"
    else:
        last_present_attempt_ok = None
        last_present_source = None

    used_ratio = selected_usage.get("last_known_used_ratio")
    ratio = float(used_ratio) if isinstance(used_ratio, (int, float)) else None
    capacity_warning_ok = ratio < warning_ratio if ratio is not None else None
    capacity_critical_ok = ratio < critical_ratio if ratio is not None else None

    last_success_epoch = _iso_epoch(state.get("last_success_at"))
    if last_success_epoch is None:
        last_success_age_hours = None
    else:
        last_success_age_hours = max(0.0, (now_epoch - last_success_epoch) / 3600)

    if protection_max_age_hours <= 0:
        protection_fresh: bool | None = None
    elif last_success_age_hours is None:
        protection_fresh = False
    else:
        protection_fresh = last_success_age_hours <= protection_max_age_hours

    issues: list[str] = []
    if enabled:
        if last_present_attempt_ok is not True:
            issues.append("last_present_attempt_not_successful")
        if capacity_critical_ok is not True:
            issues.append("capacity_critical_or_unknown")
        if protection_fresh is False:
            issues.append("protection_stale_or_unknown")

    devices = state.get("devices")
    return {
        "enabled": enabled,
        "ok": not issues,
        "device_name": state.get("device_name"),
        "devices": devices if isinstance(devices, dict) else {},
        "issues": issues,
        "state_error": state_error,
        "last_attempt_at": state.get("last_attempt_at"),
        "last_attempt_result": state.get("last_attempt_result"),
        "last_attempt_exit_code": state.get("last_attempt_exit_code"),
        "last_present_attempt_at": state.get("last_present_attempt_at"),
        "last_present_attempt_result": last_present_result,
        "last_present_attempt_exit_code": state.get("last_present_attempt_exit_code"),
        "last_present_attempt_ok": last_present_attempt_ok,
        "last_present_attempt_source": last_present_source,
        "last_success_at": state.get("last_success_at"),
        "last_success_age_hours": last_success_age_hours,
        "protection_max_age_hours": protection_max_age_hours,
        "protection_fresh": protection_fresh,
        "last_known_used_ratio": ratio,
        "last_known_size_bytes": selected_usage.get("last_known_size_bytes"),
        "last_known_alloc_bytes": selected_usage.get("last_known_alloc_bytes"),
        "last_known_free_bytes": selected_usage.get("last_known_free_bytes"),
        "last_known_observed_epoch": selected_usage.get("last_known_observed_epoch"),
        "last_known_observed_iso": selected_usage.get("last_known_observed_iso"),
        "capacity_warning_ratio": warning_ratio,
        "capacity_critical_ratio": critical_ratio,
        "capacity_warning_ok": capacity_warning_ok,
        "capacity_critical_ok": capacity_critical_ok,
    }
