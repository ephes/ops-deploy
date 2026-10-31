"""One original bootstrap and read-only HTTP trial-state observation, then stop."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from .diagnose_wyoming import _evidence
from .fixture import VALUES, write
from .harness import admit, api, original, wait_http
from .matrix import original_vars
from .matter_native import verify_native_dependencies
from .matter_ready import diagnostics, wait_ready
from .prerequisites import seed


def project(value: Any) -> dict[str, Any]:
    """Discard configuration bodies; only finite enums and booleans leave RAM."""
    if not isinstance(value, dict) or set(value) != {"stable", "pending", "revert_at", "active_config_type", "default"}:
        raise ValueError("invalid owned HTTP status response")
    active = value["active_config_type"]
    if not isinstance(active, str) or active not in {"stable", "pending", "default", "default_legacy_port"}:
        raise ValueError("invalid owned HTTP active slot")
    deadline = value["revert_at"]
    if deadline is not None:
        try:
            if not isinstance(deadline, str) or datetime.fromisoformat(deadline).tzinfo is None:
                raise ValueError
        except ValueError:
            raise ValueError("invalid owned HTTP revert deadline") from None
    slots: dict[str, dict[str, bool] | None] = {}
    for name in ("stable", "pending", "default"):
        slot = value[name]
        if slot is None and name == "pending":
            slots[name] = None
            continue
        if not isinstance(slot, dict) or type(slot.get("server_port")) is not int:
            raise ValueError("invalid owned HTTP config slot")
        port = slot["server_port"]
        if not 1 <= port <= 65535:
            raise ValueError("invalid owned HTTP port")
        slots[name] = {"port_is_fixture10020": port == 10020, "port_is_builtin8123": port == 8123}
    error = value["pending"].get("error") if value["pending"] is not None else None
    if error is not None and (not isinstance(error, str) or error not in {"apply_failed", "not_promoted"}):
        raise ValueError("invalid owned HTTP pending error")
    return {
        "active_slot": active,
        "pending_present": value["pending"] is not None,
        "pending_error": error,
        "revert_scheduled": deadline is not None,
        "slots": slots,
    }


def run() -> None:
    if os.environ.get("HOMEASSISTANT_FIXTURE_CASE") != "current":
        raise ValueError("HTTP state diagnostic requires the current fixture")
    admit()
    bootstrapped = onboarded = observed = False
    try:
        seed("2026.10.2")
        original("00-original-existing-host-bootstrap", original_vars("2026.10.2"))
        bootstrapped = True
        try:
            verify_native_dependencies()
        except BaseException:
            _evidence(diagnostics, "Matter prerequisite")
            raise
        wait_ready()
        wait_http()
        token = api("seed")["token"]
        assert isinstance(token, str)
        VALUES.append(token)
        onboarded = True
        write(
            "api-onboarding.json",
            {
                "actual_user_created": True,
                "actual_token_exchange": True,
                "actual_long_lived_token": True,
                "frontend_core_onboarding_completed": False,
                "health": api("health", token=token),
            },
        )
        # Only this existing read-only command; no configure/promote/service call.
        response = api("ws", token=token, command_value={"type": "http/config"})
        projection = project(response["result"])
        del response
        write("http-status-projection.json", projection)
        observed = True
    finally:
        _evidence(
            lambda: write(
                "HTTP-DIAGNOSTIC.json",
                {
                    "purpose": "original bootstrap HTTP trial-state observation only",
                    "case": "current",
                    "original00_completed": bootstrapped,
                    "user_token_onboarding_completed": onboarded,
                    "http_status_projection_written": observed,
                    "selected_original_phases": 0,
                    "typed_phases": 0,
                    "peers_started": False,
                    "http_configuration_or_promotion_writes": 0,
                    "scope": "owned synthetic guest only; no full44/inventory/hardware/private caller qualification",
                },
            ),
            "HTTP state summary",
        )


if __name__ == "__main__":
    run()
