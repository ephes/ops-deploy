"""One original bootstrap and read-only HTTP trial-state observation, then stop."""

from __future__ import annotations

import os

from .diagnose_wyoming import _evidence
from .fixture import VALUES, write
from .harness import admit, api, original, wait_http
from .http_baseline import project as project
from .matrix import original_vars
from .matter_native import verify_native_dependencies
from .matter_ready import diagnostics, wait_ready
from .prerequisites import seed


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
