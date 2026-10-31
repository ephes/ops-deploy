"""One original current-host selected pass; no typed or 44-phase application replay."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from typing import Any

from .fixture import VALUES, write
from .harness import admit, api, original, wait_http
from .matrix import config, original_vars, peers
from .matter_native import verify_native_dependencies
from .matter_ready import diagnostics, wait_ready
from .prerequisites import seed
from .wyoming_diagnostics import capture


def _evidence(action: Callable[[], Any], label: str) -> bool:
    primary = sys.exception()
    try:
        action()
        return True
    except Exception:
        if primary is None:
            raise
        # Disk/full-output failures must not replace an earlier original error.
        print("Owned Wyoming diagnostic evidence failed: " + label, file=sys.stderr)
        return False


def run() -> None:
    admit()
    case = os.environ["HOMEASSISTANT_FIXTURE_CASE"]
    assert case == "current"
    started = False
    succeeded = False
    captured = False
    try:
        seed("2026.10.2")
        original("00-original-existing-host-bootstrap", original_vars("2026.10.2"))
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
        with peers():
            selected = config(token=token, selected=True)
            capture("before-original-selected", token)
            started = True
            try:
                original("01-original-selected", original_vars("2026.10.2", selected=selected))
                succeeded = True
            finally:
                captured = _evidence(lambda: capture("after-original-selected", token), "after original selection")
    finally:
        _evidence(
            lambda: write(
                "summary.json",
                {
                    "purpose": "single original Wyoming selection diagnostic",
                    "case": case,
                    "selected_original_started": started,
                    "selected_original_succeeded": succeeded,
                    "after_diagnostics_written": captured,
                    "typed_phases_executed": 0,
                    "scope": (
                        "owned synthetic current guest / shared hosted kernel; no inventory/hardware/migration credit"
                    ),
                },
            ),
            "summary",
        )


if __name__ == "__main__":
    run()
