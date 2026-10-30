"""One owned prerequisite diagnostic, without selected/typed matrix phases."""

from __future__ import annotations

import os

from .fixture import write
from .harness import admit, original
from .matrix import original_vars
from .matter_native import verify_native_dependencies
from .matter_ready import diagnostics, wait_ready
from .prerequisites import seed


def run() -> None:
    admit()
    case = os.environ["HOMEASSISTANT_FIXTURE_CASE"]
    completed = False
    try:
        assert case == "current"
        try:
            seed("2026.10.2")
            original("00-original-existing-host-bootstrap", original_vars("2026.10.2"))
            verify_native_dependencies()
        except BaseException:
            diagnostics()
            raise
        wait_ready()
        completed = True
    finally:
        write(
            "summary.json",
            {
                "completed": completed,
                "purpose": "Matter prerequisite diagnostic only",
                "case": case,
                "typed_phases_executed": 0,
                "selected_original_phases_executed": 0,
                "scope": (
                    "owned synthetic guest / shared hosted kernel; no inventory, hardware or migration qualification"
                ),
            },
        )


if __name__ == "__main__":
    run()
