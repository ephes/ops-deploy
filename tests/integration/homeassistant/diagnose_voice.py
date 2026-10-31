"""One exact current00→34 history with exit diagnostics; never enters phase35."""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

from . import component_matrix, harness, matrix
from .diagnose_wyoming import _evidence
from .fixture import write
from .voice_diagnostics import LABELS, capture


class _PrefixComplete(BaseException):
    """Exit only after the unchanged34 operation and all its assertions return."""


def run() -> None:
    # Refuse another case before admission or fixture/application work.
    if os.environ.get("HOMEASSISTANT_FIXTURE_CASE") != "current":
        raise ValueError("voice failure diagnostic requires the current fixture")
    harness.admit()
    reached: list[str] = []
    completed = False
    original_typed = harness.typed

    def observed(label: str, *args: Any, **kwargs: Any) -> Any:
        if int(label.split("-", 1)[0]) >= 35:
            raise AssertionError("voice diagnostic cannot enter phase35 or later")
        reached.append(label)
        if label not in LABELS:
            return original_typed(label, *args, **kwargs)
        capture(label, "before")
        try:
            result = original_typed(label, *args, **kwargs)
        finally:
            _evidence(lambda: capture(label, "after"), label)
        if label == "34-voice-recovery":
            raise _PrefixComplete
        return result

    try:
        # Both fixture modules imported the canonical typed function. Wrap only
        # these fixture call sites; production and all comparators stay intact.
        with patch.object(matrix, "typed", observed), patch.object(component_matrix, "typed", observed):
            try:
                matrix.run()
            except _PrefixComplete:
                completed = True
            else:
                raise AssertionError("voice diagnostic prefix stop was not reached")
    finally:
        _evidence(
            lambda: write(
                "VOICE-DIAGNOSTIC.json",
                {
                    "purpose": "one exact current00→34 prefix with process-exit diagnostics",
                    "completed_through34": completed,
                    "typed_labels_reached": reached,
                    "phases": harness.PHASES,
                    "case": "current",
                    "scope": "owned synthetic prefix only; no full44/inventory/hardware/private caller qualification",
                },
            ),
            "voice prefix summary",
        )


if __name__ == "__main__":
    run()
