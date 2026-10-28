"""Real freshness reader against owned state; missing/malformed are collectable."""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.software_live.state import STATE_PROBE


@pytest.mark.parametrize(
    ("value", "fresh"),
    [("fresh", True), ("old", False), ("future", False), (True, False), (None, False), ("bad", False)],
)
def test_actual_freshness_probe(tmp_path: Path, value: Any, fresh: bool) -> None:
    epochs = {"fresh": time.time() - 5, "old": time.time() - 1801, "future": time.time() + 60}
    value = epochs.get(value, value)
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"generated_at_epoch": value}))
    before = path.stat()
    result = subprocess.run(
        [sys.executable, "-I", "-", str(path)], input=STATE_PROBE, capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout) == {"exists": True, "fresh": fresh, "mtime_ns": before.st_mtime_ns}
    assert path.stat().st_mtime_ns == before.st_mtime_ns


def test_missing_and_malformed_state(tmp_path: Path) -> None:
    path = tmp_path / "state.json"

    def inspect() -> dict[str, Any]:
        result: dict[str, Any] = json.loads(
            subprocess.run(
                [sys.executable, "-I", "-", str(path)], input=STATE_PROBE, capture_output=True, text=True, check=True
            ).stdout
        )

        return result

    assert inspect() == {"exists": False, "fresh": False}
    path.write_text("not JSON")
    assert inspect()["fresh"] is False
