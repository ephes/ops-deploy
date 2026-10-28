"""The owned native harness refuses local computers before creating host state."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_actual_native_fixture_refuses_non_hosted_invocation(tmp_path: Path) -> None:
    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_runtime_native_fixture.py"
    evidence = tmp_path / "owned-evidence"
    result = subprocess.run(
        [sys.executable, str(fixture)],
        env={
            **os.environ,
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "local",
            "GITHUB_RUN_ID": "1",
            "IMPLEMENTATION_SHA": "a" * 40,
            "MAC_APPS_EVIDENCE_DIR": str(evidence),
        },
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode != 0
    receipts = list(evidence.glob("*.json"))
    assert len(receipts) == 1
    record = json.loads(receipts[0].read_text())
    assert record["failure_type"] == "RefusedHost"
    assert record["status"] == "failed"
    assert "installed_resources" not in record
