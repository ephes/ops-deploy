"""Refusal boundary for the hosted direct-user archive fixture."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_fixture_refuses_local_machine_before_provenance_keys_or_host_work(tmp_path: Path) -> None:
    script = Path(__file__).resolve().parents[1] / "smoke/daybook_archive_native_fixture.py"
    evidence = tmp_path / "evidence"
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        timeout=20,
        env={
            **os.environ,
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "local",
            "GITHUB_RUN_ID": "1",
            "IMPLEMENTATION_SHA": "a" * 40,
            "MAC_APPS_EVIDENCE_DIR": str(evidence),
        },
    )
    assert result.returncode != 0
    paths = list(evidence.glob("*.json"))
    assert len(paths) == 1
    receipt = json.loads(paths[0].read_text())
    assert receipt["failure_type"] == "RefusedHost"
    assert "installed_resources" not in receipt
    assert "transport" not in receipt
    assert "phases" not in receipt
