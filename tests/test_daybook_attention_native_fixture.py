"""Native fixture refuses local execution before any provenance or host work."""

from __future__ import annotations

import json
import os
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.daybook_voice_memo_attention import deploy as api
from ops_deploy.testing import run_deploy_fake
from tests.test_daybook_voice_memo_attention import config


def test_owned_fixture_refuses_this_local_machine_before_provenance_or_host_work(tmp_path: Path) -> None:
    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_attention_native_fixture.py"
    evidence = tmp_path / "evidence"
    result = subprocess.run(
        [sys.executable, str(fixture)],
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
    receipts = list(evidence.glob("*.json"))
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_text())
    assert receipt["failure_type"] == "RefusedHost"
    assert "installed_resources" not in receipt
    assert "phases" not in receipt
    assert not list(tmp_path.glob("**/daybook"))


def test_native_import_observation_accepts_actual_sdk_deploy_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_attention_native_fixture.py"
    monkeypatch.syspath_prepend(str(fixture.parent))
    module: dict[str, Any] = runpy.run_path(str(fixture))
    artifact = tmp_path / "daybook-0.0.0-py3-none-any.whl"
    artifact.write_bytes(b"OWNED inert controller artifact")
    monkeypatch.setattr(
        api, "observe", lambda _: dict.fromkeys(("quiescent", "directories", "wheel", "environment", "resources"), True)
    )
    result = run_deploy_fake(
        api.install_daybook_voice_memo_attention, config(artifact), responses={"uname -s": ["Darwin"]}
    )
    assert result.succeeded, result.error
    observed = module["import_result"](result)
    assert observed.name.startswith("Original disabled Daybook voice-memo attention wheel | ")
    assert observed.succeeded
