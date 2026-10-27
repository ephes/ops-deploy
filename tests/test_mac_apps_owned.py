"""Fixture-only cleanup helper: refusal receipts and exact owned process cleanup."""

from __future__ import annotations

import importlib.util
import json
import platform
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest


def owned_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "smoke/mac_apps_owned.py"
    spec = importlib.util.spec_from_file_location("owned_mac_apps_helper", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_refused_host_writes_receipt_and_creates_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = owned_module()
    monkeypatch.setenv("MAC_APPS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("IMPLEMENTATION_SHA", "a" * 40)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(RuntimeError, match="disposable ARM GitHub runner"):
        module.OwnedMac("unit")
    receipt = json.loads((tmp_path / "evidence/unit-proof.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["failure_type"] == "RefusedHost"
    assert "cleanup" not in receipt


@pytest.mark.skipif(platform.system() != "Darwin", reason="BSD ps columns are the fixture's contract")
def test_spawned_helper_tree_is_stopped_exactly_and_unrelated_process_survives() -> None:
    module = owned_module()
    owner = object.__new__(module.OwnedMac)
    owner.processes = []
    # The helper forks a grandchild; an unrelated sibling must not be touched.
    script = "import subprocess,time;subprocess.Popen(['/bin/sleep','300']);time.sleep(300)"
    helper = owner.spawn([sys.executable, "-c", script])
    unrelated = subprocess.Popen(["/bin/sleep", "300"])
    try:
        for _ in range(50):
            tracked = module.tree({helper.pid}, groups={helper.pid})
            if len(tracked) == 2:
                break
            time.sleep(0.1)
        assert len(tracked) == 2
        assert unrelated.pid not in tracked
        assert module.processes()[helper.pid]["pgid"] == helper.pid
        assert module.stop_exact(tracked, [helper]) == []
        assert helper.poll() is not None
        assert unrelated.poll() is None
    finally:
        unrelated.kill()
        unrelated.wait()
        for pid in module.tree({helper.pid}):
            subprocess.run(["/bin/kill", "-9", str(pid)], check=False)
