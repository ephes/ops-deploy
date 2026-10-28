"""Disposable fixture boundary and confinement, without actual host actions."""

from __future__ import annotations

import json
import os
import pwd
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_voice_memo_inbox.layout import directories, logs
from ops_deploy.services.daybook_voice_memo_inbox.render import SECRET_DEFAULTS, resources

FIXTURE = Path(__file__).resolve().parents[1] / "smoke/daybook_inbox_native_fixture.py"


def test_owned_fixture_refuses_this_local_machine_before_provenance_or_host_work(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    result = subprocess.run(
        [sys.executable, str(FIXTURE)],
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


def test_native_config_substitutions_keep_all_managed_resources_owned_and_activation_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(FIXTURE.parent))
    module: dict[str, Any] = runpy.run_path(str(FIXTURE))
    owned = SimpleNamespace(root=tmp_path.resolve(), suffix="owned-123")
    actor = pwd.getpwuid(os.getuid())
    cfg = module["configuration"](
        owned,
        SourceTree(tmp_path / "source", "a" * 40),
        tmp_path / "source.bundle",
        "/owned/uv",
        actor,
        name="local-proof",
    )
    paths = [row.path for row in directories(cfg)]
    paths += [row.path for row in logs(cfg)]
    paths += [row.path for row in resources(cfg, dict.fromkeys(SECRET_DEFAULTS, "UNUSABLE-OWNED"))]
    assert paths
    assert all(Path(path).is_relative_to(owned.root) for path in paths)
    assert cfg.daybook_voice_memo_inbox_launchd_enabled is False
    assert cfg.daybook_voice_memo_inbox_long_label_enabled is False
    assert cfg.daybook_voice_memo_inbox_python_version == "3.14.7"
    assert cfg.daybook_voice_memo_inbox_launchd_label.startswith("com.example.ops-mac-apps.")
    assert cfg.daybook_voice_memo_inbox_long_launchd_label.startswith("com.example.ops-mac-apps.")
    assert not list(tmp_path.iterdir())
