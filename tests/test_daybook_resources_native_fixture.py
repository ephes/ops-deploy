"""Separate resource fixture boundaries and original render confinement."""

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

FIXTURE = Path(__file__).resolve().parents[1] / "smoke/daybook_resources_native_fixture.py"


def fixture_module(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.syspath_prepend(str(FIXTURE.parent))
    return runpy.run_path(str(FIXTURE))


def test_actual_resource_fixture_refuses_local_computer_before_host_resources(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    result = subprocess.run(
        [sys.executable, str(FIXTURE)],
        env={
            **os.environ,
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "local",
            "GITHUB_RUN_ID": "1",
            "IMPLEMENTATION_SHA": "a" * 40,
            "MAC_APPS_EVIDENCE_DIR": str(evidence),
        },
        capture_output=True,
        timeout=20,
    )
    assert result.returncode != 0
    records = list(evidence.glob("*.json"))
    assert len(records) == 1
    receipt = json.loads(records[0].read_text())
    assert receipt["status"] == "failed"
    assert receipt["failure_type"] == "RefusedHost"
    assert "installed_resources" not in receipt
    assert "filesystem" not in receipt
    assert "timers" not in receipt


def test_actual_template_selection_stays_inside_owned_root_without_global_plists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ops_deploy.services.daybook_sessions.render import _resource_texts

    module = fixture_module(monkeypatch)
    actor = pwd.getpwuid(os.getuid())
    cfg = module["configuration"](SimpleNamespace(root=tmp_path.resolve()), actor)
    values = {
        "daybook_sessions_aws_access_key_id": "UNUSABLE-OWNED",
        "daybook_sessions_aws_secret_access_key": "UNUSABLE-OWNED",
        "daybook_archive_token": "UNUSABLE-OWNED",
        "daybook_weeknotes_cast_token": "UNUSABLE-OWNED",
        "daybook_weeknotes_home_token": "UNUSABLE-OWNED",
        "daybook_weeknotes_public_repositories_json": '{"owned":"https://example.test/owned.git"}',
        "daybook_weeknotes_confidential_names_json": '["UNUSABLE-OWNED"]',
    }
    rows = _resource_texts(cfg, values)
    assert len(rows) == 9
    assert all(Path(row.path).is_relative_to(tmp_path.resolve()) for row in rows)
    assert not any(row.path.endswith(".plist") for row in rows)
    assert cfg.daybook_weeknotes_reconcile_pi_auth_rotate is False
    assert cfg.daybook_weeknotes_post_identity_epoch == ""
    assert cfg.daybook_archive_quote_classifier_cmd == "/usr/bin/false"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("failure", ["none", "different", "expected"])
def test_fault_assertion_requires_exact_genuine_resource_failure(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    module = fixture_module(monkeypatch)

    class OwnedError(RuntimeError):
        pass

    def callback() -> None:
        if failure != "none":
            raise OwnedError(failure)

    if failure == "expected":
        module["refuse"](callback, "expected", OwnedError)
    else:
        with pytest.raises(AssertionError):
            module["refuse"](callback, "expected", OwnedError)
