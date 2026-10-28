"""The owned native harness refuses local computers before creating host state."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


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


def test_actual_owned_diagnostic_cli_retains_only_fixed_failure_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    import runpy
    import shlex

    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_runtime_native_fixture.py"
    monkeypatch.syspath_prepend(str(fixture.parent))
    module = runpy.run_path(str(fixture))
    command = shlex.split(module["diagnostic_command"]())
    command[0] = sys.executable
    private = "UNUSABLE-OWNED-DIAGNOSTIC-INPUT"
    result = subprocess.run(command, input=json.dumps({"private": private}), capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"failure": "KeyError", "probes": []}
    assert private not in result.stdout + result.stderr


@pytest.mark.parametrize("kind", ["outer", "inner", "run-failed"])
def test_owned_diagnostic_failures_keep_type_without_body_or_false_transport_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    import runpy
    from types import SimpleNamespace

    from ops_deploy.core.git_source import SourceTree
    from tests.test_daybook_runtime_contract import config

    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_runtime_native_fixture.py"
    monkeypatch.syspath_prepend(str(fixture.parent))
    module = runpy.run_path(str(fixture))
    capture = module["capture_observation"]
    scope = capture.__globals__
    private = "UNUSABLE-OWNED-DIAGNOSTIC-ERROR-BODY"

    def failed_payload(*args: object) -> None:
        raise ValueError(private)

    def runner(callback: object, **kwargs: object) -> SimpleNamespace:
        if kind == "outer":
            raise ValueError(private)
        if kind == "inner":
            assert callable(callback)
            callback()
            return SimpleNamespace(succeeded=True, error=None)
        return SimpleNamespace(succeeded=False, error=RuntimeError(private))

    monkeypatch.setitem(scope, "run_deploy_ssh", runner)
    monkeypatch.setitem(scope, "observation_payload", failed_payload)
    result = capture(config(), {}, SourceTree(tmp_path, "a" * 40), {})
    assert result == {"failure": "RuntimeError" if kind == "run-failed" else "ValueError"}
    assert private not in json.dumps(result)
    assert "transport" not in json.dumps(result)
