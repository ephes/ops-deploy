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


@pytest.mark.parametrize(
    ("message", "tags"),
    [
        ("error: The environment is outdated; run uv sync", ["env-outdated", "error"]),
        ("Would replace project environment at: /private/daybook", ["would-replace-env"]),
        ("Would create project environment at: /private/daybook", ["would-create-env"]),
        ("Would download 1 package", ["would-download"]),
        ("Would make no changes", ["no-changes"]),
        ("Would install 1 package", ["would-install"]),
        ("/owned/Caches/daybook/offline", []),
    ],
)
def test_actual_diagnostic_reports_uv_fixed_signals_without_child_body(
    monkeypatch: pytest.MonkeyPatch,
    message: str,
    tags: list[str],
) -> None:
    import runpy
    import shlex

    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_runtime_native_fixture.py"
    monkeypatch.syspath_prepend(str(fixture.parent))
    module = runpy.run_path(str(fixture))
    private = "UNUSABLE-SYNTHETIC-CHILD-BODY"
    replacement = """import types
MAX_INPUT=1024
class ObservationError(RuntimeError):pass
class NativeProbes:
 def __init__(self,data):self.data=data
 def run(self,*args,**kwargs):
  body=OWNED_ERROR_BODY
  return types.SimpleNamespace(returncode=1,stderr=body)
def observe(data,probes):
 probes.run([data['uv_bin']])
 return {'healthy':False}
"""
    replacement = replacement.replace("OWNED_ERROR_BODY", repr((message + " " + private).encode()))
    monkeypatch.setitem(module["diagnostic_command"].__globals__, "SCRIPT", replacement.encode())
    command = shlex.split(module["diagnostic_command"]())
    command[0] = sys.executable
    data = {"python": "/owned/python", "uv_bin": "/owned/uv", "host_tmux": "/owned/tmux"}
    result = subprocess.run(command, input=json.dumps(data), capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "state": {"healthy": False},
        "probes": [
            {
                "probe": "uv-check",
                "returncode": 1,
                "stderr_category": "nonempty",
                "uv_signals": tags,
            }
        ],
    }
    assert private not in result.stdout + result.stderr


@pytest.mark.parametrize("fails", [False, True])
def test_native_upload_counter_observes_actual_sftp_method_without_body(
    monkeypatch: pytest.MonkeyPatch,
    fails: bool,
) -> None:
    import io
    import runpy
    from types import SimpleNamespace

    import paramiko

    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_runtime_native_fixture.py"
    monkeypatch.syspath_prepend(str(fixture.parent))
    module = runpy.run_path(str(fixture))
    private = "UNUSABLE-OWNED-SFTP-BODY"

    def original(*args: object, **kwargs: object) -> None:
        if fails:
            raise OSError(private)

    monkeypatch.setattr(paramiko.SFTPClient, "putfo", original)

    def run(*args: object, **kwargs: object) -> object:
        try:
            client = paramiko.SFTPClient.__new__(paramiko.SFTPClient)
            client.putfo(
                io.BytesIO(private.encode()),
                "/private/var/tmp/ops-deploy-daybook-source-" + "a" * 32 + "/source.bundle",
            )
        except OSError:
            return SimpleNamespace(succeeded=False)
        return SimpleNamespace(succeeded=True)

    monkeypatch.setitem(module["source_run_with_upload_counter"].__globals__, "run_deploy_ssh", run)
    result, counts = module["source_run_with_upload_counter"]()
    assert result.succeeded is not fails
    assert counts == {
        "attempted": 1,
        "succeeded": int(not fails),
        "failed": int(fails),
        "paths": ["/private/var/tmp/ops-deploy-daybook-source-" + "a" * 32 + "/source.bundle"],
    }
    assert private not in json.dumps(counts)


@pytest.mark.parametrize("reached", [False, True])
def test_native_sftp_setup_injection_requires_actual_callback_path(
    monkeypatch: pytest.MonkeyPatch,
    reached: bool,
) -> None:
    import runpy
    from contextlib import suppress
    from types import SimpleNamespace

    from pyinfra.api.exceptions import ConnectError
    from pyinfra.connectors.ssh import SSHConnector

    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_runtime_native_fixture.py"
    monkeypatch.syspath_prepend(str(fixture.parent))
    module = runpy.run_path(str(fixture))

    def run(*args: object, **kwargs: object) -> object:
        if reached:
            with suppress(ConnectError):
                SSHConnector.get_file_transfer_connection(None)
        return SimpleNamespace(succeeded=False)

    monkeypatch.setitem(module["source_run_with_upload_counter"].__globals__, "run_deploy_ssh", run)
    if reached:
        _result, counts = module["source_run_with_upload_counter"](_owned_fail_sftp_setup=True)
        assert counts["setup_attempted"] == 1
    else:
        with pytest.raises(AssertionError):
            module["source_run_with_upload_counter"](_owned_fail_sftp_setup=True)


@pytest.mark.parametrize("case", ["ordinary", "escaped_connect", "early_failure", "unrelated_error", "unreached"])
def test_native_setup_failure_distinguishes_normal_failed_op_from_escaped_or_early_failure(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    import runpy

    from pyinfra.api.exceptions import ConnectError, PyinfraError

    from ops_deploy.testing import DeployRun, OpResult

    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_runtime_native_fixture.py"
    monkeypatch.syspath_prepend(str(fixture.parent))
    module = runpy.run_path(str(fixture))
    prefix = "Install exact Sessions source and locked managed environment | "
    error = (
        ConnectError("No hosts remaining!")
        if case == "escaped_connect"
        else PyinfraError("unrelated" if case == "unrelated_error" else "No hosts remaining!")
    )
    run = DeployRun(
        ops=[
            OpResult(
                prefix + "Prepare private temporary Daybook source upload directory", True, case != "early_failure"
            ),
            OpResult(prefix + "Stage exact Daybook Main source bundle", False, False),
        ],
        error=error,
    )
    counts = {
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "paths": [],
        "setup_attempted": 0 if case == "unreached" else 1,
    }
    if case == "ordinary":
        module["assert_source_setup_failure"](run, counts)
    else:
        with pytest.raises(AssertionError):
            module["assert_source_setup_failure"](run, counts)


def test_actual_pyinfra_single_host_failed_operation_raises_fixed_base_error() -> None:
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.exceptions import PyinfraError

    inventory = Inventory((["owned-unconnected-metadata-only"], {}))
    state = State(inventory, Config())
    target = inventory.get_host("owned-unconnected-metadata-only")
    state.activate_host(target)
    with pytest.raises(PyinfraError, match=r"^No hosts remaining!$") as failed:
        state.fail_hosts({target})
    assert type(failed.value) is PyinfraError
    assert state.failed_hosts == {target}


@pytest.mark.parametrize(
    ("category", "success", "observed"),
    [
        ("sessions_source_requires_reconcile_disabled_unloaded", False, 1),
        ("sessions_source_reconcile_probe_failed", False, 0),
        ("prefix sessions_source_requires_reconcile_disabled_unloaded", False, 0),
        ("sessions_source_requires_reconcile_disabled_unloaded", True, 0),
    ],
)
def test_native_reconcile_refusal_observer_retains_only_exact_failed_category(
    monkeypatch: pytest.MonkeyPatch,
    category: str,
    success: bool,
    observed: int,
) -> None:
    import runpy
    from types import SimpleNamespace

    from pyinfra.api import StringCommand
    from pyinfra.connectors.ssh import SSHConnector
    from pyinfra.connectors.util import CommandOutput, OutputLine

    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_runtime_native_fixture.py"
    monkeypatch.syspath_prepend(str(fixture.parent))
    module = runpy.run_path(str(fixture))
    private = "UNUSABLE-OWNED-PRIVATE-DIAGNOSTIC"
    monkeypatch.setattr(
        SSHConnector,
        "run_shell_command",
        lambda *_args, **_kwargs: (
            success,
            CommandOutput([OutputLine("stderr", category), OutputLine("stderr", private)]),
        ),
    )

    def run(*args: object, **kwargs: object) -> object:
        SSHConnector.run_shell_command(SSHConnector.__new__(SSHConnector), StringCommand("owned synthetic only"))
        return SimpleNamespace(succeeded=success)

    monkeypatch.setitem(module["source_run_with_upload_counter"].__globals__, "run_deploy_ssh", run)
    _result, counts = module["source_run_with_upload_counter"](_owned_observe_reconcile_refusal=True)
    assert counts["reconcile_refusal_events"] == observed
    assert private not in json.dumps(counts)
    assert category not in json.dumps(counts)
