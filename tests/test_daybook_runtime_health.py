"""Original managed health predicate, separate from pure monitor metadata."""

from __future__ import annotations

import base64
import importlib
import importlib.resources
import json
import os
import subprocess
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from ops_deploy.core.git_source import SourceTree
from tests.test_daybook_inbox_deploy import source  # noqa: F401 - pytest fixture


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    dependencies: dict[str, dict[str, Any]] = {
        "ops_daybook_observer": {
            "MAX_INPUT": 8192,
            "NativeProbes": type("OwnedProbes", (), {"health": Mock()}),
            "observe": Mock(),
        },
        "ops_daybook_stop": {"STATUS_FRAME": b"\nOPS_DAYBOOK_EXECUTOR_STDOUT=", "STATUS_CAPTURE": "owned-capture"},
    }
    for name, attrs in dependencies.items():
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, name, module)
    module = types.ModuleType("owned_original_health")
    resource = importlib.resources.files("ops_deploy.services.daybook_operations_runtime").joinpath(
        "files/runtime_health.py"
    )
    exec(compile(resource.read_bytes(), "<actual-health>", "exec"), module.__dict__)
    return module


@pytest.mark.parametrize("state", ["idle", "request", "claim", "assigned", "running", "receipt", "awaiting", "blocked"])
def test_every_original_readable_local_state_allows_disabled_or_attention_remote_flags(helper: Any, state: str) -> None:
    assert (
        helper.healthy(
            0,
            {
                "enabled": True,
                "status": state,
                "server": {"enabled": False, "needs_operator": True, "expiry_pending": True},
            },
        )
        is True
    )


@pytest.mark.parametrize(("rc", "enabled", "status"), [(1, True, "idle"), (0, False, "idle"), (0, True, "unreadable")])
def test_original_failures_remain_failures(helper: Any, rc: int, enabled: bool, status: str) -> None:
    assert helper.healthy(rc, {"enabled": enabled, "status": status}) is False


def test_original_role_oracle_uses_local_enabled_and_unreadable_only(helper: Any) -> None:
    role_root = os.environ.get("OPS_LIBRARY_PATH")
    if not role_root:
        pytest.skip("Actual role oracle is qualified explicitly")
    import jinja2.nativetypes
    import yaml

    tasks = yaml.safe_load((Path(role_root) / "roles/daybook_operations_runtime_deploy/tasks/verify.yml").read_text())
    expression = next(
        t["ansible.builtin.set_fact"]["daybook_operations_runtime_verify_report"]
        for t in tasks
        if isinstance(t.get("ansible.builtin.set_fact", {}).get("daybook_operations_runtime_verify_report"), str)
    )
    env = jinja2.nativetypes.NativeEnvironment(undefined=importlib.import_module("jinja2").StrictUndefined)
    env.filters.update(importlib.import_module("ansible.plugins.filter.core").FilterModule().filters())
    for rc, enabled, status in [
        (0, True, "idle"),
        (0, True, "running"),
        (0, True, "blocked"),
        (0, True, "unreadable"),
        (0, False, "idle"),
        (1, True, "idle"),
    ]:
        payload = {
            "enabled": enabled,
            "status": status,
            "server": {
                "enabled": False,
                "active_state": "assigned",
                "disposition": None,
                "stale": True,
                "needs_operator": True,
                "expiry_pending": True,
            },
        }
        original: Any = env.from_string(expression).render(
            daybook_operations_runtime_verify_report=[],
            item={"rc": rc, "stdout": json.dumps(payload), "item": "regular"},
        )
        assert original[0]["healthy"] is helper.healthy(rc, payload)


@pytest.mark.parametrize("different_account", [False, True])
def test_actual_client_sanitizes_private_response_and_preserves_original_login_context(
    helper: Any, monkeypatch: pytest.MonkeyPatch, different_account: bool, capsys: Any
) -> None:
    driver = helper.NativeHealth.__new__(helper.NativeHealth)
    driver.data = {"python": "/owned/python", "policy": "/owned/policy", "owner": "root", "user": "fixture"}
    driver.account = types.SimpleNamespace(pw_uid=os.geteuid() + int(different_account))
    payload = {
        "enabled": True,
        "status": "running",
        "deliveries": [{"body": "PRIVATE-DISCARDED"}],
        "server": {"enabled": False, "needs_operator": True},
    }
    output = b"PRIVATE-PROFILE-NOISE" + helper.STATUS_FRAME + base64.b64encode(json.dumps(payload).encode()) + b"\n"
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=output, stderr=b"PRIVATE-STDERR"))
    monkeypatch.setattr(helper.subprocess, "run", run)
    assert driver.client("regular") is None
    argv = run.call_args.args[0]
    if different_account:
        assert argv[:9] == ["/usr/bin/sudo", "-H", "-S", "-n", "-i", "-u", "fixture", "--", "/owned/python"]
    else:
        assert argv[0] == "/owned/python"
    assert "timeout" not in run.call_args.kwargs
    assert capsys.readouterr() == ("", "")


def test_verify_runs_original_cli_for_every_source_after_fresh_metadata(helper: Any) -> None:
    calls: list[str] = []
    driver = types.SimpleNamespace(ready=lambda: calls.append("metadata"), client=calls.append)
    assert helper.verify({"status_sources": ["regular", "long"]}, driver) == {"verified": True, "managed_cli_calls": 2}
    assert calls == ["metadata", "regular", "long"]


def test_failed_local_metadata_never_invokes_application(helper: Any) -> None:
    client = Mock(side_effect=AssertionError("must not run app"))
    driver = types.SimpleNamespace(ready=Mock(side_effect=RuntimeError("unsafe-resource")), client=client)
    with pytest.raises(RuntimeError, match="unsafe-resource"):
        helper.verify({"status_sources": ["regular"]}, driver)
    client.assert_not_called()


def test_controller_keeps_resource_only_vs_original_managed_health_distinct(
    source: tuple[SourceTree, Path],  # noqa: F811
) -> None:
    from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig, verify_daybook_runtime_health
    from ops_deploy.services.daybook_operations_runtime.inspect import verify_daybook_runtime
    from ops_deploy.services.daybook_operations_runtime.status import SourceStatus
    from ops_deploy.testing import run_deploy_fake

    tree, _ = source
    cfg = DaybookRuntimeConfig(user="fixture", revision=tree.commit)
    token = {"executor_token": "UNUSABLE-OWNED-EXECUTOR-CREDENTIAL-ONLY"}
    # Original healthy does not require server enabled or zero attention/expiry.
    statuses = (SourceStatus("regular", False, None, True, 1, True),)
    resources = run_deploy_fake(
        verify_daybook_runtime, cfg, token, tree, statuses=statuses, responses={"uname -s": ["Darwin"]}
    )
    assert resources.succeeded, resources.error
    assert len(resources.ops) == 1
    assert resources.ops[0].read_only is True
    assert not resources.mutating_changed_ops
    actual_health = run_deploy_fake(verify_daybook_runtime_health, cfg, token, tree, responses={"uname -s": ["Darwin"]})
    assert actual_health.succeeded, actual_health.error
    assert len(actual_health.ops) == 1
    assert actual_health.ops[0].read_only is False
    assert len(actual_health.mutating_changed_ops) == 1
    assert actual_health.fact_commands == ["uname -s"]


def test_native_health_fixture_refuses_local_machine_before_setup(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_health_native_fixture.py"
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


def test_original_metadata_budget_accepts_delayed_supervisor_before_app_calls(helper: Any, monkeypatch: Any) -> None:
    driver = helper.NativeHealth.__new__(helper.NativeHealth)
    driver.data = {"verify_retries": 4, "poll_delay": 5}
    base = helper.NativeHealth.__bases__[0]
    base.health.side_effect = [(False, None), (False, 123), (True, 123)]
    sleep = Mock()
    monkeypatch.setattr(helper.time, "sleep", sleep)
    assert driver.wait_metadata(base.health) == (True, 123)
    assert base.health.call_count == 3
    assert [call.args for call in sleep.call_args_list] == [(5,), (5,)]


def test_original_metadata_budget_exhaustion_and_unknown_errors_do_not_invoke_app(
    helper: Any, monkeypatch: Any
) -> None:
    driver = helper.NativeHealth.__new__(helper.NativeHealth)
    driver.data = {"verify_retries": 3, "poll_delay": 5}
    base = helper.NativeHealth.__bases__[0]
    base.health.return_value = (False, None)
    sleep = Mock()
    monkeypatch.setattr(helper.time, "sleep", sleep)
    assert driver.wait_metadata(base.health) == (False, None)
    assert base.health.call_count == 4
    assert sleep.call_count == 3
    base.health.reset_mock()
    base.health.side_effect = RuntimeError("unavailable metadata")
    with pytest.raises(RuntimeError, match="unavailable metadata"):
        driver.wait_metadata(base.health)
    assert base.health.call_count == 1
    assert sleep.call_count == 3


def test_each_original_metadata_stage_gets_initial_attempt_plus_declared_retries(helper: Any, monkeypatch: Any) -> None:
    driver = helper.NativeHealth.__new__(helper.NativeHealth)
    driver.data = {
        "verify_retries": 1,
        "poll_delay": 5,
        "label": "owned-keeper",
        "expected_argv": ["owned", "host-keep"],
        "user": "fixture",
        "mode": "host",
        "host_tmux": "/owned/tmux",
        "host_socket": "owned",
        "host_tmpdir": "/owned/tmp",
    }
    driver.account = types.SimpleNamespace(pw_uid=501)
    output = b"arguments = {\nowned\nhost-keep\n}\npid = 123\n"
    driver.run = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 113, stdout=b""),
            subprocess.CompletedProcess([], 0, stdout=output),
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0),
        ]
    )
    sleep = Mock()
    monkeypatch.setattr(helper.time, "sleep", sleep)
    assert driver.health() == (True, 123)
    assert [call.args[0][0] for call in driver.run.call_args_list] == [
        "/bin/launchctl",
        "/bin/launchctl",
        "/usr/bin/pgrep",
        "/usr/bin/pgrep",
        "/owned/tmux",
        "/owned/tmux",
    ]
    assert [call.args for call in sleep.call_args_list] == [(5,), (5,), (5,)]
    assert driver.run.call_args.kwargs == {"user": True, "extra": {"TMUX_TMPDIR": "/owned/tmp"}}
    driver.run = Mock(return_value=subprocess.CompletedProcess([], 127, stdout=b"PRIVATE-TOOL-ERROR"))
    with pytest.raises(helper.HealthError, match="runtime_health_launchd_unavailable"):
        driver.health()
    assert driver.run.call_count == 1


def test_default_original_twelve_retries_means_thirteen_attempts(helper: Any, monkeypatch: Any) -> None:
    from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig

    cfg = DaybookRuntimeConfig(user="fixture", revision="a" * 40)
    driver = helper.NativeHealth.__new__(helper.NativeHealth)
    driver.data = {"verify_retries": cfg.verify_retries, "poll_delay": cfg.poll_delay}
    probe, sleep = Mock(return_value=(False, None)), Mock()
    monkeypatch.setattr(helper.time, "sleep", sleep)
    assert driver.wait_metadata(probe) == (False, None)
    assert cfg.verify_retries == 12
    assert probe.call_count == 13
    assert [call.args for call in sleep.call_args_list] == [(cfg.poll_delay,)] * 12


@pytest.mark.parametrize("failed_phase", ["serving", "session"])
def test_unknown_process_or_session_errors_fail_without_poll_retry(
    helper: Any, monkeypatch: Any, failed_phase: str
) -> None:
    driver = helper.NativeHealth.__new__(helper.NativeHealth)
    driver.data = {
        "verify_retries": 12,
        "poll_delay": 5,
        "label": "owned",
        "expected_argv": ["owned"],
        "user": "fixture",
        "mode": "host",
        "host_tmux": "/owned/tmux",
        "host_socket": "owned",
        "host_tmpdir": "/owned/tmp",
    }
    driver.account = types.SimpleNamespace(pw_uid=501)
    label = subprocess.CompletedProcess([], 0, stdout=b"arguments = {\nowned\n}\npid = 123\n")
    results = [label]
    if failed_phase == "session":
        results.append(subprocess.CompletedProcess([], 0))
    results.append(subprocess.CompletedProcess([], 127))
    driver.run = Mock(side_effect=results)
    sleep = Mock()
    monkeypatch.setattr(helper.time, "sleep", sleep)
    with pytest.raises(helper.HealthError, match="unavailable"):
        driver.health()
    assert driver.run.call_count == len(results)
    sleep.assert_not_called()
