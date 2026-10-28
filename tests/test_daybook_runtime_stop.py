"""Original stop ordering/failure tests; no inventory, Journal or real signals."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import types
from dataclasses import replace
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.daybook_operations_runtime import guards
from ops_deploy.services.daybook_operations_runtime.config import RuntimeStopPolicy
from ops_deploy.services.daybook_operations_runtime.guards import RuntimeGuardError, StopState
from ops_deploy.services.daybook_operations_runtime.stop import stop_command
from tests.test_daybook_runtime_contract import config

PACKAGE = files("ops_deploy.services.daybook_operations_runtime")
observer = types.ModuleType("ops_daybook_observer")
observer.__dict__.update(runpy.run_path(str(PACKAGE.joinpath("files/runtime_state.py"))))
sys.modules["ops_daybook_observer"] = observer
sys.modules["ops_daybook_guards"] = guards
MODULE = runpy.run_path(str(PACKAGE.joinpath("files/runtime_stop.py")))
stop = MODULE["stop"]
StopError = MODULE["StopError"]


class Driver:
    def __init__(self, *, running: bool = True) -> None:
        self.cfg = config(action="stop", confirmed=True, mode="host")
        self.state = StopState(True, running, running, running, True, True, 0, 0, ())
        self.events: list[str] = []
        self.fail: str | None = None
        self.second_window = False
        self.busy = False
        self.restored = True

    def snapshot(self) -> StopState:
        self.events.append("snapshot")
        return self.state

    def window(self, running: bool) -> None:
        self.events.append("window")
        if self.second_window and self.events.count("window") == 2:
            raise RuntimeGuardError("runtime_run_window_near_or_active")

    def deliveries(self) -> int:
        self.events.append("deliveries")
        return 1 if self.busy else 0

    def source(self, binding: str) -> Any:
        self.events.append("executor_status:" + binding)
        if self.fail == "status":
            raise StopError("runtime_transition_status_unanswered")
        return types.SimpleNamespace(binding=binding, active_state=None)

    def wait(self, predicate: Any, retries: int, delay: int) -> bool:
        self.events.append("wait:" + str(retries) + ":" + str(delay))
        return bool(predicate())

    def bootout(self) -> None:
        self.events.append("bootout")
        if self.fail == "bootout":
            raise StopError("runtime_stop_bootout_failed")

    def unloaded(self) -> bool:
        self.events.append("unloaded")
        return self.fail != "unloaded"

    def terminate(self) -> None:
        self.events.append("TERM")

    def gone(self) -> bool:
        self.events.append("gone")
        return self.fail != "gone"

    def session_gone(self) -> bool:
        self.events.append("session_gone")
        return self.fail != "session"

    def drained(self) -> bool:
        self.events.append("drained")
        return self.fail != "store"

    def restore(self) -> bool:
        self.events.append("restore_keeper")
        return self.restored


def test_original_stop_order_quiet_windows_term_and_drained() -> None:
    driver = Driver()
    assert stop(driver)["stopped"] is True
    actions = [e for e in driver.events if not e.startswith("wait:")]
    assert actions == [
        "snapshot",
        "window",
        "deliveries",
        "executor_status:regular",
        "snapshot",
        "window",
        "bootout",
        "unloaded",
        "TERM",
        "gone",
        "session_gone",
        "drained",
    ]
    assert "wait:30:10" in driver.events
    assert "wait:60:5" in driver.events


@pytest.mark.parametrize("failure", ["bootout", "unloaded", "gone", "session", "store"])
def test_original_post_bootout_failure_restores_keeper_before_failure(failure: str) -> None:
    driver = Driver()
    driver.fail = failure
    with pytest.raises(StopError, match="keeper_restored"):
        stop(driver)
    assert driver.events[-1] == "restore_keeper"
    assert "drained" not in driver.events or failure == "store"


def test_failed_restore_is_genuine_failed_state() -> None:
    driver = Driver()
    driver.fail = "gone"
    driver.restored = False
    with pytest.raises(StopError, match="keeper_NOT_restored"):
        stop(driver)


@pytest.mark.parametrize("failure", ["status", "busy", "second_window", "halt", "not_keeper", "no_gui", "no_host"])
def test_original_pre_mutation_refusals_preserve_keeper(failure: str) -> None:
    driver = Driver()
    if failure == "status":
        driver.fail = "status"
    elif failure == "busy":
        driver.busy = True
    elif failure == "second_window":
        driver.second_window = True
    else:
        field, value = {
            "halt": ("halts", 1),
            "not_keeper": ("label_runs_keeper", False),
            "no_gui": ("aqua", False),
            "no_host": ("capability_host", False),
        }[failure]
        changes: dict[str, Any] = {field: value}
        driver.state = replace(driver.state, **changes)
    with pytest.raises((StopError, RuntimeGuardError)):
        stop(driver)
    assert "bootout" not in driver.events
    assert "TERM" not in driver.events
    assert "restore_keeper" not in driver.events


def test_already_stopped_recovery_keeps_original_status_effects_without_signal() -> None:
    driver = Driver(running=False)
    assert stop(driver)["stopped"] is True
    assert "executor_status:regular" in driver.events
    assert "bootout" not in driver.events
    assert "TERM" not in driver.events
    assert "wait:0:10" in driver.events


def test_stop_policy_original_defaults_and_same_day_validation() -> None:
    assert RuntimeStopPolicy().model_dump() == {"windows": (), "lead_minutes": 0, "timezone": "Europe/Berlin"}
    with pytest.raises(ValidationError):
        RuntimeStopPolicy.model_validate({"windows": [{"start": "00:10", "end": "02:00"}], "lead_minutes": 20})


def test_actual_embedded_stop_cli_refuses_invalid_request_without_raw_output(tmp_path: Path) -> None:
    import shlex

    argv = shlex.split(stop_command())
    argv[0] = sys.executable
    private = "UNUSABLE-OWNED-REQUEST-BODY"
    result = subprocess.run(argv, input=json.dumps({"private": private}), text=True, capture_output=True, timeout=10)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == "runtime_stop_failed"
    assert private not in result.stderr


@pytest.mark.parametrize("as_user", [False, True])
def test_native_executor_uses_original_account_login_flags_and_sanitizes_body(
    monkeypatch: pytest.MonkeyPatch, as_user: bool
) -> None:
    import os
    from unittest.mock import Mock

    account_uid = os.geteuid() if as_user else os.geteuid() + 1
    driver = MODULE["NativeStop"].__new__(MODULE["NativeStop"])
    driver.account = types.SimpleNamespace(pw_uid=account_uid, pw_dir="/Users/owned")
    driver.data = config(mode="host").model_dump(mode="json")
    response = {"server": {"active_state": "pending", "private": "UNUSABLE-SYNTHETIC-BODY"}}
    command = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(response).encode(), b""))
    monkeypatch.setattr(subprocess, "run", command)
    result = driver.source("regular")
    assert vars(result) == {"binding": "regular", "active_state": "pending"}
    argv = command.call_args.args[0]
    if not as_user:
        assert argv[:8] == ["/usr/bin/sudo", "-H", "-S", "-n", "-i", "-u", driver.data["user"], "--"]
    else:
        assert argv[0] == driver.data["python"]
    assert "timeout" not in command.call_args.kwargs
    assert command.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    command.return_value = subprocess.CompletedProcess([], 1, b"PRIVATE-ERROR-BODY", b"PRIVATE-ERROR-BODY")
    with pytest.raises(StopError, match=r"^runtime_transition_status_unanswered$"):
        driver.source("regular")


def test_original_role_stop_commands_and_bounds_are_the_source_oracle() -> None:
    import os

    import yaml

    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Actual paired stop role oracle runs explicitly during qualification")
    role = Path(source) / "roles/daybook_operations_runtime_deploy"
    tasks = yaml.safe_load((role / "tasks/stop.yml").read_text())
    commands = {task["name"]: task["ansible.builtin.command"] for task in tasks if "ansible.builtin.command" in task}
    status = commands["stop | Ask the server about each source this machine runs"]["argv"]
    assert status == [
        "{{ daybook_operations_runtime_python }}",
        "-I",
        "-c",
        "from daybook.cli import main; raise SystemExit(main())",
        "operations",
        "status",
        "--policy",
        "{{ daybook_operations_runtime_policy }}",
        "--policy-owner",
        "{{ daybook_operations_runtime_owner }}",
        "--binding",
        "{{ item }}",
    ]
    status_task = next(t for t in tasks if t["name"] == "stop | Ask the server about each source this machine runs")
    assert status_task["become_flags"] == "-H -S -n -i"
    host_task = next(t for t in tasks if t["name"] == "stop | Ask whether the capability host is running")
    assert host_task["become_flags"] == "-H -S -n -i"
    assert host_task["environment"] == {"TMUX_TMPDIR": "{{ daybook_operations_runtime_host_tmpdir }}"}
    defaults = yaml.safe_load((role / "defaults/main.yml").read_text())
    cfg = config()
    for name in ("quiet_retries", "quiet_delay", "stop_timeout", "poll_delay"):
        assert getattr(cfg, name) == defaults["daybook_operations_runtime_" + name]
    window = RuntimeStopPolicy()
    assert list(window.windows) == defaults["daybook_operations_runtime_stop_windows"]
    assert window.lead_minutes == defaults["daybook_operations_runtime_stop_window_lead_minutes"]
    assert window.timezone == defaults["daybook_operations_runtime_stop_window_timezone"]
    code = yaml.safe_load((role / "tasks/code.yml").read_text())
    python_find = next(task for task in code if task["name"] == "code | Find the pinned interpreter")
    assert python_find["environment"]["UV_PYTHON_PREFERENCE"] == "only-managed"
    host_script = PACKAGE.joinpath("files/runtime_stop.py").read_text()
    assert '"/bin/kill", "-TERM", *pids' in host_script
    assert '"-KILL"' not in host_script
    assert '"kill-session"' not in host_script


def test_original_serving_only_failure_also_attempts_keeper_recovery() -> None:
    driver = Driver()
    driver.state = replace(driver.state, label_loaded=False, label_runs_keeper=False)
    driver.fail = "gone"
    with pytest.raises(StopError, match="keeper_restored"):
        stop(driver)
    assert "bootout" not in driver.events
    assert "TERM" in driver.events
    assert driver.events[-1] == "restore_keeper"


def test_original_rescue_recovers_keeper_even_if_initial_label_was_unloaded() -> None:
    import os

    import yaml

    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Actual paired rescue oracle runs explicitly during qualification")
    tasks = yaml.safe_load((Path(source) / "roles/daybook_operations_runtime_deploy/tasks/stop.yml").read_text())
    rescue = next(task["rescue"] for task in tasks if task["name"] == "stop | Stop the supervisor")
    frozen = yaml.safe_load((Path(__file__).parent / "fixtures/daybook-runtime-stop-rescue-cf3.yml").read_text())
    assert frozen["rescue"] == rescue
    enable = next(task for task in rescue if task["name"] == "stop | Enable the keeper label")
    bootstrap = next(task for task in rescue if task["name"] == "stop | Boot the keeper back in")
    assert enable["when"] == "daybook_operations_runtime_stop_is_keeper | bool"
    assert bootstrap["when"] == "daybook_operations_runtime_stop_is_keeper | bool"
    assert "stop_label" not in str(enable["when"])
    assert "stop_label" not in str(bootstrap["when"])
