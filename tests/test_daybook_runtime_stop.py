"""Original stop ordering/failure tests; no inventory, Journal or real signals."""

from __future__ import annotations

import base64
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
    command = Mock(
        return_value=subprocess.CompletedProcess(
            [],
            0,
            b"unrelated profile banner\n"
            + MODULE["STATUS_FRAME"]
            + base64.b64encode(json.dumps(response).encode())
            + b"\nlogout profile banner\n",
            b"",
        )
    )
    monkeypatch.setattr(subprocess, "run", command)
    result = driver.source("regular")
    assert vars(result) == {"binding": "regular", "active_state": "pending"}
    argv = command.call_args.args[0]
    if not as_user:
        assert argv[:8] == ["/usr/bin/sudo", "-H", "-S", "-n", "-i", "-u", driver.data["user"], "--"]
    else:
        assert argv[0] == driver.data["python"]
    tail = argv if as_user else argv[8:]
    assert tail == [
        driver.data["python"],
        "-I",
        "-c",
        MODULE["STATUS_CAPTURE"],
        driver.data["python"],
        "-I",
        "-c",
        "from daybook.cli import main; raise SystemExit(main())",
        "operations",
        "status",
        "--policy",
        driver.data["policy"],
        "--policy-owner",
        driver.data["owner"],
        "--binding",
        "regular",
    ]
    assert "timeout" not in command.call_args.kwargs
    assert command.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    command.return_value = subprocess.CompletedProcess([], 1, b"PRIVATE-ERROR-BODY", b"PRIVATE-ERROR-BODY")
    with pytest.raises(StopError, match=r"^runtime_transition_status_unanswered$"):
        driver.source("regular")


def test_original_serving_only_failure_also_attempts_keeper_recovery() -> None:
    driver = Driver()
    driver.state = replace(driver.state, label_loaded=False, label_runs_keeper=False)
    driver.fail = "gone"
    with pytest.raises(StopError, match="keeper_restored"):
        stop(driver)
    assert "bootout" not in driver.events
    assert "TERM" in driver.events
    assert driver.events[-1] == "restore_keeper"


@pytest.mark.parametrize("exit_code", [0, 7])
def test_actual_managed_status_capture_preserves_cli_bytes_and_failure(exit_code: int) -> None:
    private = "OWNED-SYNTHETIC-STATUS-BODY"
    child = "import sys;sys.stdout.write(sys.argv[1]);sys.stderr.write(sys.argv[1]);raise SystemExit(int(sys.argv[2]))"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            MODULE["STATUS_CAPTURE"],
            sys.executable,
            "-I",
            "-c",
            child,
            private,
            str(exit_code),
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == exit_code
    assert completed.stderr == b""
    assert completed.stdout.startswith(MODULE["STATUS_FRAME"])
    assert (
        base64.b64decode(completed.stdout.partition(MODULE["STATUS_FRAME"])[2].strip(), validate=True)
        == private.encode()
    )


@pytest.mark.parametrize("body", [b"", b"profile banner\n{}", b"\nOPS_DAYBOOK_EXECUTOR_STDOUT=invalid!"])
def test_managed_status_requires_actual_capture_frame_without_leaking_body(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
) -> None:
    import os
    from unittest.mock import Mock

    driver = MODULE["NativeStop"].__new__(MODULE["NativeStop"])
    driver.account = types.SimpleNamespace(pw_uid=os.geteuid())
    driver.data = config(mode="host").model_dump(mode="json")
    monkeypatch.setattr(subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 0, body, b"")))
    with pytest.raises(StopError, match=r"^runtime_transition_status_invalid$"):
        driver.source("regular")
