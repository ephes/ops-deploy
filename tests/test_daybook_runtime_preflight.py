"""Original managed preflight orchestration; no actual app or host calls."""

from __future__ import annotations

import dataclasses
import importlib.resources
import sys
import types
from typing import Any
from unittest.mock import Mock

import pytest

from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig, guards
from ops_deploy.services.daybook_operations_runtime.guards import StopState


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    class LabelBase:
        observation: Any

        def label(self) -> Any:
            return self.observation

    dependencies = {
        "ops_daybook_guards": vars(guards),
        "ops_daybook_observer": {"MAX_INPUT": 8192, "ObservationError": RuntimeError},
        "ops_daybook_stop": {"NativeStop": LabelBase, "StopError": RuntimeError},
    }
    for name, attrs in dependencies.items():
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, name, module)
    module = types.ModuleType("owned_pure_preflight")
    body = (
        importlib.resources.files("ops_deploy.services.daybook_operations_runtime")
        .joinpath("files/runtime_preflight.py")
        .read_bytes()
    )
    exec(compile(body, "<actual-preflight>", "exec"), module.__dict__)
    return module


class Driver:
    def __init__(self, *, running: bool = True) -> None:
        self.cfg = DaybookRuntimeConfig(user="fixture", revision="a" * 40, mode="host", action="stop", confirmed=True)
        self.state = StopState(True, running, running, running, True, True, 0, 0, ())
        self.events: list[str] = []

    def snapshot(self) -> StopState:
        self.events.append("metadata")
        return self.state

    def window(self, running: bool) -> None:
        self.events.append("window-running" if running else "window-stopped")

    def __getattr__(self, name: str) -> Any:
        raise AssertionError("unexpected nonmetadata driver use: " + name)


@pytest.mark.parametrize("running", [True, False])
def test_original_preflight_queries_sources_once_and_never_stops(helper: Any, running: bool) -> None:
    class ManagedDriver(Driver):
        def source(self, binding: str) -> Any:
            self.events.append("executor:" + binding)
            return types.SimpleNamespace(binding=binding, active_state=None)

    driver = ManagedDriver(running=running)
    driver.cfg = driver.cfg.model_copy(update={"status_sources": ("regular", "long")})
    assert helper.original_preflight({}, driver) == {
        "ready": True,
        "running": running,
        "managed_cli_calls": 2,
        "stopped": False,
    }
    assert driver.events == [
        "metadata",
        "window-running" if running else "window-stopped",
        "executor:regular",
        "executor:long",
    ]


@pytest.mark.parametrize("fault", ["halt", "delivery", "aqua", "capability", "assigned", "unanswered"])
def test_original_unready_preflight_does_not_stop_or_change_source(helper: Any, fault: str) -> None:
    class ManagedDriver(Driver):
        def source(self, binding: str) -> Any:
            self.events.append("executor:" + binding)
            if fault == "unanswered":
                raise RuntimeError("runtime_transition_status_unanswered")
            return types.SimpleNamespace(binding=binding, active_state="assigned" if fault == "assigned" else None)

    driver = ManagedDriver()
    fields: dict[str, dict[str, Any]] = {
        "halt": {"halts": 1},
        "delivery": {"deliveries": 1},
        "aqua": {"aqua": False},
        "capability": {"capability_host": False},
    }
    driver.state = dataclasses.replace(driver.state, **fields.get(fault, {}))
    with pytest.raises(RuntimeError):
        helper.original_preflight({}, driver)
    assert all(event in {"metadata", "window-running", "executor:regular"} for event in driver.events)


def test_original_window_refusal_precedes_executor_effects(helper: Any) -> None:
    driver = Driver()
    driver.window = Mock(side_effect=guards.RuntimeGuardError("runtime_run_window_near_or_active"))  # type: ignore[method-assign]
    with pytest.raises(guards.RuntimeGuardError, match="run_window"):
        helper.original_preflight({}, driver)
    assert driver.events == ["metadata"]


@pytest.mark.parametrize("stderr", [b"", b"Permission denied", b'Could not find service "other" in domain'])
def test_nonabsence_label_errors_never_become_unloaded_metadata(helper: Any, stderr: bytes) -> None:
    import subprocess

    driver = helper.NativePreflight.__new__(helper.NativePreflight)
    driver.data = {"label": "owned-exact"}
    driver.observation = subprocess.CompletedProcess([], 113, stdout=b"", stderr=stderr)
    with pytest.raises(RuntimeError, match="label_unavailable"):
        driver.label()


def test_actual_known_absent_label_is_retained(helper: Any) -> None:
    import subprocess

    driver = helper.NativePreflight.__new__(helper.NativePreflight)
    driver.data = {"label": "owned-exact"}
    driver.observation = subprocess.CompletedProcess(
        [], 113, stdout=b"", stderr=b'Could not find service "owned-exact" in domain for user gui: 501'
    )
    assert driver.label() is driver.observation


def test_actual_controller_preflight_queues_managed_app_work() -> None:
    from ops_deploy.services.daybook_operations_runtime import RuntimeStopPolicy, check_daybook_runtime_update
    from ops_deploy.testing import run_deploy_fake

    cfg = DaybookRuntimeConfig(user="fixture", revision="a" * 40, mode="host", action="stop", confirmed=True)
    run = run_deploy_fake(
        check_daybook_runtime_update, cfg, policy=RuntimeStopPolicy(), responses={"uname -s": ["Darwin"]}
    )
    assert run.succeeded, run.error
    assert len(run.ops) == 1
    assert run.ops[0].read_only is False
    assert len(run.mutating_changed_ops) == 1
    assert run.fact_commands == ["uname -s"]
    assert run.uploaded_paths == []
