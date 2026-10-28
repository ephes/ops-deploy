"""Managed transition caller ordering and failure guards, no real app or host."""

from __future__ import annotations

import importlib.resources
import json
import sys
import types
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig
from ops_deploy.services.daybook_operations_runtime.guards import (
    RuntimeGuardError,
    TransitionStatus,
    parse_transition_status,
    require_profile_transition,
    require_start_status,
    require_transition_status,
)
from ops_deploy.services.daybook_operations_runtime.render import render_resource


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    # Only the production orchestrator is exercised here. Native/root/GUI tests
    # must separately qualify the real driver, source and filesystem boundaries.
    dependencies: dict[str, dict[str, Any]] = {
        "ops_daybook_guards": {
            "require_profile_transition": require_profile_transition,
            "parse_transition_status": parse_transition_status,
            "require_transition_status": require_transition_status,
            "require_start_status": require_start_status,
        },
        "ops_daybook_observer": {
            "NativeProbes": object,
            "safe_file": Mock(),
            "code_current": Mock(),
            "store_count": Mock(),
        },
        "ops_daybook_stage": {"make_directory": Mock(), "put": Mock(), "validate_client": Mock()},
        "ops_transition_filesystem": {"directory_fd": Mock(), "put_bytes": Mock(), "remove_declared_file": Mock()},
    }
    for name, values in dependencies.items():
        module = types.ModuleType(name)
        module.__dict__.update(values)
        monkeypatch.setitem(sys.modules, name, module)
    module = types.ModuleType("owned_runtime_transition")
    source = importlib.resources.files("ops_deploy.services.daybook_operations_runtime").joinpath(
        "files/runtime_transition.py"
    )
    exec(compile(source.read_bytes(), "<actual-runtime-transition>", "exec"), module.__dict__)
    return module


class Driver:
    def __init__(
        self,
        action: str = "cutover",
        *,
        start: bool = True,
        loaded: bytes | None = None,
        serving: bool = False,
        closed: bool = False,
        drained: bool = True,
        current: bool = True,
    ) -> None:
        self.cfg = DaybookRuntimeConfig(user="fixture", revision="a" * 40, action=action, confirmed=True, start=start)
        old = self.cfg.model_copy(update={"action": "install", "start": False})
        self.profile: dict[str, Any] = json.loads(render_resource(old, "policy.json.j2"))
        self.calls: list[str] = []
        self.loaded = loaded
        self.has_serving = serving
        self.closed = closed
        self.drained = drained
        self.current = current
        self.before = TransitionStatus(action == "rollback", "idle", None, action != "rollback")
        self.ready = TransitionStatus(action == "cutover", "idle", None, action == "cutover")
        self.client_count = 0

    def source_current(self) -> None:
        self.calls.append("source")
        if not self.current:
            raise RuntimeError("runtime_transition_source_not_current")

    def previous(self) -> dict[str, Any]:
        self.calls.append("previous")
        return self.profile

    def label(self) -> SimpleNamespace:
        self.calls.append("label")
        return SimpleNamespace(returncode=113 if self.loaded is None else 0, stdout=self.loaded or b"")

    def serving(self) -> bool:
        self.calls.append("serving")
        return self.has_serving

    def closed_out(self) -> bool:
        self.calls.append("closed")
        return self.closed

    def client(self, command: str) -> TransitionStatus | None:
        self.calls.append("client-" + command)
        if command == "idle":
            return None
        self.client_count += 1
        return self.before if self.client_count == 1 else self.ready

    def validate_commands(self) -> None:
        self.calls.append("command-preconditions")

    def prepare_resources(self) -> None:
        self.calls.append("prepare")

    def disable(self) -> None:
        self.calls.append("disable")

    def unload_idle(self) -> None:
        self.calls.append("unload")

    def old_store_empty(self) -> bool:
        self.calls.append("store")
        return self.drained

    def select_command(self) -> bool:
        self.calls.append("select")
        return True

    def publish_policy(self) -> None:
        self.calls.append("policy-and-constructor")

    def start(self, has_command: bool) -> None:
        ready = self.client("status")
        assert ready is not None
        require_start_status(self.cfg.action, ready)
        assert has_command
        self.calls.append("enable-and-bootstrap")


def test_cutover_preserves_original_managed_order_and_start_checks(helper: Any) -> None:
    driver = Driver()
    assert helper.transition(driver) == {"transitioned": True, "started": True}
    assert driver.calls == [
        "source",
        "previous",
        "label",
        "serving",
        "closed",
        "command-preconditions",
        "client-status",
        "prepare",
        "disable",
        "unload",
        "client-idle",
        "select",
        "policy-and-constructor",
        "client-status",
        "enable-and-bootstrap",
    ]


def test_start_false_leaves_original_selected_profile_without_enabling_scheduler(helper: Any) -> None:
    driver = Driver(start=False)
    assert helper.transition(driver) == {"transitioned": True, "started": False}
    assert driver.calls[-1] == "policy-and-constructor"
    assert "enable-and-bootstrap" not in driver.calls


@pytest.mark.parametrize("loaded", [b"\tserve\n", b"\thost-keep\n"])
def test_active_runtime_label_refuses_before_app_status_or_mutation(helper: Any, loaded: bytes) -> None:
    driver = Driver(loaded=loaded)
    with pytest.raises(helper.TransitionError, match="requires_quiescence"):
        helper.transition(driver)
    assert "client-status" not in driver.calls
    assert "prepare" not in driver.calls
    assert "disable" not in driver.calls


def test_detached_supervisor_also_refuses_before_mutation(helper: Any) -> None:
    driver = Driver(serving=True)
    with pytest.raises(helper.TransitionError, match="requires_quiescence"):
        helper.transition(driver)
    assert "prepare" not in driver.calls


def test_wrong_source_refuses_before_any_profile_or_application_read(helper: Any) -> None:
    driver = Driver(current=False)
    with pytest.raises(RuntimeError, match="source_not_current"):
        helper.transition(driver)
    assert driver.calls == ["source"]


def test_rollback_after_original_closeout_refuses_before_app_or_mutation(helper: Any) -> None:
    driver = Driver("rollback", closed=True)
    with pytest.raises(RuntimeGuardError, match="closed_out_rollback_refused"):
        helper.transition(driver)
    assert "client-status" not in driver.calls
    assert "prepare" not in driver.calls


def test_rollback_unresolved_store_refuses_before_command_or_policy_replacement(helper: Any) -> None:
    driver = Driver("rollback", drained=False)
    with pytest.raises(helper.TransitionError, match="rollback_store_not_drained"):
        helper.transition(driver)
    assert driver.calls[-1] == "store"
    assert "select" not in driver.calls
    assert "policy-and-constructor" not in driver.calls


def test_unreconciled_original_status_refuses_before_disable(helper: Any) -> None:
    driver = Driver()
    driver.before = TransitionStatus(True, "idle", None, True)
    with pytest.raises(RuntimeGuardError, match="existing_state_not_reconciled"):
        helper.transition(driver)
    assert driver.calls[-1] == "client-status"
    assert "prepare" not in driver.calls


def test_failed_start_readiness_retains_real_intermediate_mutation_and_does_not_bootstrap(helper: Any) -> None:
    driver = Driver()
    driver.ready = TransitionStatus(True, "idle", None, False)
    with pytest.raises(RuntimeGuardError, match="start_not_reconciled"):
        helper.transition(driver)
    assert "policy-and-constructor" in driver.calls
    assert "enable-and-bootstrap" not in driver.calls


def test_static_command_precondition_failure_precedes_any_mutation(helper: Any) -> None:
    driver = Driver()

    def refuse() -> None:
        driver.calls.append("command-preconditions")
        raise helper.TransitionError("runtime_transition_command_boundary_invalid")

    driver.validate_commands = refuse  # type: ignore[method-assign]
    with pytest.raises(helper.TransitionError, match="command_boundary_invalid"):
        helper.transition(driver)
    assert driver.calls[-1] == "command-preconditions"
    assert "prepare" not in driver.calls
    assert "disable" not in driver.calls
    assert "unload" not in driver.calls
    assert "select" not in driver.calls
