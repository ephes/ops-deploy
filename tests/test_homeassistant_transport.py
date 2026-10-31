"""Actual SDK precedence and protected connector boundary; no SSH/sudo execution."""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import Mock

import pytest
from pyinfra.api import Config, Inventory, State, StringCommand
from pyinfra.api.arguments import CONNECTOR_ARGUMENT_KEYS, AllArguments, pop_global_arguments
from pyinfra.connectors.util import CommandOutput

from ops_deploy.services.homeassistant.transport import run_protected_command


def test_actual_sdk_config_host_deploy_operation_and_explicit_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config(SUDO=True, SUDO_USER="config-user", USE_SUDO_PASSWORD=False)
    state = State(Inventory(([("owned", {"_sudo_user": "host-user"})], {})), config)
    target = state.inventory.get_host("owned")
    runner = Mock(return_value=(True, CommandOutput([])))
    monkeypatch.setattr(target, "run_shell_command", runner)
    command = StringCommand("owned read-only fixture command")
    run_protected_command(target, command)
    kwargs = runner.call_args.kwargs
    assert kwargs["_sudo"] is True
    assert kwargs["_sudo_user"] == "host-user"
    target.current_deploy_kwargs = cast(AllArguments, {"_sudo_user": "deploy-user", "_timeout": 99})
    run_protected_command(target, command)
    assert runner.call_args.kwargs["_sudo_user"] == "deploy-user"
    target.current_op_global_arguments = cast(AllArguments, {"_sudo": False, "_sudo_user": "operation-user"})
    run_protected_command(target, command, _timeout=17)
    kwargs = runner.call_args.kwargs
    assert kwargs["_sudo"] is False
    assert kwargs["_sudo_user"] == "operation-user"
    assert kwargs["_timeout"] == 17
    run_protected_command(target, command, _sudo_user="explicit-user")
    assert runner.call_args.kwargs["_sudo_user"] == "explicit-user"


def test_matches_sdk_fact_resolution_but_forces_private_output_in_verbose_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    state = State(Inventory(([("owned", {"_su_user": "owned-su", "_get_pty": True})], {})), Config())
    state.print_fact_input = True
    state.print_fact_output = True
    target = state.inventory.get_host("owned")
    target.current_deploy_kwargs = cast(AllArguments, {"_env": {"OWNED": "value"}, "_shell_executable": "sh"})
    target.current_op_global_arguments = cast(AllArguments, {"_timeout": 99, "_sudo": False})
    runner = Mock(return_value=(True, CommandOutput([])))
    monkeypatch.setattr(target, "run_shell_command", runner)
    override = {"_timeout": 21, "_stdin": "owned-private-body-9751", "_get_pty": False}
    expected, _ = pop_global_arguments(state, target, {**target.current_op_global_arguments, **override})
    run_protected_command(target, StringCommand("owned fixture"), **override)
    kwargs = runner.call_args.kwargs
    assert kwargs == {
        **{key: value for key, value in expected.items() if key in CONNECTOR_ARGUMENT_KEYS},
        "print_input": False,
        "print_output": False,
    }
    assert state.print_fact_input is True
    assert state.print_fact_output is True
    assert dict(target.current_op_global_arguments) == {"_timeout": 99, "_sudo": False}


@pytest.mark.parametrize("override", [{"print_output": True}, {"print_input": True}, {"_owned_typo": True}])
def test_unknown_or_body_printing_override_fails_before_connector(
    monkeypatch: pytest.MonkeyPatch, override: dict[str, Any]
) -> None:
    state = State(Inventory(([("owned", {})], {})), Config())
    target = state.inventory.get_host("owned")
    runner = Mock()
    monkeypatch.setattr(target, "run_shell_command", runner)
    with pytest.raises(ValueError, match="unsupported protected"):
        run_protected_command(target, StringCommand("owned fixture"), **override)
    runner.assert_not_called()


@pytest.mark.parametrize("operation_sudo", [None, False, True])
def test_actual_deploy_operation_security_reader_chain_preserves_privilege_and_privacy(
    monkeypatch: pytest.MonkeyPatch, operation_sudo: bool | None
) -> None:
    from collections.abc import Generator

    from pyinfra import host
    from pyinfra.api import deploy, operation
    from pyinfra.connectors.fake import FakeConnector

    from ops_deploy.services.homeassistant.security import _read
    from ops_deploy.testing import run_deploy_fake

    captured = []
    original = FakeConnector.run_shell_command

    def execute(self: Any, command: Any, *args: Any, **kwargs: Any) -> Any:
        if str(command) == "owned-inspection":
            captured.append(kwargs.copy())
        return original(self, command, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", execute)

    @operation()
    def inspect() -> Generator[StringCommand, None, None]:
        assert _read(host, "owned-inspection") == "owned-response"
        yield StringCommand("owned-fixture-operation")

    @deploy("Owned privilege fixture")
    def outer() -> None:
        if operation_sudo is None:
            inspect()
        else:
            inspect(_sudo=operation_sudo)

    result = run_deploy_fake(
        outer,
        responses={"owned-inspection": ["owned-response"]},
        host_data={"_sudo": False, "_sudo_user": "owned-root"},
        _sudo=True,
    )
    assert result.succeeded, result.error
    assert captured
    for kwargs in captured:
        assert kwargs["_sudo"] is (True if operation_sudo is None else operation_sudo)
        assert kwargs["_sudo_user"] == "owned-root"
        assert kwargs["_timeout"] == 60
        assert kwargs["print_input"] is False
        assert kwargs["print_output"] is False
