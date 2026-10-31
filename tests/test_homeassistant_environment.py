"""Actual SDK generator sequencing with synthetic environment facts, not native HA."""

from __future__ import annotations

import shlex
from collections.abc import Generator
from typing import Any

import pytest
from pyinfra import state
from pyinfra.api import Config, StringCommand
from pyinfra.connectors.fake import FakeConnector
from pyinfra.connectors.util import CommandOutput
from pyinfra.operations import systemd

from ops_deploy.services.homeassistant import environment
from ops_deploy.services.homeassistant.python_state import EnvironmentState
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake


@pytest.fixture
def fixture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    values: dict[str, Any] = {
        "current": EnvironmentState(True, "Python 3.14.8"),
        "present": True,
        "observations": [],
        "stops": [],
    }
    monkeypatch.setattr(environment, "find_python", lambda cfg: "/owned/python3.14")

    def observe(cfg: HomeAssistantRuntimeConfig, kind: str, phase: str) -> EnvironmentState:
        values["observations"].append((state.is_executing, kind, phase))
        current = values["current"]
        assert isinstance(current, EnvironmentState)
        return current

    def stop(*, service: str, running: bool) -> Generator[StringCommand, None, None]:
        assert running is False
        values["stops"].append(service)
        yield StringCommand("systemctl stop " + service)

    monkeypatch.setattr(environment, "_observe", observe)
    monkeypatch.setattr(environment, "_present", lambda *args: values["present"])
    monkeypatch.setattr(systemd.service, "_inner", stop)
    return values


@pytest.mark.parametrize("matter", [False, True])
def test_current_environment_entire_operation_noop(fixture: dict[str, Any], matter: bool) -> None:
    run = run_deploy_fake(lambda: environment.prepare_environment(HomeAssistantRuntimeConfig(), matter=matter))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.executed_commands == []
    assert run.uploads == []
    assert fixture["stops"] == []
    assert all(phase == "environment" for _, _, phase in fixture["observations"])


@pytest.mark.parametrize("matter", [False, True])
def test_original_stop_remove_create_order(fixture: dict[str, Any], matter: bool) -> None:
    fixture["current"] = EnvironmentState(True, "Python 3.13.9")
    cfg = HomeAssistantRuntimeConfig(manage_matter_server=False)
    run = run_deploy_fake(lambda: environment.prepare_environment(cfg, matter=matter))
    assert run.succeeded, run.error
    commands = run.executed_commands
    stops = (
        ["systemctl stop matter-server"] if matter else ["systemctl stop matter-server", "systemctl stop homeassistant"]
    )
    assert commands[: len(stops)] == stops
    path = cfg.matter_server_virtualenv_path if matter else cfg.virtualenv_path
    assert commands[len(stops)] == "rm -rf -- " + path
    assert commands[-1] == environment.create_command(cfg, "matter" if matter else "homeassistant", "/owned/python3.14")
    assert len(run.mutating_changed_ops) == 1
    assert run.uploads == []


def test_missing_python_does_not_stop_existing_units(fixture: dict[str, Any]) -> None:
    fixture["current"] = EnvironmentState(False)
    fixture["present"] = False
    run = run_deploy_fake(lambda: environment.prepare_environment(HomeAssistantRuntimeConfig()))
    assert run.succeeded, run.error
    assert fixture["stops"] == []
    assert len(run.executed_commands) == 1
    assert " venv --seed " in run.executed_commands[0]


def test_missing_requested_interpreter_fails_before_observation_or_mutation(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(environment, "find_python", lambda cfg: None)
    run = run_deploy_fake(lambda: environment.prepare_environment(HomeAssistantRuntimeConfig()))
    assert not run.succeeded
    assert fixture["observations"] == []
    assert run.executed_commands == []


def test_install_failure_retains_actual_stop_and_removal_without_recovery(fixture: dict[str, Any]) -> None:
    fixture["current"] = EnvironmentState(True, "Python 3.13.9")
    run = run_deploy_fake(
        lambda: environment.prepare_environment(HomeAssistantRuntimeConfig()),
        responses={" venv --seed ": {"success": False}},
    )
    assert not run.succeeded
    assert run.ops[0].succeeded is False
    assert run.executed_commands[:3] == [
        "systemctl stop matter-server",
        "systemctl stop homeassistant",
        "rm -rf -- /home/homeassistant/site/.venv",
    ]
    assert len(run.executed_commands) == 4
    assert not any("start " in command for command in run.executed_commands)


@pytest.mark.parametrize("deferred", [False, True])
def test_execution_rechecks_after_prior_interpreter_link_update(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch, deferred: bool
) -> None:
    from pyinfra.operations import server

    fixture["current"] = EnvironmentState(True, "Python 3.13.9")
    original = FakeConnector.run_shell_command

    def command(self: FakeConnector, cmd: Any, *args: Any, **kwargs: Any) -> Any:
        text = cmd if isinstance(cmd, str) else cmd.get_raw_value()
        if text == "synthetic-update-python-link":
            fixture["current"] = EnvironmentState(True, "Python 3.14.8")
            return True, CommandOutput([])
        return original(self, cmd, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", command)

    def deploy() -> None:
        server.shell(commands=["synthetic-update-python-link"])
        environment.prepare_environment(HomeAssistantRuntimeConfig(), deferred=deferred)

    run = run_deploy_fake(deploy, pyinfra_config=Config(DIFF=True))
    assert run.succeeded, run.error
    assert run.executed_commands == ["synthetic-update-python-link"]
    assert run.ops[-1].changed is False
    assert fixture["observations"][-1] == (True, "homeassistant", "environment")


def test_original_argv_user_home_destination_and_quoting() -> None:
    cfg = HomeAssistantRuntimeConfig(user="owned", home="/srv/owned", site_path="/srv/owned-site")
    for kind in ("homeassistant", "matter"):
        command = environment.create_command(cfg, kind, "/owned/python path")
        assert command.startswith("cd /srv/owned-site && ")
        argv = shlex.split(command.split(" && ", 1)[1])
        assert argv[:7] == ["runuser", "-u", "owned", "--", "env", "HOME=/srv/owned", "/usr/local/bin/uv"]
        assert argv[7:11] == ["venv", "--seed", "--python", "/owned/python path"]
        assert argv[11:] == ([cfg.matter_server_virtualenv_path] if kind == "matter" else [])


def test_actual_pending_interpreter_operation_binds_change_checking_plan(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from pyinfra.connectors.util import OutputLine

    from ops_deploy.services.homeassistant import interpreter

    cfg = HomeAssistantRuntimeConfig()
    installed = False
    original = FakeConnector.run_shell_command
    monkeypatch.setattr(environment, "find_python", interpreter.find_python)

    def command(self: FakeConnector, cmd: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal installed
        text = cmd if isinstance(cmd, str) else cmd.get_raw_value()
        if "python install" in text:
            installed = True
            return True, CommandOutput([])
        if "python find" in text:
            return installed, CommandOutput([OutputLine("stdout", "/owned/python3.14" if installed else "")])
        return original(self, cmd, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", command)

    def deploy() -> None:
        installation = interpreter.install_python(cfg)
        environment.prepare_environment(cfg, python_install=installation)

    run = run_deploy_fake(deploy, pyinfra_config=Config(DIFF=True))
    assert run.succeeded, run.error
    assert installed
    assert sum("python install" in command for command in run.executed_commands) == 1
    assert all("python find" in command or "python install" in command for command in run.executed_commands)
    assert fixture["observations"] == [(True, "homeassistant", "environment")]
    assert run.ops[-1].changed is False


def test_invalid_version_is_a_failed_operation_before_any_mutation(fixture: dict[str, Any]) -> None:
    fixture["current"] = EnvironmentState(True, "unparseable")
    run = run_deploy_fake(lambda: environment.prepare_environment(HomeAssistantRuntimeConfig()))
    assert not run.succeeded
    assert run.executed_commands == []
    assert "existing virtualenv version is invalid" in str(run.error)
