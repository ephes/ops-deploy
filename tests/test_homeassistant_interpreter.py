"""Actual SDK execution ordering with synthetic UV responses, not native UV."""

from __future__ import annotations

import shlex
from typing import Any

import pytest
from pyinfra.api import Config
from pyinfra.connectors.fake import FakeConnector
from pyinfra.connectors.util import CommandOutput, OutputLine

from ops_deploy.services.homeassistant import interpreter
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake


def test_current_interpreter_does_not_install() -> None:
    cfg = HomeAssistantRuntimeConfig()
    run = run_deploy_fake(
        lambda: interpreter.install_python(cfg),
        responses={"python find 3.14.8": [" /owned/cpython-3.14.8/bin/python3.14 "]},
    )
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert all("python install" not in event.value for event in run.events)


@pytest.mark.parametrize("deferred", [False, True])
def test_real_sdk_find_is_fresh_after_install_and_before_later_decision(
    monkeypatch: pytest.MonkeyPatch, deferred: bool
) -> None:
    cfg = HomeAssistantRuntimeConfig()
    calls: list[str] = []
    installed = False
    original = FakeConnector.run_shell_command

    def command(self: FakeConnector, cmd: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal installed
        text = cmd if isinstance(cmd, str) else cmd.get_raw_value()
        calls.append(text)
        if "python install" in text:
            installed = True
            return True, CommandOutput([])
        if "python find" in text:
            body = "/owned/cpython-3.14.8/bin/python3.14" if installed else ""
            return installed, CommandOutput([OutputLine("stdout", body)])
        return original(self, cmd, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", command)
    run = run_deploy_fake(lambda: interpreter.install_python(cfg, deferred=deferred), pyinfra_config=Config(DIFF=True))
    assert run.succeeded, run.error
    assert len(run.mutating_changed_ops) == 1
    assert run.uploads == []
    assert sum("python install" in text for text in calls) == 1
    install_index = next(i for i, text in enumerate(calls) if "python install" in text)
    assert any("python find" in text for text in calls[:install_index])
    assert "python find" in calls[install_index + 1]


def test_install_error_stays_failed_without_synthetic_recovery() -> None:
    run = run_deploy_fake(
        lambda: interpreter.install_python(HomeAssistantRuntimeConfig()),
        responses={"python find": {"success": False}, "python install": {"success": False}},
    )
    assert not run.succeeded
    assert sum("python install" in text for text in run.executed_commands) == 1


def test_successful_install_without_available_interpreter_fails() -> None:
    run = run_deploy_fake(
        lambda: interpreter.install_python(HomeAssistantRuntimeConfig()),
        responses={"python find": {"success": False}},
    )
    assert not run.succeeded
    assert any("python install" in text for text in run.executed_commands)


def test_service_user_find_and_install_explicit_home_cwd() -> None:
    cfg = HomeAssistantRuntimeConfig(user="ownedha", home="/srv/owned", uv_path="/opt/uv", python_version="3.14.8")
    for action in ("find", "install"):
        assert shlex.split(interpreter.interpreter_command(cfg, action)) == [
            "runuser",
            "-u",
            "ownedha",
            "--",
            "env",
            "HOME=/srv/owned",
            "/bin/sh",
            "-c",
            "cd /srv/owned && exec /opt/uv python " + action + " 3.14.8",
        ]
