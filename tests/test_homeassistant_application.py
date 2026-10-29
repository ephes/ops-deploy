"""Prepared application SDK wiring; original policy oracle lives in python_state tests."""

from __future__ import annotations

import shlex
from typing import Any

import pytest
from pyinfra import state
from pyinfra.api import Config
from pyinfra.connectors.fake import FakeConnector
from pyinfra.connectors.util import CommandOutput
from pyinfra.operations import server

from ops_deploy.services.homeassistant import application
from ops_deploy.services.homeassistant.python_state import EnvironmentState
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake


@pytest.mark.parametrize("matter", [False, True])
@pytest.mark.parametrize("reason", ["current", "missing", "wrong-version", "force", "llama", "chip"])
def test_original_actual_install_branches(matter: bool, reason: str, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = HomeAssistantRuntimeConfig(
        package_spec="homeassistant==2026.10.2",
        matter_server_package_spec="python-matter-server[server]==8.1.2",
        force_reinstall=reason == "force",
    )
    current = EnvironmentState(
        python_exists=True,
        application_exists=reason != "missing",
        installed_version="old" if reason == "wrong-version" else "8.1.2" if matter else "2026.10.2",
        chip_status=int(reason == "chip"),
    )
    phases = []

    def observe(cfg: HomeAssistantRuntimeConfig, kind: str, phase: str) -> EnvironmentState:
        phases.append((kind, phase))
        return current

    monkeypatch.setattr(application, "_observe", observe)
    run = run_deploy_fake(
        lambda: application.install_application(cfg, matter=matter, llama_cpp_rebuild=reason == "llama")
    )
    assert run.succeeded, run.error
    expected = reason in {"missing", "wrong-version", "force"} or (reason == "chip" if matter else reason == "llama")
    assert len(run.mutating_changed_ops) == int(expected)
    assert run.uploads == []
    assert all(pair == ("matter" if matter else "homeassistant", "application") for pair in phases)
    assert run.executed_commands == (
        [application.application_command(cfg, "matter" if matter else "homeassistant")] if expected else []
    )


@pytest.mark.parametrize("matter", [False, True])
def test_unpinned_does_not_upgrade_existing_application(matter: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    current = EnvironmentState(True, application_exists=True, installed_version="old")
    monkeypatch.setattr(application, "_observe", lambda *args: current)
    run = run_deploy_fake(lambda: application.install_application(HomeAssistantRuntimeConfig(), matter=matter))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.executed_commands == []


@pytest.mark.parametrize("matter", [False, True])
def test_environment_dependency_defers_old_import_and_execution_reads_fresh_state(
    matter: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    rebuilt = False
    phases = []
    original = FakeConnector.run_shell_command

    def command(self: FakeConnector, cmd: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal rebuilt
        text = cmd if isinstance(cmd, str) else cmd.get_raw_value()
        if text == "synthetic-rebuild-environment":
            rebuilt = True
            return True, CommandOutput([])
        return original(self, cmd, *args, **kwargs)

    def observe(*args: object) -> EnvironmentState:
        assert rebuilt, "must not import obsolete application during planning"
        phases.append(state.is_executing)
        return EnvironmentState(True, application_exists=False)

    monkeypatch.setattr(FakeConnector, "run_shell_command", command)
    monkeypatch.setattr(application, "_observe", observe)
    cfg = HomeAssistantRuntimeConfig()

    def deploy() -> None:
        env = server.shell(commands=["synthetic-rebuild-environment"])
        application.install_application(cfg, matter=matter, environment=env)

    run = run_deploy_fake(deploy, pyinfra_config=Config(DIFF=True))
    assert run.succeeded, run.error
    assert phases == [True]
    assert run.executed_commands == [
        "synthetic-rebuild-environment",
        application.application_command(cfg, "matter" if matter else "homeassistant"),
    ]
    assert len(run.mutating_changed_ops) == 2


def test_failed_install_not_hidden_and_no_service_restart(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(application, "_observe", lambda *args: EnvironmentState(True, application_exists=False))
    run = run_deploy_fake(
        lambda: application.install_application(HomeAssistantRuntimeConfig()),
        responses={"pip install": {"success": False}},
    )
    assert not run.succeeded
    assert run.ops[0].succeeded is False
    assert len(run.executed_commands) == 1
    assert "systemctl" not in run.executed_commands[0]


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("matter", [False, True])
def test_original_install_argv_user_constraints_and_declared_quotes(enabled: bool, matter: bool) -> None:
    cfg = HomeAssistantRuntimeConfig(
        user="owned",
        home="/srv/owned",
        python_security_floor_enabled=enabled,
        package_spec='"homeassistant==2026.10.2" --no-deps',
        matter_server_package_spec='"python-matter-server[server]==8.1.2" --no-deps',
    )
    text = application.application_command(cfg, "matter" if matter else "homeassistant")
    assert text.startswith("cd /srv/owned/site && ")
    venv = cfg.matter_server_virtualenv_path if matter else cfg.virtualenv_path
    package = "python-matter-server[server]==8.1.2" if matter else "homeassistant==2026.10.2"
    assert shlex.split(text.split(" && ", 1)[1]) == [
        "runuser",
        "-u",
        "owned",
        "--",
        "env",
        "HOME=/srv/owned",
        "/usr/local/bin/uv",
        "pip",
        "install",
        "--python",
        venv,
        package,
        "--no-deps",
        *(["--constraint", cfg.python_security_constraints_path] if enabled else []),
    ]


def test_invalid_declared_spec_stops_before_any_operation() -> None:
    cfg = HomeAssistantRuntimeConfig(package_spec='"unterminated')
    run = run_deploy_fake(lambda: application.install_application(cfg))
    assert not run.succeeded
    assert run.ops == []
    assert run.executed_commands == []
