"""Prepared sequence using actual SDK file operations and synthetic host state."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

import pytest
from pyinfra.api import Config
from pyinfra.operations import server

from ops_deploy.services.homeassistant import application, environment, ownership
from ops_deploy.services.homeassistant.python_runtime import PythonRuntimeChanges, configure_python_runtime
from ops_deploy.services.homeassistant.python_state import EnvironmentState
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake
from tests import fakehost


def responses(cfg: HomeAssistantRuntimeConfig, *, wrong_record: bool = False) -> dict[str, Any]:
    result = {
        **fakehost.UBUNTU,
        **fakehost.system_account(cfg.user, cfg.home),
        **fakehost.symlink(cfg.virtualenv_link, cfg.virtualenv_path, user=cfg.user),
        "python find": ["/owned/python3.14"],
        "pip install": {"stderr": ["Audited 10 packages"]},
    }
    records = [cfg.virtualenv_version_file]
    if cfg.manage_matter_server:
        records.append(cfg.matter_server_virtualenv_version_file)
    for path in records:
        result.update(fakehost.file(path, "old\n" if wrong_record else cfg.python_version + "\n", user=cfg.user))
        result.update(fakehost.directory(str(PurePosixPath(path).parent), user=cfg.user))
    for path in [cfg.site_path, cfg.matter_server_storage_path, cfg.matter_server_chip_factory_dir]:
        result.update(fakehost.directory(path, user=cfg.user))
    if cfg.matter_server_log_file:
        result.update(fakehost.directory(str(PurePosixPath(cfg.matter_server_log_file).parent), user=cfg.user))
    return result


@pytest.fixture
def current(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    seen = []

    def observe(cfg: HomeAssistantRuntimeConfig, kind: str, phase: str) -> EnvironmentState:
        seen.append((kind, phase))
        return EnvironmentState(
            True,
            "Python " + cfg.python_version,
            application_exists=True,
            installed_version="8.1.2" if kind == "matter" else "2026.10.2",
        )

    monkeypatch.setattr(environment, "_observe", observe)
    monkeypatch.setattr(application, "_observe", observe)
    monkeypatch.setattr(ownership, "probe", lambda *args, **kwargs: "current")
    return seen


@pytest.mark.parametrize("matter", [False, True])
@pytest.mark.parametrize("extras", [False, True])
@pytest.mark.parametrize("wrong_record", [False, True])
def test_current_composition_and_original_no_notification_for_version_record(
    current: list[tuple[str, str]], matter: bool, extras: bool, wrong_record: bool
) -> None:
    cfg = HomeAssistantRuntimeConfig(
        manage_matter_server=matter,
        package_spec="homeassistant==2026.10.2",
        matter_server_package_spec="python-matter-server[server]==8.1.2",
        extra_package_specs=("owned-extra==1",) if extras else (),
    )
    returned: list[PythonRuntimeChanges] = []

    def deploy() -> None:
        changes = configure_python_runtime(cfg)
        returned.append(changes)
        server.shell(commands=["synthetic-ha-handler"], _if=changes.homeassistant_changed)
        server.shell(commands=["synthetic-matter-handler"], _if=changes.matter_changed)

    run = run_deploy_fake(deploy, responses=responses(cfg, wrong_record=wrong_record), pyinfra_config=Config(DIFF=True))
    assert run.succeeded, run.error
    record_changes = (2 if matter else 1) if wrong_record else 0
    assert len(run.mutating_changed_ops) == int(extras) + record_changes
    assert len(run.uploads) == record_changes
    assert not returned[0].homeassistant_changed()
    assert not returned[0].matter_changed()
    assert not any("synthetic-" in command for command in run.executed_commands)
    assert any(kind == "matter" for kind, _ in current) is matter
    assert (returned[0].matter_application is not None) is matter


def test_package_change_notification_is_deferred_after_both_environments(
    current: list[tuple[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = HomeAssistantRuntimeConfig(
        manage_matter_server=True,
        package_spec="homeassistant==2026.10.2",
        matter_server_package_spec="python-matter-server[server]==8.1.2",
        extra_package_specs=("owned-extra==1",),
    )
    facts = responses(cfg)
    facts["pip install"] = {"stderr": ["Installed 1 package"]}

    def deploy() -> None:
        changes = configure_python_runtime(cfg)
        server.shell(commands=["owned-final-configuration"])
        server.shell(commands=["synthetic-ha-handler"], _if=changes.homeassistant_changed)
        server.shell(commands=["synthetic-matter-handler"], _if=changes.matter_changed)

    run = run_deploy_fake(deploy, responses=facts)
    assert run.succeeded, run.error
    assert run.executed_commands[-2:] == ["owned-final-configuration", "synthetic-ha-handler"]
    assert "synthetic-matter-handler" not in run.executed_commands
    assert len(run.mutating_changed_ops) == 3


def test_premature_notifications_fail_instead_of_guessing(current: list[tuple[str, str]]) -> None:
    cfg = HomeAssistantRuntimeConfig()

    def deploy() -> None:
        changes = configure_python_runtime(cfg)
        changes.homeassistant_changed()

    with pytest.raises(RuntimeError, match="before execution"):
        run_deploy_fake(deploy, responses=responses(cfg))


@pytest.mark.parametrize("matter", [False, True])
def test_full_cold_sequence_resolves_python_and_observes_only_created_environments(
    matter: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pyinfra.connectors.fake import FakeConnector
    from pyinfra.connectors.util import CommandOutput, OutputLine

    cfg = HomeAssistantRuntimeConfig(manage_matter_server=matter)
    installed_python = False
    created = {"homeassistant": False, "matter": False}
    applications = {"homeassistant": False, "matter": False}
    queries = []
    original = FakeConnector.run_shell_command

    def command(self: FakeConnector, cmd: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal installed_python
        text = cmd if isinstance(cmd, str) else cmd.get_raw_value()
        if "python find" in text:
            return installed_python, CommandOutput(
                [OutputLine("stdout", "/owned/python3.14" if installed_python else "")]
            )
        if "python install" in text:
            installed_python = True
        elif " venv --seed " in text:
            assert installed_python
            created["matter" if cfg.matter_server_virtualenv_path in text else "homeassistant"] = True
        elif " pip install " in text:
            kind = "matter" if cfg.matter_server_virtualenv_path in text else "homeassistant"
            assert created[kind]
            applications[kind] = True
        return original(self, cmd, *args, **kwargs)

    def observe(cfg: HomeAssistantRuntimeConfig, kind: str, phase: str) -> EnvironmentState:
        queries.append((kind, phase))
        if phase == "application":
            assert created[kind], "old or nonexistent application must not be imported"
        return EnvironmentState(
            created[kind], "Python 3.14.8" if created[kind] else "", application_exists=applications[kind]
        )

    monkeypatch.setattr(FakeConnector, "run_shell_command", command)
    monkeypatch.setattr(environment, "_observe", observe)
    monkeypatch.setattr(application, "_observe", observe)
    monkeypatch.setattr(environment, "_present", lambda *args: False)
    monkeypatch.setattr(ownership, "probe", lambda *args, **kwargs: "current")
    results: list[PythonRuntimeChanges] = []
    run = run_deploy_fake(
        lambda: results.append(configure_python_runtime(cfg)),
        responses={**fakehost.UBUNTU, **fakehost.system_account(cfg.user, cfg.home)},
        pyinfra_config=Config(DIFF=True),
    )
    assert run.succeeded, run.error
    assert installed_python
    assert created == {"homeassistant": True, "matter": matter}
    assert applications == created
    assert results[0].homeassistant_changed()
    assert results[0].matter_changed() is matter
    assert sum("python install" in command for command in run.executed_commands) == 1
    assert sum(" venv --seed " in command for command in run.executed_commands) == (2 if matter else 1)
    assert len(run.uploads) == (2 if matter else 1)
    assert not any("systemctl" in command for command in run.executed_commands)


def test_failed_extra_install_preserves_prior_record_effect_but_does_not_run_handler(
    current: list[tuple[str, str]],
) -> None:
    cfg = HomeAssistantRuntimeConfig(extra_package_specs=("owned-extra==1",))
    facts = responses(cfg, wrong_record=True)
    facts["pip install"] = {"success": False, "stderr": ["Installed then failed"]}

    def deploy() -> None:
        changes = configure_python_runtime(cfg)
        server.shell(commands=["synthetic-ha-handler"], _if=changes.homeassistant_changed)

    run = run_deploy_fake(deploy, responses=facts)
    assert not run.succeeded
    assert len(run.uploads) == 1
    assert not any("synthetic-ha-handler" in command for command in run.executed_commands)
    assert any(op.succeeded is False for op in run.ops)
