"""Service unit writes and actual SDK commands; no host service proof."""

from __future__ import annotations

from typing import Any

import pytest
from pyinfra.operations import server

from ops_deploy.services.homeassistant.render import render_unit
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig, ServiceState
from ops_deploy.services.homeassistant.services import ensure_service_states, flush_service_handlers, write_units
from ops_deploy.testing import run_deploy_fake
from tests import fakehost


def responses(cfg: HomeAssistantRuntimeConfig, *, current_units: bool, running: bool = True) -> dict[str, Any]:
    result = {
        **fakehost.LINUX,
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.service(cfg.service_name + ".service", running=running, enabled=cfg.service_enabled),
        **fakehost.service(
            cfg.matter_server_service_name + ".service", running=running, enabled=cfg.matter_server_service_enabled
        ),
    }
    if current_units:
        result.update(fakehost.file(cfg.systemd_unit_path, render_unit(cfg, "homeassistant")))
        result.update(fakehost.file(cfg.matter_server_systemd_unit_path, render_unit(cfg, "matter-server")))
    return result


@pytest.mark.parametrize("matter", [False, True])
@pytest.mark.parametrize("current", [False, True])
@pytest.mark.parametrize("restart", [False, True])
def test_units_notify_at_later_flush_only_and_original_restart_flags(
    matter: bool, current: bool, restart: bool
) -> None:
    cfg = HomeAssistantRuntimeConfig(
        manage_matter_server=matter,
        restart_on_change=restart,
        matter_server_restart_on_change=restart,
        service_enabled=False,
        matter_server_service_enabled=False,
    )

    def component() -> None:
        units = write_units(cfg)
        server.shell(name="Owned later configuration boundary", commands=["printf later-configuration"])
        flush_service_handlers(
            cfg,
            reload_required=units.reload_required,
            homeassistant_required=units.homeassistant_changed,
            matter_required=units.matter_changed,
        )

    run = run_deploy_fake(component, responses=responses(cfg, current_units=current))
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    if current:
        assert not run.uploads
        assert "systemctl" not in commands
    else:
        assert len(run.uploads) == (2 if matter else 1)
        assert run.uploads[0] == (cfg.systemd_unit_path, render_unit(cfg, "homeassistant").encode())
        assert commands.index("printf later-configuration") < commands.index("systemctl daemon-reload")
        for unit, selected in ((cfg.service_name, True), (cfg.matter_server_service_name, matter)):
            assert (f"restart {unit}.service" in commands) is (selected and restart)
            assert (f"enable {unit}.service" in commands) is (selected and restart)
        if matter and restart:
            assert commands.index("restart homeassistant.service") < commands.index("restart matter-server.service")


@pytest.mark.parametrize("matter", [False, True])
@pytest.mark.parametrize("desired", ["started", "stopped", "restarted", "reloaded"])
def test_explicit_state_and_unconditional_daemon_reload(matter: bool, desired: ServiceState) -> None:
    cfg = HomeAssistantRuntimeConfig(
        manage_matter_server=matter, service_state=desired, matter_server_service_state=desired
    )
    run = run_deploy_fake(lambda: ensure_service_states(cfg), responses=responses(cfg, current_units=True))
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    assert commands.count("systemctl daemon-reload") == (2 if matter else 1)
    assert len(run.mutating_changed_ops) == (2 if matter else 1)
    for unit, selected in ((cfg.service_name, True), (cfg.matter_server_service_name, matter)):
        action = {"stopped": "stop", "restarted": "restart", "reloaded": "reload"}.get(desired)
        if action:
            assert (f"{action} {unit}.service" in commands) is selected
        else:
            assert f"start {unit}.service" not in commands
    assert not run.uploads


def test_failed_unit_metadata_install_stops_before_notifications_or_later_effects() -> None:
    cfg = HomeAssistantRuntimeConfig()

    def component() -> None:
        units = write_units(cfg)
        flush_service_handlers(
            cfg,
            reload_required=units.reload_required,
            homeassistant_required=units.homeassistant_changed,
            matter_required=units.matter_changed,
        )

    failing = responses(cfg, current_units=False)
    failing["chmod 644"] = {"success": False, "stderr": ["owned install failure"]}
    run = run_deploy_fake(component, responses=failing)
    assert not run.succeeded
    assert any("chmod 644" in command for command in run.executed_commands)
    assert run.uploads  # Earlier file transfer is an actual partial effect, not zero.
    assert not any("systemctl" in command for command in run.executed_commands)
