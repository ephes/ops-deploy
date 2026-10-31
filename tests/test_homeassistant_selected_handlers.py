"""Original selected notifications at real SDK boundaries, with owned fake hosts."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
import yaml
from pyinfra.operations import server

from ops_deploy.services.homeassistant.ingress import HomeAssistantIngressConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

module = importlib.import_module("ops_deploy.services.homeassistant.deploy")
COMMANDS = {
    "reload systemd": "systemctl daemon-reload",
    "restart homeassistant": "restart homeassistant.service",
    "restart matter server": "restart matter-server.service",
    "reload udev rules": "udevadm control --reload-rules",
    "trigger udev": "udevadm trigger --subsystem-match=tty",
    "reload traefik config": "",
}


def test_original_named_handler_set_and_default() -> None:
    root = Path(__file__).parent / "parity/homeassistant"
    original = yaml.safe_load((root / "service-handlers.yml").read_text())
    assert [item["name"] for item in original] == list(COMMANDS)
    defaults = yaml.safe_load((root / "deployment/defaults.yml").read_text())
    assert HomeAssistantIngressConfig().reload_handler == defaults["homeassistant_traefik_reload_handler"]
    assert original[2]["when"] == "homeassistant_matter_server_restart_on_change | bool"
    assert original[3]["when"] == original[4]["when"] == "homeassistant_enable_udev_rule"


@pytest.mark.parametrize("selector", COMMANDS)
@pytest.mark.parametrize("prefix", ["", "homeassistant_deploy : ", "local.ops_library.homeassistant_deploy : "])
@pytest.mark.parametrize("changed", [False, True])
def test_selected_handler_uses_original_conditions_order_and_one_flush(
    selector: str, prefix: str, changed: bool
) -> None:
    cfg = HomeAssistantRuntimeConfig(manage_matter_server=False)

    def component() -> None:
        pending = module._PendingHandlers()
        route = server.shell(name="Owned route result", commands=["printf route"], _if=lambda: changed)
        pending.notify_ingress(route, prefix + selector, cfg)
        server.shell(name="Owned next task", commands=["printf next-task"])
        pending.flush(cfg)
        server.shell(name="Owned second boundary", commands=["printf second-boundary"])
        pending.flush(cfg)

    run = run_deploy_fake(
        component,
        responses={
            **fakehost.LINUX,
            **fakehost.service("homeassistant.service"),
            **fakehost.service("matter-server.service"),
        },
    )
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    for name, command in COMMANDS.items():
        if command:
            assert commands.count(command) == int(changed and selector == name)
            if changed and selector == name:
                assert commands.index("printf next-task") < commands.index(command)
                assert commands.index(command) < commands.index("printf second-boundary")


@pytest.mark.parametrize(
    "selector", ["restart homeassistant", "restart matter server", "reload udev rules", "trigger udev"]
)
def test_selected_handler_original_false_condition_skips(selector: str) -> None:
    cfg = HomeAssistantRuntimeConfig(
        restart_on_change=False, matter_server_restart_on_change=False, enable_udev_rule=False
    )

    def component() -> None:
        pending = module._PendingHandlers()
        route = server.shell(name="Owned route result", commands=["printf route"])
        pending.notify_ingress(route, selector, cfg)
        pending.flush(cfg)

    run = run_deploy_fake(component, responses=fakehost.LINUX)
    assert run.succeeded, run.error
    assert COMMANDS[selector] not in "\n".join(run.executed_commands)


@pytest.mark.parametrize("selector", ["reload udev rules", "trigger udev"])
def test_normal_and_selected_udev_notifications_are_deduplicated(selector: str) -> None:
    cfg = HomeAssistantRuntimeConfig()

    def component() -> None:
        rule = server.shell(name="Owned rule result", commands=["printf rule"])
        route = server.shell(name="Owned route result", commands=["printf route"])
        pending = module._PendingHandlers(udev=rule)
        pending.notify_ingress(route, selector, cfg)
        pending.flush(cfg)
        pending.flush(cfg)

    run = run_deploy_fake(component, responses=fakehost.LINUX)
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    assert commands.count("udevadm control --reload-rules") == 1
    assert commands.count("udevadm trigger --subsystem-match=tty") == 1


@pytest.mark.parametrize("changed", [False, True])
def test_unknown_selector_fails_only_after_changed_route_before_next_task(changed: bool) -> None:
    def component() -> None:
        pending = module._PendingHandlers()
        route = server.shell(name="Owned route result", commands=["printf route"], _if=lambda: changed)
        pending.notify_ingress(route, "owned missing handler", HomeAssistantRuntimeConfig())
        server.shell(name="Owned next task", commands=["printf next-task"])
        pending.flush(HomeAssistantRuntimeConfig())

    run = run_deploy_fake(component, responses=fakehost.LINUX)
    assert run.succeeded is not changed
    assert ("printf next-task" in "\n".join(run.executed_commands)) is not changed


def test_disabled_ingress_does_not_resolve_unknown_selector() -> None:
    def component() -> None:
        pending = module._PendingHandlers()
        pending.notify_ingress(None, "owned missing handler", HomeAssistantRuntimeConfig())
        pending.flush(HomeAssistantRuntimeConfig())

    run = run_deploy_fake(component, responses=fakehost.LINUX)
    assert run.succeeded, run.error
    assert not run.executed_commands


@pytest.mark.parametrize("selector", ["restart homeassistant", "restart matter server"])
def test_normal_and_selected_service_notification_runs_once(selector: str) -> None:
    cfg = HomeAssistantRuntimeConfig()

    def component() -> None:
        result = server.shell(name="Owned normal change", commands=["printf normal"])
        route = server.shell(name="Owned route result", commands=["printf route"])
        pending = module._PendingHandlers()
        callbacks = pending.homeassistant if selector == "restart homeassistant" else pending.matter
        callbacks.append(result.did_change)
        pending.notify_ingress(route, selector, cfg)
        pending.flush(cfg)
        pending.flush(cfg)

    run = run_deploy_fake(
        component,
        responses={
            **fakehost.LINUX,
            **fakehost.service("homeassistant.service"),
            **fakehost.service("matter-server.service"),
        },
    )
    assert run.succeeded, run.error
    assert "\n".join(run.executed_commands).count(COMMANDS[selector]) == 1
