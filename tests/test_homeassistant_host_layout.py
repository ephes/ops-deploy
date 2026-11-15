"""Host layout and fake-connector effects; not native device proof."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import pytest

from ops_deploy.services.homeassistant.host_layout import configure_layout, directories, run_udev_handlers
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake
from tests import fakehost


@pytest.mark.parametrize("home", ["/home/homeassistant", "/srv/owned-ha"])
def test_ordered_paths_below_home(home: str) -> None:
    cfg = HomeAssistantRuntimeConfig(home=home)
    below = (".local", ".local/share", ".local/share/uv", "site", "site/config", "site/data", "site/logs", "site/bin")
    assert directories(cfg) == (home, *(f"{home}/{path}" for path in below))


@pytest.mark.parametrize("enable", [False, True])
def test_actual_fake_connector_preserves_deferred_udev_and_original_scope(enable: bool) -> None:
    cfg = HomeAssistantRuntimeConfig(enable_udev_rule=enable)

    def component() -> None:
        rule = configure_layout(cfg)
        from pyinfra.operations import server

        server.shell(name="Owned later configuration marker", commands=["true"])
        run_udev_handlers(rule)

    run = run_deploy_fake(component, responses=fakehost.LINUX)
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    assert "useradd" in commands
    assert "dialout" in commands
    assert "systemctl" not in commands
    rule_uploads = [body for path, body in run.uploads if path == cfg.udev_rule_path]
    if enable:
        assert rule_uploads == [
            files("ops_deploy.services.homeassistant").joinpath("templates/99-homeassistant-zbt1.rules.j2").read_bytes()
        ]
        assert "udevadm control --reload-rules" in commands
        assert "udevadm trigger --subsystem-match=tty" in commands
        names = [op.name for op in run.ops]
        assert names.index("Owned later configuration marker") < names.index("Reload Home Assistant udev rules")
    else:
        assert not rule_uploads
        assert "udevadm" not in commands


def test_current_rule_skips_both_deferred_commands_and_keeps_other_groups() -> None:
    cfg = HomeAssistantRuntimeConfig()
    body = files("ops_deploy.services.homeassistant").joinpath("templates/99-homeassistant-zbt1.rules.j2").read_text()
    responses = {
        **fakehost.LINUX,
        **fakehost.file(cfg.udev_rule_path, body),
        **fakehost.directory(str(Path(cfg.udev_rule_path).parent)),
        "cat /etc/group": ["homeassistant:x:1000:", "dialout:x:20:", "retained:x:21:"],
        "cat /etc/passwd | cut": [
            "homeassistant:x:1000:1000::/home/homeassistant:/bin/bash|homeassistant|homeassistant dialout retained||!"
        ],
    }
    for path in directories(cfg):
        responses.update(fakehost.directory(path, user=cfg.user))

    def component() -> None:
        run_udev_handlers(configure_layout(cfg))

    run = run_deploy_fake(component, responses=responses)
    assert run.succeeded, run.error
    assert not run.mutating_changed_ops
    assert not run.uploads
    assert not any("udevadm" in command or "usermod" in command for command in run.executed_commands)
