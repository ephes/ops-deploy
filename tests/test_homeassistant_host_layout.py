"""Original layout source and fake-connector effects; not native device proof."""

from __future__ import annotations

import hashlib
import json
import os
from importlib.resources import files
from pathlib import Path

import jinja2
import pytest
import yaml

from ops_deploy.services.homeassistant.host_layout import configure_layout, directories, run_udev_handlers
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake
from tests import fakehost


@pytest.mark.parametrize("home", ["/home/homeassistant", "/srv/owned-ha"])
def test_original_ordered_paths_and_no_extra_group_or_recursive_policy(home: str) -> None:
    cfg = HomeAssistantRuntimeConfig(home=home)
    fixture = Path(__file__).parent / "parity/homeassistant"
    original = yaml.safe_load((fixture / "directories.yml").read_text())[0]
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    values = {"homeassistant_" + key: value for key, value in cfg.model_dump().items()}
    expected = tuple(env.from_string(value).render(**values) for value in original["loop"])
    assert directories(cfg) == expected
    assert original["ansible.builtin.file"]["mode"] == "0755"
    user = yaml.safe_load((fixture / "user.yml").read_text())[0]["ansible.builtin.user"]
    assert user["groups"] == ["dialout"]
    assert user["append"] is True
    assert "group" not in user
    assert "system" not in user


def test_source_bindings_and_exact_rule() -> None:
    fixture = Path(__file__).parent / "parity/homeassistant"
    manifest = json.loads((fixture / "layout-source.json").read_text())
    for relative, expected in manifest["files"].items():
        if relative.startswith("templates/"):
            body = files("ops_deploy.services.homeassistant").joinpath(relative).read_bytes()
        else:
            body = (
                fixture / ("layout-handlers.yml" if relative == "handlers/main.yml" else Path(relative).name)
            ).read_bytes()
        assert hashlib.sha256(body).hexdigest() == expected
        if os.environ.get("OPS_LIBRARY_PATH"):
            original = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles/homeassistant_deploy" / relative
            assert hashlib.sha256(original.read_bytes()).hexdigest() == expected


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
