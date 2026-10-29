"""Original ingress bytes and native SDK file calls, no Traefik host proof."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import jinja2
import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.services.homeassistant.ingress import HomeAssistantIngressConfig, render_ingress, write_ingress
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

FIXTURE = Path(__file__).parent / "parity/homeassistant/ingress"


def test_original_source_and_inert_default_handler() -> None:
    manifest = json.loads((FIXTURE / "source.json").read_text())
    for relative, row in manifest["files"].items():
        assert hashlib.sha256((FIXTURE / row["fixture"]).read_bytes()).hexdigest() == row["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            actual = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles/homeassistant_deploy" / relative
            assert hashlib.sha256(actual.read_bytes()).hexdigest() == row["sha256"]
    defaults = yaml.safe_load((FIXTURE / "defaults.yml").read_text())
    for key, value in HomeAssistantIngressConfig().model_dump(exclude={"app_port", "default_ipv4"}).items():
        assert (list(value) if isinstance(value, tuple) else value) == defaults["homeassistant_traefik_" + key]
    assert HomeAssistantIngressConfig().app_port == defaults["homeassistant_app_port"]
    handlers = yaml.safe_load((FIXTURE / "handlers.yml").read_text())
    handler = next(row for row in handlers if row["name"] == "reload traefik config")
    assert set(handler) == {"name", "ansible.builtin.debug"}
    tasks = yaml.safe_load((FIXTURE / "tasks.yml").read_text())
    assert tasks[0]["ansible.builtin.file"]["mode"] == "0755"
    assert tasks[1]["ansible.builtin.template"]["mode"] == "0644"
    assert "notify" not in tasks[0]


@pytest.mark.parametrize("ipv4", [None, "", "192.0.2.11"])
@pytest.mark.parametrize("resolver", ["", "owned-resolver"])
def test_original_render_bytes_and_address_fallback(ipv4: str | None, resolver: str) -> None:
    cfg = HomeAssistantIngressConfig(
        domain="owned.example",
        certresolver=resolver,
        default_ipv4=ipv4,
        entrypoints=("owned-one", "owned-two"),
        middlewares=("second", "first"),
        local_middlewares=(),
        app_port=8321,
    )
    context = {
        "homeassistant_traefik_" + key: value
        for key, value in cfg.model_dump(exclude={"enabled", "app_port", "default_ipv4"}).items()
    }
    context.update(homeassistant_app_port=cfg.app_port, ansible_default_ipv4={} if ipv4 is None else {"address": ipv4})
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(FIXTURE),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    body = render_ingress(cfg)
    assert body.get_secret_value() == env.get_template("route.j2").render(**context)
    assert ("192.168.178.50" in body.get_secret_value()) is (ipv4 is None)
    assert "owned.example" not in repr(body)


@pytest.mark.parametrize("current", [False, True])
def test_current_route_and_changed_route_never_restart_traefik(current: bool) -> None:
    cfg = HomeAssistantIngressConfig(domain="owned.example")
    body = render_ingress(cfg).get_secret_value()
    responses = {**fakehost.LINUX, **fakehost.directory(cfg.dynamic_dir)}
    if current:
        responses.update(fakehost.file(cfg.dynamic_dir + "/homeassistant.yml", body))
    result = []
    run = run_deploy_fake(lambda: result.append(write_ingress(cfg)), responses=responses)
    assert run.succeeded
    assert result[0] is not None
    assert result[0].did_change() is (not current)
    assert len(run.uploads) == int(not current)
    assert not any("systemctl" in command for command in run.executed_commands)


def test_directory_metadata_only_does_not_notify_template_handler() -> None:
    cfg = HomeAssistantIngressConfig()
    responses = {
        **fakehost.LINUX,
        **fakehost.directory(cfg.dynamic_dir, mode="drwx------"),
        **fakehost.file(cfg.dynamic_dir + "/homeassistant.yml", render_ingress(cfg).get_secret_value()),
    }
    result = []
    run = run_deploy_fake(lambda: result.append(write_ingress(cfg)), responses=responses)
    assert run.succeeded
    assert len(run.mutating_changed_ops) == 1
    assert result[0] is not None
    assert not result[0].did_change()
    assert not run.uploads


def test_disabled_and_selected_rendered_override() -> None:
    disabled = run_deploy_fake(write_ingress, HomeAssistantIngressConfig(enabled=False))
    assert disabled.succeeded
    assert not disabled.events
    assert not disabled.ops
    cfg = HomeAssistantIngressConfig()
    body = SecretStr("http:\n  routers: {}\n# owned alternate rendered template\n")
    run = run_deploy_fake(
        write_ingress, cfg, rendered=body, responses={**fakehost.LINUX, **fakehost.directory(cfg.dynamic_dir)}
    )
    assert run.succeeded
    assert run.uploads == [(cfg.dynamic_dir + "/homeassistant.yml", body.get_secret_value().encode())]
    assert not any("systemctl" in command for command in run.executed_commands)
