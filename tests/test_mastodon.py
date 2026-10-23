"""Admission failure, secret transport, configuration drift and no-op convergence."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.mastodon import MastodonConfig, deploy_mastodon
from ops_deploy.services.mastodon.render import SECRET_KEYS, render, render_env, role_vars
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

TEMPLATES = Path(__file__).parents[1] / "src/ops_deploy/services/mastodon/templates"
SOURCE_FILES = ("Gemfile.lock", "yarn.lock", "package.json", ".ruby-version", ".nvmrc")


def config(**changes: Any) -> MastodonConfig:
    return MastodonConfig(
        **{
            "site_path": "/srv/mastodon/live",
            "home_path": "/srv/mastodon",
            "local_domain": "social.example.org",
            "web_domain": "social.example.org",
            "source_commit": "a" * 40,
            "ruby_version": "4.0.5",
            "node_version": "24.17.0",
            "source_files": dict.fromkeys(SOURCE_FILES, "a" * 64),
            "smtp_server": "smtp.example.org",
            "smtp_login": "sender@example.org",
            "smtp_from_address": "Sender <sender@example.org>",
            "smtp_domain": "example.org",
            **changes,
        }
    )


def secrets() -> SecretValues:
    return SecretValues(SecretRef("secrets/test/mastodon.yml"), dict.fromkeys(SECRET_KEYS, "fixture-secret-sentinel"))


def converged(cfg: MastodonConfig) -> dict[str, Any]:
    result = {
        **fakehost.UBUNTU,
        "def require(ok):": [cfg.node_version],
        "ActiveEnterTimestamp": ["current"],
        "NeedDaemonReload": ["no"],
    }
    for name in ("web", "sidekiq", "streaming", "nginx"):
        unit = f"mastodon-{name}.service"
        result.update(fakehost.file(f"/etc/systemd/system/{unit}", render(cfg, f"{name}.service.j2")))
        result.update(fakehost.service(unit))
    for directory in ("/etc/systemd/system", "/etc/mastodon", "/etc/traefik/dynamic"):
        result.update(fakehost.directory(directory))
    result.update(fakehost.file("/etc/mastodon/nginx.conf", render(cfg, "nginx.conf.j2")))
    result.update(fakehost.file("/etc/traefik/dynamic/mastodon.yml", render(cfg, "traefik.yml.j2")))
    return result


def test_converged_has_zero_mutations_and_no_secret_in_commands() -> None:
    cfg = config()
    run = run_deploy_fake(deploy_mastodon, cfg=cfg, secrets=secrets(), responses=converged(cfg))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert route_guard_command() not in run.executed_commands
    assert "fixture-secret-sentinel" not in repr(run.events)
    assert "fixture-secret-sentinel" not in repr(run.ops)
    assert not any("db:migrate" in command or "assets:precompile" in command for command in run.executed_commands)


def test_transaction_lock_refuses_changed_route_before_upload() -> None:
    cfg = config()
    facts = {
        **converged(cfg),
        **fakehost.file("/etc/traefik/dynamic/mastodon.yml", "old route\n"),
        "traefik-route-guard": {"success": False},
    }
    run = run_deploy_fake(deploy_mastodon, cfg=cfg, secrets=secrets(), responses=facts)
    assert not run.succeeded
    assert route_guard_command() in run.executed_commands
    assert run.uploaded_paths == []


def test_admission_failure_plans_no_operation() -> None:
    cfg = config()
    facts = {**converged(cfg), "def require(ok):": [FAILED]}
    with patch("ops_deploy.services.mastodon.deploy.files.put") as put:
        run = run_deploy_fake(deploy_mastodon, cfg=cfg, secrets=secrets(), responses=facts)
        assert not run.succeeded
        assert not run.ops
        assert not run.executed_commands
        put.assert_not_called()


def test_unit_drift_restarts_only_its_service() -> None:
    cfg = config()
    facts = {**converged(cfg), **fakehost.file("/etc/systemd/system/mastodon-web.service", "old unit\n")}
    run = run_deploy_fake(deploy_mastodon, cfg=cfg, secrets=secrets(), responses=facts)
    assert run.succeeded, run.error
    assert "systemctl restart mastodon-web.service" in run.executed_commands
    assert not any(
        f"systemctl restart mastodon-{name}.service" in run.executed_commands
        for name in ("sidekiq", "streaming", "nginx")
    )
    assert all("/public/system" not in event.value for event in run.events if event.kind == "put")


def test_restart_debt_is_repaid_without_file_drift() -> None:
    cfg = config()
    facts = {**converged(cfg), "ActiveEnterTimestamp": ["owed"]}
    run = run_deploy_fake(deploy_mastodon, cfg=cfg, secrets=secrets(), responses=facts)
    assert run.succeeded, run.error
    assert "systemctl restart mastodon-web.service" in run.executed_commands


@pytest.mark.parametrize(
    "changes",
    [
        {"web_domain": "other.example.org"},
        {"site_path": "/srv/mastodon/../live"},
        {"source_files": {}},
        {"ruby_version": "4.0;bad"},
        {"web_port": 10044},
    ],
)
def test_unsupported_configs_fail_locally(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**changes)


def test_environment_keeps_default_account_and_storage_contract() -> None:
    text = render_env(config(), secrets()).reveal().decode()
    assert "REDIS_URL=redis://127.0.0.1:6379/0\n" in text
    assert "S3_ENABLED=false\n" in text
    assert "LOCAL_DOMAIN=social.example.org\n" in text
    assert 'SMTP_FROM_ADDRESS="Sender <sender@example.org>"\n' in text
    assert "{{" not in text


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set for fresh-role parity")
def test_templates_and_selected_defaults_match_fresh_role() -> None:
    root = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles"
    for template in TEMPLATES.glob("*.j2"):
        assert template.read_bytes() == (root / "mastodon_deploy/templates" / template.name).read_bytes()
    defaults = yaml.safe_load((root / "mastodon_shared/defaults/main.yml").read_text())
    defaults.update(yaml.safe_load((root / "mastodon_deploy/defaults/main.yml").read_text()))
    vendored = json.loads((TEMPLATES / "defaults.json").read_text())
    for name, value in vendored.items():
        assert defaults[name] == value
    assert role_vars(config())["mastodon_runtime_path"].startswith("/srv/mastodon/.nvm/versions/node/v24.17.0/bin:")


@pytest.mark.parametrize(
    "template",
    [
        "web.service.j2",
        "sidekiq.service.j2",
        "streaming.service.j2",
        "nginx.service.j2",
        "nginx.conf.j2",
        "traefik.yml.j2",
        "mastodon.env.j2",
    ],
)
def test_render_matches_ansible_fixture(template: str) -> None:
    # ansible-core 2.21, fresh ops-library 3110a0f1 / 2.68.0.
    fixture = Path(__file__).parent / "parity/mastodon_existing" / (template + ".rendered")
    actual = (
        render_env(config(), secrets()).reveal().decode()
        if template == "mastodon.env.j2"
        else render(config(), template)
    )
    assert actual == fixture.read_text()


def test_supplied_secret_is_never_interpreted_as_template() -> None:
    values = dict(secrets())
    values["secret_key_base"] = "{{literal_fixture_value}}"
    text = render_env(config(), SecretValues(SecretRef("secrets/test/mastodon.yml"), values)).reveal().decode()
    assert "SECRET_KEY_BASE={{literal_fixture_value}}\n" in text
