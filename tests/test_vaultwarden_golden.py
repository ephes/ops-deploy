"""vaultwarden's environment file, drop-in and route are the bytes hosts have.

The goldens were recorded when these renders equalled the vaultwarden_deploy
role's. Identical bytes mean a deploy rewrites none of them and so does not
restart Vaultwarden.
"""

from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.vaultwarden import VaultwardenConfig, render_dropin, render_env, render_route
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "vaultwarden"
SECRETS = {
    "admin_token": "$argon2id$v=19$m=65540,t=3,p=4$fixture-salt$fixture-hash",  # pragma: allowlist secret
    "smtp_username": "vault@example.com",
    "smtp_password": "fixture smtp password with spaces & #",  # pragma: allowlist secret
}
# The production playbook's shape.
PLAYBOOK: dict[str, Any] = {
    "domain": "https://vault.example.com",
    "smtp_host": "localhost",
    "smtp_port": 587,
    "smtp_security": "starttls",
    "smtp_from": "vault@example.com",
    "smtp_from_name": "Vaultwarden",
    "smtp_auth_mechanism": "Plain",
    "smtp_accept_invalid_certs": True,
    "smtp_accept_invalid_hostnames": True,
    "traefik_entrypoint": "web-secure",
}
CASES: dict[str, tuple[dict[str, Any], dict[str, str]]] = {
    "playbook": (PLAYBOOK, SECRETS),
    "allowlist-admin-disabled": (
        {
            **PLAYBOOK,
            "smtp_debug": True,
            "traefik_certresolver": "letsencrypt",
            "traefik_ip_allowlist": ("192.0.2.0/24", "100.64.0.0/10", "fd7a:115c:a1e0::/48"),
        },
        {**SECRETS, "admin_enabled": "false"},
    ),
    "subpath": (
        {
            "domain": "http://vault.example.net/sub/path",
            "rocket_address": "0.0.0.0",
            "rocket_port": 8080,
            "websocket_enabled": False,
            "org_creation_users": "a@example.com,b@example.com",
            "icon_service": "duckduckgo",
            "log_level": "warn",
            "sends_allowed": False,
            "emergency_access_allowed": False,
            "show_password_hint": True,
            "invitations_allowed": False,
        },
        {"admin_token": "plain-token", "admin_enabled": "true"},
    ),
}


def make(overrides: dict[str, Any], secrets: dict[str, str]) -> tuple[VaultwardenConfig, SecretValues]:
    cfg = VaultwardenConfig(secrets=SecretRef("secrets/prod/vaultwarden.yml"), **overrides)
    assert cfg.secrets is not None
    return cfg, SecretValues(cfg.secrets, secrets)


@pytest.mark.parametrize("case", sorted(CASES))
def test_files_match_golden(case: str) -> None:
    cfg, values = make(*CASES[case])

    assert_golden(GOLDEN / case / "vaultwarden.env", render_env(cfg, values).reveal().decode())
    assert_golden(GOLDEN / case / "vaultwarden-override.conf", render_dropin(cfg))
    assert_golden(GOLDEN / case / "traefik-vaultwarden.yml", render_route(cfg))


def test_env_of_the_playbook_settings() -> None:
    cfg, values = make(PLAYBOOK, SECRETS)
    lines = render_env(cfg, values).reveal().decode().splitlines()

    assert f"ADMIN_TOKEN={SECRETS['admin_token']}" in lines
    assert f"SMTP_PASSWORD={SECRETS['smtp_password']}" in lines
    assert "SMTP_AUTH_MECHANISM=Plain" in lines
    assert "SMTP_ACCEPT_INVALID_CERTS=true" in lines
    assert not any(line.startswith("SMTP_DEBUG") for line in lines)

    _, disabled = make(PLAYBOOK, {**SECRETS, "admin_enabled": "false"})
    text = render_env(cfg, disabled).reveal().decode()
    assert "# Admin panel disabled (vaultwarden_admin_enabled=False)\n" in text
    assert SECRETS["admin_token"] not in text


@pytest.mark.parametrize("case", sorted(CASES))
def test_route_points_at_rocket(case: str) -> None:
    cfg, _ = make(*CASES[case])

    route = yaml.safe_load(render_route(cfg))["http"]
    assert route["routers"]["vaultwarden"]["entryPoints"] == [cfg.traefik_entrypoint]
    url = route["services"]["vaultwarden"]["loadBalancer"]["servers"][0]["url"]
    assert url == f"http://{cfg.rocket_address}:{cfg.rocket_port}"
