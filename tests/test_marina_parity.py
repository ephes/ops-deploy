"""marina files are byte-identical to the marina_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
Ansible and ops-deploy take turns on a host without rewriting files or
restarting marina.
"""

from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.marina import MarinaConfig
from ops_deploy.services.marina.deploy import render, render_env, render_route
from tests.marina_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
SECRET_KEY = "fixture-Key_0123456789+=:,./-%@abc"


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = bool
    return env.get_template(f"marina_deploy__{template}").render(**variables)


def role_vars(cfg: MarinaConfig) -> dict[str, Any]:
    return {
        "marina_user": cfg.user,
        "marina_home": str(cfg.home),
        "marina_site_path": str(cfg.site_path),
        "marina_venv_bin": str(cfg.venv_bin),
        "marina_cache_dir": str(cfg.cache_dir),
        "marina_app_port": cfg.app_port,
        "marina_gunicorn_workers": cfg.gunicorn_workers,
        "marina_gunicorn_timeout": cfg.gunicorn_timeout,
        "marina_django_settings_module": cfg.django_settings_module,
        "marina_django_secret_key": SECRET_KEY,
        "marina_django_admin_url": cfg.django_admin_url,
        "marina_django_allowed_hosts": cfg.allowed_hosts,
        "marina_django_cache_location": str(cfg.cache_dir),
        "marina_fqdn": cfg.fqdn,
        "marina_traefik_host_rule": cfg.traefik_host_rule,
        "marina_systemd_hardening": cfg.systemd_hardening,
    }


def make(source: Path, **overrides: Any) -> tuple[MarinaConfig, SecretValues]:
    fields: dict[str, Any] = {
        "fqdn": "marina-adler.de",
        "traefik_host_rule": "Host(`marina-adler.de`) || Host(`www.marina-adler.de`)",
        **overrides,
    }
    cfg = MarinaConfig(source_path=source, secrets=SecretRef("secrets/prod/marina.yml"), **fields)
    assert cfg.secrets is not None
    values = {
        "django_secret_key": SECRET_KEY,
        "admin_username": "u",
        "admin_email": "e@example.org",
        "admin_password": "p",
    }
    return cfg, SecretValues(cfg.secrets, values)


CONFIGS: list[dict[str, Any]] = [
    {},
    {"fqdn": "marina.staging.example.com", "traefik_host_rule": "Host(`marina.staging.example.com`)"},
    {"app_port": 10100, "gunicorn_workers": 2, "gunicorn_timeout": 60, "systemd_hardening": True},
    {"user": "site", "group": "web", "home": "/srv/site", "site_path": "/srv/site/app"},
    {
        "django_settings_module": "config.settings.staging",
        "django_admin_url": "cms/",
        "django_allowed_hosts": "a.b,c.d",
    },
]


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("overrides", CONFIGS)
def test_env_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    assert render_env(cfg, secrets).reveal().decode() == render_ansible("marina.env.j2", role_vars(cfg))


@pytest.mark.parametrize(
    ("ours", "role"),
    [
        ("marina.service.j2", "systemd.service.j2"),
        ("gunicorn.sh.j2", "gunicorn.sh.j2"),
        ("user_config.fish.j2", "user_config.fish.j2"),
    ],
)
@pytest.mark.parametrize("overrides", CONFIGS)
def test_files_match_role(source: Path, overrides: dict[str, Any], ours: str, role: str) -> None:
    cfg, _ = make(source, **overrides)

    assert render(ours, cfg=cfg) == render_ansible(role, role_vars(cfg))


@pytest.mark.parametrize("overrides", CONFIGS)
def test_route_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, _ = make(source, **overrides)

    assert render_route(cfg) == render_ansible("traefik.yml.j2", role_vars(cfg))
