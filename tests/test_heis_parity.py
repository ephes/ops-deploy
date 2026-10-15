"""heis files are byte-identical to the heis_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
Ansible and ops-deploy take turns on a host without rewriting files or
restarting heis.
"""

import shlex
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.heis import HeisConfig
from ops_deploy.services.heis.deploy import render, render_env, render_route
from tests.heis_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
SECRET_KEY = "fixture-Key_0123456789+=:,./-%@abc$`'\"(x) y"
ADMIN_URL = "hidden-admin-fixture/"


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = bool
    env.filters["quote"] = shlex.quote
    env.filters["ternary"] = lambda value, yes, no: yes if value else no
    return env.get_template(f"heis_deploy__{template}").render(**variables)


def role_vars(cfg: HeisConfig) -> dict[str, Any]:
    return {
        "heis_user": cfg.user,
        "heis_home": str(cfg.home),
        "heis_site_path": str(cfg.site_path),
        "heis_venv_bin": str(cfg.venv_bin),
        "heis_cache_dir": str(cfg.cache_dir),
        "heis_app_port": cfg.app_port,
        "heis_gunicorn_workers": cfg.gunicorn_workers,
        "heis_gunicorn_timeout": cfg.gunicorn_timeout,
        "heis_django_settings_module": cfg.django_settings_module,
        "heis_django_secret_key": SECRET_KEY,
        "heis_django_admin_url": ADMIN_URL,
        "heis_django_allowed_hosts": cfg.allowed_hosts,
        "heis_django_cache_location": str(cfg.cache_dir),
        "heis_fqdn": cfg.fqdn,
        "heis_traefik_host_rule": cfg.traefik_host_rule,
        "heis_traefik_tls_host_rule": cfg.tls_host_rule,
        "heis_traefik_canonical_redirect_regex": cfg.traefik_canonical_redirect_regex,
        "heis_traefik_canonical_redirect_replacement": cfg.traefik_canonical_redirect_replacement,
        "heis_serve_media": cfg.serve_media,
        "heis_wagtailadmin_base_url": f"https://{cfg.fqdn}"
        if cfg.wagtailadmin_base_url is None
        else cfg.wagtailadmin_base_url,
    }


def make(source: Path, **overrides: Any) -> tuple[HeisConfig, SecretValues]:
    fields: dict[str, Any] = {
        "fqdn": "fabian-heis.de",
        "traefik_host_rule": "Host(`fabian-heis.de`) || Host(`www.fabian-heis.de`)",
        **overrides,
    }
    cfg = HeisConfig(source_path=source, secrets=SecretRef("secrets/prod/heis.yml"), **fields)
    assert cfg.secrets is not None
    values = {
        "django_secret_key": SECRET_KEY,
        "django_admin_url": ADMIN_URL,
        "admin_username": "u",
        "admin_email": "e@example.org",
        "admin_password": "p",
    }
    return cfg, SecretValues(cfg.secrets, values)


CONFIGS: list[dict[str, Any]] = [
    {},
    {"fqdn": "heis.staging.example.com", "traefik_host_rule": "Host(`heis.staging.example.com`)"},
    {"app_port": 10100, "gunicorn_workers": 2, "gunicorn_timeout": 60, "serve_media": True},
    # Production's shape (inventories/prod/host_vars/heis.yml).
    {
        "traefik_host_rule": "Host(`fabian-heis.de`) || Host(`www.fabian-heis.de`) || "
        "Host(`fabian-heis.com`) || Host(`www.fabian-heis.com`)",
        "traefik_tls_host_rule": "Host(`fabian-heis.de`) || Host(`www.fabian-heis.de`) || "
        "Host(`fabian-heis.com`) || Host(`www.fabian-heis.com`)",
        "traefik_canonical_redirect_regex": r"^https?://(?:www\.fabian-heis\.de|(?:www\.)?fabian-heis\.com)(.*)$",
        "traefik_canonical_redirect_replacement": "https://fabian-heis.de${1}",
        "django_allowed_hosts": "fabian-heis.de,www.fabian-heis.de,fabian-heis.com,www.fabian-heis.com,localhost",
        "serve_media": True,
        "setup_default_pages": False,
        "seed_content": False,
    },
    {"traefik_tls_host_rule": "Host(`fabian-heis.de`)", "wagtailadmin_base_url": "https://cms.example.org"},
    {"user": "site", "group": "web", "home": "/srv/site", "site_path": "/srv/site/app"},
    {
        "django_settings_module": "config.settings.staging",
        "django_allowed_hosts": "a.b,c.d",
    },
]


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("overrides", CONFIGS)
def test_env_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    assert render_env(cfg, secrets).reveal().decode() == render_ansible("heis.env.j2", role_vars(cfg))


@pytest.mark.parametrize(
    ("ours", "role"),
    [
        ("heis.service.j2", "systemd.service.j2"),
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
