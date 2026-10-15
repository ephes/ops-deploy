"""work_app files are byte-identical to the work_app_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
Ansible and ops-deploy take turns on a host without rewriting files or
restarting work-app.
"""

from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.work_app import WorkAppConfig
from ops_deploy.services.work_app.deploy import render, render_env, render_route, traefik_config
from tests.work_app_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
KEY = "k-" + "0123456789abcdefghijklmnopqrstuvwxyz" * 2


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(f"work_app_deploy__{template}").render(**variables)


def role_vars(cfg: WorkAppConfig, secrets: SecretValues, auth_hash: str = "") -> dict[str, Any]:
    route = traefik_config(cfg, secrets)
    return {
        "work_app_user": cfg.user,
        "work_app_group": cfg.group,
        "work_app_home": str(cfg.home),
        "work_app_site_path": str(cfg.site_path),
        "work_app_venv_bin": str(cfg.venv_bin),
        "work_app_env_file": str(cfg.env_path),
        "work_app_database_path": str(cfg.database_path),
        "work_app_static_root": str(cfg.static_root),
        "work_app_workers": cfg.workers,
        "work_app_app_host": cfg.app_host,
        "work_app_app_port": cfg.app_port,
        "work_app_wsgi_module": cfg.wsgi_module,
        "work_app_django_settings_module": cfg.django_settings_module,
        "work_app_secret_key": secrets["django_secret_key"],
        "work_app_django_debug": cfg.django_debug,
        "work_app_django_allowed_hosts": list(cfg.django_allowed_hosts),
        "work_app_django_csrf_trusted_origins": list(cfg.django_csrf_trusted_origins),
        "work_app_django_admin_url": cfg.django_admin_url,
        "work_app_evidence_base_url": cfg.evidence_base_url,
        "work_app_traefik_host": cfg.traefik_host,
        "work_app_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "work_app_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "work_app_basic_auth_enabled": True,
        "work_app_basic_auth_user": route.basic_auth.user if route.basic_auth else "",
        "work_app_basic_auth_password_hash": auth_hash,
    }


def make(source: Path, **overrides: Any) -> tuple[WorkAppConfig, SecretValues]:
    cfg = WorkAppConfig(source_path=source, secrets=SecretRef("secrets/prod/work_app.yml"), **overrides)
    assert cfg.secrets is not None
    return cfg, SecretValues(cfg.secrets, {"django_secret_key": KEY, "basic_auth_password": "fixture-password"})


CONFIGS: list[dict[str, Any]] = [
    {},
    {
        "traefik_host": "work.example.org",
        "django_allowed_hosts": ("127.0.0.1", "localhost", "work.example.org"),
        "django_csrf_trusted_origins": ("https://work.example.org", "https://b.example.org"),
    },
    {"django_debug": True, "workers": 4, "app_port": 10100, "django_admin_url": "manage-admin/"},
    {"user": "ledger", "group": "ops", "home": "/srv/ledger", "site_path": "/srv/ledger/site"},
    {"database_path": "/srv/data/db.sqlite3", "traefik_cert_resolver": "letsencrypt"},
    {"internal_ip_ranges": ("10.0.0.0/8",), "evidence_base_url": "https://example.com/blob/main/"},
    {"django_settings_module": "config.settings.staging", "wsgi_module": "config.wsgi:application"},
]


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("overrides", CONFIGS)
def test_env_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    assert render_env(cfg, secrets).reveal().decode() == render_ansible("env.j2", role_vars(cfg, secrets))


@pytest.mark.parametrize("overrides", CONFIGS)
def test_unit_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    assert render("work-app.service.j2", cfg=cfg) == render_ansible("work-app.service.j2", role_vars(cfg, secrets))


@pytest.mark.parametrize("overrides", CONFIGS)
def test_route_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)
    auth_hash = hash_password("fixture-password")

    ours = render_route(traefik_config(cfg, secrets), auth_hash)

    assert ours == render_ansible("traefik.yml.j2", role_vars(cfg, secrets, auth_hash))


def test_env_is_unquoted_like_the_role(source: Path) -> None:
    cfg, secrets = make(source)

    lines = render_env(cfg, secrets).reveal().decode().splitlines()

    assert f"DJANGO_SECRET_KEY={KEY}" in lines
    assert "DJANGO_DEBUG=false" in lines
    assert "DATABASE_URL=sqlite:////home/work/site/db.sqlite3" in lines
