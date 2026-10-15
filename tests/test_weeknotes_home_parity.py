"""weeknotes.home files are byte-identical to the weeknotes_home_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
Ansible and ops-deploy take turns on a host without rewriting files or
restarting weeknotes-home or Traefik.
"""

import os
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.weeknotes_home import WeeknotesHomeConfig
from ops_deploy.services.weeknotes_home.deploy import database_url, render, render_env, render_route, traefik_config
from tests.weeknotes_home_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
DEFAULTS = Path(__file__).parent / "parity" / "weeknotes_home_defaults.yml"
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#-long-enough'
PASSWORD = 'p@ss/w:rd?#[]"\\ +%'


def environment(loader: jinja2.BaseLoader) -> jinja2.Environment:
    env = jinja2.Environment(
        loader=loader, undefined=jinja2.StrictUndefined, trim_blocks=True, keep_trailing_newline=True
    )
    env.filters["bool"] = bool  # Ansible's ``bool`` filter, for real booleans
    return env


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = environment(jinja2.FileSystemLoader(VENDORED))
    return env.get_template(f"weeknotes_home_deploy__{template}").render(**variables)


def role_database_url(variables: dict[str, Any]) -> str:
    """The expression of the role's ``weeknotes_home_database_url`` default, evaluated by Jinja."""

    expression = yaml.safe_load(DEFAULTS.read_text())["weeknotes_home_database_url"]
    return environment(jinja2.BaseLoader()).from_string(expression).render(**variables)


def role_vars(cfg: WeeknotesHomeConfig, secrets: SecretValues, auth_hash: str = "") -> dict[str, Any]:
    route = traefik_config(cfg, secrets)
    variables: dict[str, Any] = {
        "weeknotes_home_service_name": cfg.service_name,
        "weeknotes_home_user": cfg.user,
        "weeknotes_home_group": cfg.group,
        "weeknotes_home_home": str(cfg.home),
        "weeknotes_home_service_path": str(cfg.service_path),
        "weeknotes_home_env_path": str(cfg.env_path),
        "weeknotes_home_venv_bin": str(cfg.venv_bin),
        "weeknotes_home_cache_dir": str(cfg.cache_dir),
        "weeknotes_home_static_root": str(cfg.static_root),
        "weeknotes_home_gunicorn_workers": cfg.workers,
        "weeknotes_home_gunicorn_timeout": cfg.timeout,
        "weeknotes_home_app_host": cfg.app_host,
        "weeknotes_home_app_port": cfg.app_port,
        "weeknotes_home_wsgi_module": cfg.wsgi_module,
        "weeknotes_home_django_settings_module": cfg.django_settings_module,
        "weeknotes_home_django_secret_key": secrets["django_secret_key"],
        "weeknotes_home_django_debug": cfg.django_debug,
        "weeknotes_home_django_allowed_hosts": list(cfg.django_allowed_hosts),
        "weeknotes_home_django_csrf_trusted_origins": list(cfg.django_csrf_trusted_origins),
        "weeknotes_home_django_db_conn_max_age": cfg.db_conn_max_age,
        "weeknotes_home_cast_base_url": cfg.cast_base_url,
        "weeknotes_home_api_token": secrets["api_token"],
        "weeknotes_home_postgres_host": cfg.postgres_host,
        "weeknotes_home_postgres_port": cfg.postgres_port,
        "weeknotes_home_postgres_database": cfg.postgres_database,
        "weeknotes_home_postgres_user": cfg.postgres_user,
        "weeknotes_home_postgres_password": secrets["postgres_password"],
        "weeknotes_home_traefik_host": cfg.traefik_host,
        "weeknotes_home_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "weeknotes_home_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "weeknotes_home_traefik_middlewares": list(cfg.traefik_middlewares),
        "weeknotes_home_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "weeknotes_home_basic_auth_enabled": True,
        "weeknotes_home_basic_auth_remove_header": True,
        "weeknotes_home_basic_auth_user": route.basic_auth.user if route.basic_auth else "",
        "weeknotes_home_basic_auth_password_hash": auth_hash,
    }
    variables["weeknotes_home_database_url"] = role_database_url(variables)
    return variables


def make(source: Path, **overrides: Any) -> tuple[WeeknotesHomeConfig, SecretValues]:
    cfg = WeeknotesHomeConfig(source_path=source, secrets=SecretRef("secrets/prod/weeknotes_home.yml"), **overrides)
    assert cfg.secrets is not None
    values = {
        "django_secret_key": AWKWARD,
        "postgres_password": PASSWORD,
        "api_token": "a" * 40,
        "basic_auth_password": "fixture-password",
    }
    return cfg, SecretValues(cfg.secrets, values)


CONFIGS: list[dict[str, Any]] = [
    {},
    {
        "traefik_host": "notes.example.org",
        "django_allowed_hosts": ("127.0.0.1", "localhost", "notes.example.org"),
        "django_csrf_trusted_origins": ("https://notes.example.org", "https://b.example.org"),
        "cast_base_url": "https://cast.example.org",
    },
    {"django_debug": True, "workers": 4, "timeout": 30, "app_port": 10100, "db_conn_max_age": 0},
    {
        "user": "notes",
        "group": "games",
        "home": "/srv/notes",
        "site_path": "/srv/notes/site",
        "postgres_database": "notes_db",
        "postgres_user": "notes",
        "postgres_port": 5433,
    },
    {"traefik_cert_resolver": "letsencrypt", "traefik_entrypoints": ("web-secure", "alt")},
    {"traefik_middlewares": ("ratelimit@file", "extra"), "internal_ip_ranges": ("10.0.0.0/8", "fd7a:115c:a1e0::/48")},
]


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("overrides", CONFIGS)
def test_env_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    assert render_env(cfg, secrets).reveal().decode() == render_ansible(
        "weeknotes-home.env.j2", role_vars(cfg, secrets)
    )


@pytest.mark.parametrize("overrides", CONFIGS)
def test_unit_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    ours = render("weeknotes-home.service.j2", cfg=cfg)

    assert ours == render_ansible("weeknotes-home.service.j2", role_vars(cfg, secrets))


@pytest.mark.parametrize("overrides", CONFIGS)
def test_route_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)
    auth_hash = hash_password("fixture-password")

    ours = render_route(cfg, traefik_config(cfg, secrets), auth_hash)

    assert ours == render_ansible("weeknotes-home.traefik.yml.j2", role_vars(cfg, secrets, auth_hash))


def test_database_url_matches_the_role_default(source: Path) -> None:
    cfg, secrets = make(source)

    assert database_url(cfg, secrets) == role_database_url(role_vars(cfg, secrets))
    assert "%2F" in database_url(cfg, secrets)


def test_env_quotes_what_the_role_quotes(source: Path) -> None:
    cfg, secrets = make(source)

    env = render_env(cfg, secrets).reveal().decode()

    assert 'DJANGO_SECRET_KEY="k$y`with\\"quotes\\\\and(parens)&amp;#-long-enough"' in env.splitlines()


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_vendored_database_url_matches_ops_library() -> None:
    library = Path(os.environ["OPS_LIBRARY_PATH"], "roles", "weeknotes_home_deploy", "defaults", "main.yml")

    vendored = yaml.safe_load(DEFAULTS.read_text())["weeknotes_home_database_url"]

    assert vendored == yaml.safe_load(library.read_text())["weeknotes_home_database_url"]
