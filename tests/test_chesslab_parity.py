"""chesslab files are byte-identical to the chesslab_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
Ansible and ops-deploy take turns on a host without rewriting files or
restarting chesslab or Traefik.
"""

import json
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.chesslab import ChesslabConfig
from ops_deploy.services.chesslab.deploy import render, render_env, render_route, traefik_config
from tests.chesslab_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#-long-enough'


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["dirname"] = lambda value: str(Path(value).parent)
    return env.get_template(f"chesslab_deploy__{template}").render(**variables)


def role_vars(cfg: ChesslabConfig, secrets: SecretValues, auth_hash: str = "") -> dict[str, Any]:
    route = traefik_config(cfg, secrets)
    return {
        "chesslab_user": cfg.user,
        "chesslab_group": cfg.group,
        "chesslab_home": str(cfg.home),
        "chesslab_site_path": str(cfg.site_path),
        "chesslab_data_path": str(cfg.data_path),
        "chesslab_db_path": str(cfg.db_path),
        "chesslab_env_path": str(cfg.env_path),
        "chesslab_venv_bin": str(cfg.venv_bin),
        "chesslab_workers": cfg.workers,
        "chesslab_app_host": cfg.app_host,
        "chesslab_app_port": cfg.app_port,
        "chesslab_wsgi_module": cfg.wsgi_module,
        "chesslab_limit": cfg.limit,
        "chesslab_django_settings_module": cfg.django_settings_module,
        "chesslab_django_secret_key": secrets.get("secret_key") or secrets["session_secret"],
        "chesslab_django_debug": cfg.django_debug,
        "chesslab_django_allowed_hosts": list(cfg.django_allowed_hosts),
        "chesslab_django_csrf_trusted_origins": list(cfg.django_csrf_trusted_origins),
        "chesslab_secure_cookies": cfg.secure_cookies,
        "chesslab_traefik_host": cfg.traefik_host,
        "chesslab_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "chesslab_traefik_middlewares": list(cfg.traefik_middlewares),
        "chesslab_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "chesslab_basic_auth_enabled": True,
        "chesslab_basic_auth_user": route.basic_auth.user if route.basic_auth else "",
        "chesslab_basic_auth_password_hash": auth_hash,
    }


def make(source: Path, **overrides: Any) -> tuple[ChesslabConfig, SecretValues]:
    cfg = ChesslabConfig(source_path=source, secrets=SecretRef("secrets/prod/chesslab.yml"), **overrides)
    assert cfg.secrets is not None
    users = [{"username": "u", "password": "p", "owner": "o"}]
    values = {"session_secret": AWKWARD, "users": json.dumps(users), "basic_auth_password": "fixture-password"}
    return cfg, SecretValues(cfg.secrets, values)


CONFIGS: list[dict[str, Any]] = [
    {},
    {
        "traefik_host": "chess.example.org",
        "django_allowed_hosts": ("127.0.0.1", "localhost", "chess.example.org"),
        "django_csrf_trusted_origins": ("https://chess.example.org", "https://b.example.org"),
    },
    {"django_debug": True, "secure_cookies": False, "limit": "25", "workers": 4, "app_port": 10100},
    {"user": "chess", "group": "games", "home": "/srv/chess", "site_path": "/srv/chess/site", "data_path": "/srv/d"},
    {"db_path": "/var/lib/chess/db/chess.db", "traefik_cert_resolver": "letsencrypt"},
    {"traefik_middlewares": ("ratelimit@file", "extra"), "internal_ip_ranges": ("10.0.0.0/8",)},
]


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("overrides", CONFIGS)
def test_env_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    assert render_env(cfg, secrets).reveal().decode() == render_ansible("chesslab.env.j2", role_vars(cfg, secrets))


@pytest.mark.parametrize("overrides", CONFIGS)
def test_unit_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    assert render("chesslab.service.j2", cfg=cfg) == render_ansible("chesslab.service.j2", role_vars(cfg, secrets))


@pytest.mark.parametrize("overrides", CONFIGS)
def test_route_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)
    auth_hash = hash_password("fixture-password")

    ours = render_route(traefik_config(cfg, secrets), auth_hash)

    assert ours == render_ansible("chesslab.traefik.yml.j2", role_vars(cfg, secrets, auth_hash))


def test_env_quotes_what_the_role_quotes(source: Path) -> None:
    cfg, secrets = make(source)

    env = render_env(cfg, secrets).reveal().decode()

    assert 'CHESSLAB_SECRET_KEY="k$y`with\\"quotes\\\\and(parens)&amp;#-long-enough"' in env.splitlines()
