"""weeknotes.home's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/weeknotes_home`` were recorded when these
renders still equalled the retired weeknotes_home_deploy role's output;
identical bytes mean the next deploy rewrites nothing and restarts neither
weeknotes-home nor Traefik (see tests/goldens.py).
"""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.weeknotes_home import WeeknotesHomeConfig
from ops_deploy.services.weeknotes_home.deploy import database_url, render, render_env, render_route, traefik_config
from tests.goldens import assert_golden
from tests.weeknotes_home_fixtures import make_source

GOLDEN = Path(__file__).parent / "golden" / "weeknotes_home"
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#-long-enough'
PASSWORD = 'p@ss/w:rd?#[]"\\ +%'
# A fixed bcrypt hash: hash_password salts randomly.
AUTH_HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"  # pragma: allowlist secret


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


CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    "public-host": {
        "traefik_host": "notes.example.org",
        "django_allowed_hosts": ("127.0.0.1", "localhost", "notes.example.org"),
        "django_csrf_trusted_origins": ("https://notes.example.org", "https://b.example.org"),
        "cast_base_url": "https://cast.example.org",
    },
    "middlewares": {
        "traefik_middlewares": ("ratelimit@file", "extra"),
        "internal_ip_ranges": ("10.0.0.0/8", "fd7a:115c:a1e0::/48"),
    },
}


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("case", sorted(CASES))
def test_host_files_are_golden(source: Path, case: str) -> None:
    cfg, secrets = make(source, **CASES[case])

    assert_golden(GOLDEN / case / "weeknotes-home.env", render_env(cfg, secrets).reveal().decode())
    assert_golden(GOLDEN / case / "weeknotes-home.service", render("weeknotes-home.service.j2", cfg=cfg))
    route = render_route(cfg, traefik_config(cfg, secrets), AUTH_HASH)
    assert_golden(GOLDEN / case / "weeknotes-home.traefik.yml", route)


def test_database_url_quotes_the_password(source: Path) -> None:
    cfg, secrets = make(source)

    assert database_url(cfg, secrets) == (
        "postgres://weeknotes_home:p%40ss%2Fw%3Ard%3F%23%5B%5D%22%5C%20%2B%25@localhost:5432/weeknotes_home"
    )


def test_env_quotes_shell_metacharacters(source: Path) -> None:
    cfg, secrets = make(source)

    env = render_env(cfg, secrets).reveal().decode()

    assert 'DJANGO_SECRET_KEY="k$y`with\\"quotes\\\\and(parens)&amp;#-long-enough"' in env.splitlines()
