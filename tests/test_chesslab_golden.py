"""chesslab's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/chesslab`` were recorded when these renders
still equalled the retired chesslab_deploy role's output; identical bytes
mean the next deploy rewrites nothing and restarts neither chesslab nor
Traefik (see tests/goldens.py).
"""

import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.chesslab import ChesslabConfig
from ops_deploy.services.chesslab.deploy import render, render_env, render_route, traefik_config
from tests.chesslab_fixtures import make_source
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "chesslab"
# A fixed bcrypt hash: hash_password salts randomly.
AUTH_HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"  # pragma: allowlist secret
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#-long-enough'


def make(source: Path, **overrides: Any) -> tuple[ChesslabConfig, SecretValues]:
    cfg = ChesslabConfig(source_path=source, secrets=SecretRef("secrets/prod/chesslab.yml"), **overrides)
    assert cfg.secrets is not None
    users = [{"username": "u", "password": "p", "owner": "o"}]
    values = {"session_secret": AWKWARD, "users": json.dumps(users), "basic_auth_password": "fixture-password"}
    return cfg, SecretValues(cfg.secrets, values)


CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    "public-host": {
        "traefik_host": "chess.example.org",
        "django_allowed_hosts": ("127.0.0.1", "localhost", "chess.example.org"),
        "django_csrf_trusted_origins": ("https://chess.example.org", "https://b.example.org"),
    },
    "middlewares": {"traefik_middlewares": ("ratelimit@file", "extra"), "internal_ip_ranges": ("10.0.0.0/8",)},
}


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("case", sorted(CASES))
def test_host_files_are_golden(source: Path, case: str) -> None:
    cfg, secrets = make(source, **CASES[case])

    assert_golden(GOLDEN / case / "chesslab.env", render_env(cfg, secrets).reveal().decode())
    assert_golden(GOLDEN / case / "chesslab.service", render("chesslab.service.j2", cfg=cfg))
    assert_golden(GOLDEN / case / "chesslab.traefik.yml", render_route(traefik_config(cfg, secrets), AUTH_HASH))


def test_env_quotes_shell_metacharacters(source: Path) -> None:
    cfg, secrets = make(source)

    env = render_env(cfg, secrets).reveal().decode()

    assert 'CHESSLAB_SECRET_KEY="k$y`with\\"quotes\\\\and(parens)&amp;#-long-enough"' in env.splitlines()
