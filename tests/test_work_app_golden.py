"""work_app's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/work_app`` were recorded when these renders
still equalled the retired work_app_deploy role's output; identical bytes
mean the next deploy rewrites nothing and restarts nothing (see
tests/goldens.py).
"""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.work_app import WorkAppConfig
from ops_deploy.services.work_app.deploy import render, render_env, render_route, traefik_config
from tests.goldens import assert_golden
from tests.work_app_fixtures import make_source

GOLDEN = Path(__file__).parent / "golden" / "work_app"
# A fixed bcrypt hash: hash_password salts randomly.
AUTH_HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"  # pragma: allowlist secret
KEY = "k-" + "0123456789abcdefghijklmnopqrstuvwxyz" * 2


def make(source: Path, **overrides: Any) -> tuple[WorkAppConfig, SecretValues]:
    cfg = WorkAppConfig(source_path=source, secrets=SecretRef("secrets/prod/work_app.yml"), **overrides)
    assert cfg.secrets is not None
    return cfg, SecretValues(cfg.secrets, {"django_secret_key": KEY, "basic_auth_password": "fixture-password"})


CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    "public-host": {
        "traefik_host": "work.example.org",
        "django_allowed_hosts": ("127.0.0.1", "localhost", "work.example.org"),
        "django_csrf_trusted_origins": ("https://work.example.org", "https://b.example.org"),
    },
    "evidence": {"internal_ip_ranges": ("10.0.0.0/8",), "evidence_base_url": "https://example.com/blob/main/"},
}


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("case", sorted(CASES))
def test_host_files_are_golden(source: Path, case: str) -> None:
    cfg, secrets = make(source, **CASES[case])

    assert_golden(GOLDEN / case / "env", render_env(cfg, secrets).reveal().decode())
    assert_golden(GOLDEN / case / "work-app.service", render("work-app.service.j2", cfg=cfg))
    assert_golden(GOLDEN / case / "traefik.yml", render_route(traefik_config(cfg, secrets), AUTH_HASH))


def test_env_is_unquoted(source: Path) -> None:
    cfg, secrets = make(source)

    lines = render_env(cfg, secrets).reveal().decode().splitlines()

    assert f"DJANGO_SECRET_KEY={KEY}" in lines
    assert "DJANGO_DEBUG=false" in lines
    assert "DATABASE_URL=sqlite:////home/work/site/db.sqlite3" in lines
