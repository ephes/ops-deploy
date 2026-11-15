"""homelab's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/homelab`` were recorded when these renders
still equalled the retired homelab_deploy role's output; identical bytes
mean the next deploy rewrites neither the ``.env``, the unit nor the route,
and so does not restart homelab (see tests/goldens.py).
"""

from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.homelab import HomelabConfig
from ops_deploy.services.homelab.deploy import (
    render_env,
    render_route,
    render_unit,
    traefik_config,
)
from tests.goldens import assert_golden
from tests.homelab_fixtures import make_source

GOLDEN = Path(__file__).parent / "golden" / "homelab"
# A fixed bcrypt hash: hash_password salts randomly.
AUTH_HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"  # pragma: allowlist secret
SECRET_KEY = "homelab-parity-key_with-symbols!@#%^*=+-0123456789"


CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    "public-host": {"traefik_host": "home.example.org", "django_allowed_hosts": "127.0.0.1,home.example.org"},
    "resolver-ranges": {
        "traefik_cert_resolver": "letsencrypt",
        "internal_ip_ranges": ("10.0.0.0/8", "fd00:1234:5678::/64"),
    },
}


def make(source: Path, **overrides: Any) -> tuple[HomelabConfig, SecretValues]:
    cfg = HomelabConfig(source_path=source, secrets=SecretRef("secrets/prod/homelab.yml"), **overrides)
    assert cfg.secrets is not None
    values = {"django_secret_key": SECRET_KEY, "basic_auth_password": "fixture-password", "basic_auth_user": "ops"}
    return cfg, SecretValues(cfg.secrets, values)


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("case", sorted(CASES))
def test_host_files_are_golden(source: Path, case: str) -> None:
    cfg, secrets = make(source, **CASES[case])

    env = render_env(cfg, secrets).reveal().decode()
    route = render_route(cfg, traefik_config(cfg, secrets), AUTH_HASH)

    assert_golden(GOLDEN / case / "env", env)
    assert_golden(GOLDEN / case / "homelab.service", render_unit(cfg))
    assert_golden(GOLDEN / case / "homelab.yml", route)
    assert f"DJANGO_SECRET_KEY={SECRET_KEY}" in env.splitlines()
    assert yaml.safe_load(route)["http"]["middlewares"]["homelab-auth"]["basicAuth"]["users"] == [f"ops:{AUTH_HASH}"]


def test_route_path(source: Path) -> None:
    cfg, secrets = make(source)

    assert traefik_config(cfg, secrets).path == PurePosixPath("/etc/traefik/dynamic/homelab.yml")
