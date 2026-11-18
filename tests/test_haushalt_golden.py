"""haushalt's host files, recorded.

``defaults`` is the shape ops-control deploys. Against the files the
old deploy in the haushalt repository wrote (2026-10-29), it differs only in
the header comments, the route's edge-header middleware and gunicorn's
``--forwarder-headers=``; ``DJANGO_ALLOWED_HOSTS`` keeps the host name first.
"""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.haushalt import HaushaltConfig
from ops_deploy.services.haushalt.deploy import render_env, render_route, render_unit
from tests.goldens import assert_golden
from tests.haushalt_fixtures import make_source

GOLDEN = Path(__file__).parent / "golden" / "haushalt"
SECRETS = {
    "django_secret_key": "haushalt-parity-key-" + "abcdefghij" * 4,
    "upload_token": "haushalt-parity-upload-token-0123456789abcdef",
}

CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    "no-traefik": {"traefik_enabled": False, "traefik_host": None, "allowed_networks": ()},
}


def make(tmp_path: Path, **overrides: Any) -> tuple[HaushaltConfig, SecretValues]:
    ref = SecretRef("secrets/prod/haushalt.yml")
    settings: dict[str, Any] = {
        "source_path": make_source(tmp_path),
        "secrets": ref,
        "traefik_host": "haushalt.example.com",
        "allowed_networks": ("100.64.0.0/10", "fd7a:115c:a1e0::/48"),
    }
    return HaushaltConfig(**{**settings, **overrides}), SecretValues(ref, SECRETS)


@pytest.mark.parametrize("case", sorted(CASES))
def test_host_files_are_golden(tmp_path: Path, case: str) -> None:
    cfg, secrets = make(tmp_path, **CASES[case])

    assert_golden(GOLDEN / case / "env", render_env(cfg, secrets).reveal().decode())
    assert_golden(GOLDEN / case / "haushalt.service", render_unit(cfg))
    if cfg.traefik_enabled:
        assert_golden(GOLDEN / case / "traefik.yml", render_route(cfg))
