"""opaq_app's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/opaq_app`` were recorded when these renders
still equalled the retired opaq_app_deploy role's output; identical bytes
mean the next deploy rewrites nothing and restarts nothing (see
tests/goldens.py). ``DJANGO_ALLOWED_HOSTS`` keeps order, host name first.
"""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.opaq_app import OpaqAppConfig
from ops_deploy.services.opaq_app.deploy import TEMPLATE_PACKAGE, render_env, render_route
from tests.goldens import assert_golden
from tests.opaq_app_fixtures import make_source

GOLDEN = Path(__file__).parent / "golden" / "opaq_app"
SECRETS = {
    "django_secret_key": "opaq-parity-key-" + "abcdefghij" * 4,
    "upload_token": "opaq-parity-upload-token-0123456789abcdef",
}


CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    "allowlist": {
        "allowed_networks": ("10.0.0.0/8",),
        "traefik_entrypoint": "websecure",
        "traefik_http_entrypoint": "http",
    },
    "no-traefik": {"traefik_enabled": False, "traefik_host": None, "allowed_networks": ()},
}


def make(tmp_path: Path, **overrides: Any) -> tuple[OpaqAppConfig, SecretValues]:
    ref = SecretRef("secrets/prod/opaq_app.yml")
    settings: dict[str, Any] = {
        "source_path": make_source(tmp_path),
        "secrets": ref,
        "traefik_host": "opaq.example.com",
        "allowed_networks": ("100.64.0.0/10", "fd7a:115c:a1e0::/48"),
    }
    return OpaqAppConfig(**{**settings, **overrides}), SecretValues(ref, SECRETS)


@pytest.mark.parametrize("case", sorted(CASES))
def test_host_files_are_golden(tmp_path: Path, case: str) -> None:
    cfg, secrets = make(tmp_path, **CASES[case])

    assert_golden(GOLDEN / case / "env", render_env(cfg, secrets).reveal().decode())
    assert_golden(GOLDEN / case / "opaq-app.service", render(TEMPLATE_PACKAGE, "opaq-app.service.j2", cfg=cfg))
    if cfg.traefik_enabled:
        assert_golden(GOLDEN / case / "traefik.yml", render_route(cfg))
