"""The MinIO unit, env file and route are the bytes hosts have (recorded from the role's renders)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.minio import MinioConfig, MinioCredentials
from ops_deploy.services.minio.render import render
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "minio"
# Synthetic bcrypt-shaped value, not a real hash of anything.
AUTH_HASH = "$2y$05$abcdefghijklmnopqrstuu012345678901234567890123456789012"  # pragma: allowlist secret
CASES: dict[str, tuple[dict[str, Any], dict[str, str]]] = {
    "defaults": ({}, {}),
    "custom-tls": (
        {
            "user": "fixtureminio",
            "group": "fixtureminio",
            "home": "/srv/minio",
            "data_dirs": ["/srv/minio/data"],
            "config_dir": "/etc/fixture-minio",
            "certs_dir": "/etc/fixture-minio/certs",
            "env_file": "/etc/default/fixture-minio",
            "api_port": 19001,
            "console_port": 19002,
            "tls_enable": True,
            "sse_enabled": True,
            "systemd_memory_max": "2G",
            "systemd_limit_nofile": 32768,
            "systemd_tasks_max": "4096",
            "traefik_host": "minio.example.test",
            "traefik_api_host": "objects.example.test",
            "traefik_cert_resolver": "letsencrypt",
            "internal_ip_ranges": ["192.0.2.0/24", "2001:db8::/32"],
        },
        {"sse_master_key": "fixture-key:synthetic-only"},
    ),
    "api-internal-only": (
        {
            "console_basic_auth_enabled": False,
            "traefik_host": "console.example.test",
            "traefik_api_host": "storage.example.test",
            "data_dirs": ["/srv/minio/one", "/srv/minio/two"],
            "traefik_api_internal_only": True,
            "internal_ip_ranges": ["10.0.0.0/8", "100.64.0.0/10"],
        },
        {},
    ),
}


@pytest.mark.parametrize("case", sorted(CASES))
@pytest.mark.parametrize("template", ["minio.env.j2", "minio.service.j2", "traefik-minio.yml.j2"])
def test_render_matches_golden(case: str, template: str) -> None:
    config, extra = CASES[case]
    cfg = MinioConfig.model_validate(config)
    credentials = MinioCredentials.model_validate(
        {"root_user": "fixture-root", "root_password": "fixture-root-value", **extra}
    )
    assert_golden(GOLDEN / case / template.removesuffix(".j2"), render(template, cfg, credentials, AUTH_HASH))
