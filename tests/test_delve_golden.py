"""delve's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/delve`` were recorded when these renders
still equalled the retired delve_deploy role's output; identical bytes mean
the next deploy rewrites nothing and restarts nothing (see tests/goldens.py).
"""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.delve import DelveConfig
from ops_deploy.services.delve.deploy import TEMPLATE_PACKAGE, render_env, render_route, traefik_config
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "delve"
REF = SecretRef("secrets/prod/delve.yml")


# The ops-control playbook's settings, the role defaults, and the other branches.
VARIANTS: dict[str, dict[str, Any]] = {
    "defaults": {},
    "playbook": {
        "public_url": "https://delve.home.example.org",
        "traefik_host": "delve.home.example.org",
        "apple_client_id": "org.example.player",
        "storekit_root_certs_path": "/etc/delve/apple-storekit-root-certs.pem",
        "storekit_bundle_id": "org.example.player",
        "storekit_product_ids": "org.example.player.pro.monthly",
        "admin_emails": "ops@example.org",
        "profile_legacy_reregister": True,
        "apple_signin_legacy_no_nonce": True,
    },
    "everything": {
        "service_name": "delve-x",
        "user": "dx",
        "group": "dxg",
        "site_path": "/srv/delve",
        "data_dir": "/srv/delve-data",
        "config_dir": "/srv/delve-etc",
        "port": 10099,
        "apple_client_id": "org.example.player",
        "apple_server_notifications": True,
        "profile_legacy_reregister": False,
        "apple_signin_legacy_no_nonce": False,
        "env": "staging",
        "traefik_entrypoints": ("web-secure", "internal"),
        "traefik_cert_resolver": "letsencrypt",
        "traefik_admin_ip_allowlist": ("100.64.0.0/10", "fd7a:115c:a1e0::/48"),
        "discovery_collector_concurrency": 8,
        "discovery_collector_calendar": "hourly",
        "systemd_nofile": 4096,
        # Every analysis branch, the media directory outside the data dir.
        "smart_skip_analysis": True,
        "smart_skip_analysis_profile_path": "/srv/delve-etc/profile.json",
        "analysis_media_dir": "/srv/delve-media",
        "analysis_media_disk_cap_bytes": 5000000000,
        "ffprobe_path": "/usr/local/bin/ffprobe",
        "ffmpeg_path": "/usr/local/bin/ffmpeg",
        "voxhelm_url": "https://voxhelm.example.org",
        "voxhelm_token_path": "/srv/delve-etc/vox",
        "voxhelm_timeout_seconds": 90,
        "voxhelm_upload_timeout_seconds": 3600,
        "voxhelm_poll_seconds": 10,
        "detector_url": "http://100.64.0.7:8177",
        "detector_api_key_path": "/srv/delve-etc/det",
        "detector_timeout_seconds": 600,
    },
}
SECRETS: dict[str, dict[str, str]] = {
    "defaults": {"session_secret": "s" * 16},
    "playbook": {"session_secret": "fixture-session-secret-0123", "dogfood_token": "fixture-dogfood"},
    "everything": {"session_secret": "x$y`z(parens)&#'-0123456789", "dogfood_token": "t"},
}


@pytest.fixture(params=sorted(VARIANTS))
def case(request: pytest.FixtureRequest, tmp_path: Path) -> tuple[str, DelveConfig, SecretValues]:
    binary = tmp_path / "delved"
    binary.write_bytes(b"\x7fELF")
    profile = tmp_path / "profile.json"
    profile.write_text('{"taxonomy": "server-taxonomy-v1"}\n')
    variant = dict(VARIANTS[request.param])
    if variant.get("smart_skip_analysis"):
        variant["smart_skip_analysis_profile_src"] = profile
    cfg = DelveConfig(binary_path=binary, secrets=REF, **variant)
    return request.param, cfg, SecretValues(REF, SECRETS[request.param])


def test_host_files_are_golden(case: tuple[str, DelveConfig, SecretValues]) -> None:
    name, cfg, secrets = case
    golden = GOLDEN / name

    for template in ("delve.service.j2", "delve-discovery-collect.service.j2", "delve-discovery-collect.timer.j2"):
        assert_golden(golden / template.removesuffix(".j2"), render(TEMPLATE_PACKAGE, template, cfg=cfg))
    assert_golden(golden / "delve.env", render_env(cfg, secrets).reveal().decode())
    assert_golden(golden / "delve-traefik.yml", render_route(cfg, traefik_config(cfg), None))
