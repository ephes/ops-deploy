"""recorder's host files against their recorded renders.

The goldens under ``tests/golden/recorder`` were first recorded when these
renders still equalled the retired recorder_deploy role's output. The env
file and the route still do; the unit has since gained ``MemoryMax=``
(``systemd_memory_max``, see docs/changelog.md) and equals the role's unit
only with that field empty. Identical bytes mean the next deploy rewrites
nothing and restarts nothing (see tests/goldens.py).
"""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.recorder import RecorderConfig
from ops_deploy.services.recorder.deploy import TEMPLATE_PACKAGE, render_env, render_route, traefik_config
from tests.goldens import assert_golden
from tests.recorder_fixtures import make_source

GOLDEN = Path(__file__).parent / "golden" / "recorder"
HOST = "recorder.example.com"
ALL_SECRETS = {
    "session_secret": "fixture-session-secret",
    "admin_emails": "a@example.com,b@example.com",
    "mail_api_url": "https://mail.example.com",
    "mail_domain": "mg.example.com",
    "mail_token": "fixture-mail-token",
    "mail_from": "Recorder <rec@example.com>",
    "s3_access_key": "fixture-access",
    "s3_secret_key": "fixture-secret",
    "livekit_url": "wss://live.example.com",
    "livekit_host_url": "",
    "livekit_api_key": "fixture-lk-key",
    "livekit_api_secret": "fixture-lk-secret",
}


def make(tmp_path: Path, **overrides: Any) -> RecorderConfig:
    return RecorderConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/recorder.yml"),
        public_url=f"https://{HOST}",
        traefik_host=HOST,
        **overrides,
    )


VARIANTS: dict[str, tuple[dict[str, Any], dict[str, str]]] = {
    "minimal": ({}, {"session_secret": "s", "admin_emails": "a@example.com"}),
    "production": ({"s3_endpoint": "127.0.0.1:9001"}, {k: v for k, v in ALL_SECRETS.items() if "livekit" not in k}),
    "everything": (
        {
            "s3_endpoint": "minio:9000",
            "s3_use_ssl": True,
            "max_chunk_bytes": 8388608,
            "upload_buffer_bytes": 33554432,
            "live_room_prefix": "x-",
        },
        ALL_SECRETS,
    ),
}


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_env_file_is_golden(tmp_path: Path, name: str) -> None:
    overrides, secrets = VARIANTS[name]
    cfg = make(tmp_path, **overrides)

    env = render_env(cfg, SecretValues(SecretRef("secrets/prod/recorder.yml"), secrets)).reveal().decode()

    assert_golden(GOLDEN / name / "recorder.env", env)


def test_unit_and_route_are_golden(tmp_path: Path) -> None:
    cfg = make(tmp_path)

    assert_golden(GOLDEN / "recorder.service", render(TEMPLATE_PACKAGE, "recorder.service.j2", cfg=cfg))
    assert_golden(GOLDEN / "recorder-traefik.yml", render_route(cfg, traefik_config(cfg)))


def test_unit_without_memory_limit_drops_only_that_block(tmp_path: Path) -> None:
    limited = render(TEMPLATE_PACKAGE, "recorder.service.j2", cfg=make(tmp_path))
    unlimited = render(TEMPLATE_PACKAGE, "recorder.service.j2", cfg=make(tmp_path, systemd_memory_max=""))

    assert "MemoryMax=1G\n" in limited
    assert "MemoryMax" not in unlimited
    block = limited[limited.index("# Upper bound for the whole service.") : limited.index("# Hardening")]
    assert limited.replace(block, "") == unlimited
    assert "MemoryMax=2G\n" in render(
        TEMPLATE_PACKAGE, "recorder.service.j2", cfg=make(tmp_path, systemd_memory_max="2G")
    )
