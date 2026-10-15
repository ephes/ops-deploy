"""recorder files are byte-identical to the recorder_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does.
"""

from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.recorder import RecorderConfig
from ops_deploy.services.recorder.deploy import TEMPLATE_PACKAGE, render_env, render_route, traefik_config
from tests.recorder_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
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


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
    return env.get_template(f"recorder_deploy__{template}").render(**variables)


def role_vars(cfg: RecorderConfig, secrets: dict[str, str]) -> dict[str, Any]:
    """The playbook's role vars for these inputs (``default`` filters applied)."""

    return {
        "recorder_user": cfg.user,
        "recorder_group": cfg.user,
        "recorder_data_dir": str(cfg.data_dir),
        "recorder_env_path": str(cfg.env_path),
        "recorder_bin_path": str(cfg.bin_path),
        "recorder_systemd_nofile": cfg.systemd_nofile,
        "recorder_listen_address": cfg.listen_address,
        "recorder_port": cfg.port,
        "recorder_public_url": cfg.public_url,
        "recorder_live_room_prefix": cfg.live_room_prefix,
        "recorder_max_chunk_bytes": "" if cfg.max_chunk_bytes is None else cfg.max_chunk_bytes,
        "recorder_s3_endpoint": cfg.s3_endpoint,
        "recorder_s3_bucket": cfg.s3_bucket,
        "recorder_s3_access_key": secrets.get("s3_access_key", ""),
        "recorder_s3_secret_key": secrets.get("s3_secret_key", ""),
        "recorder_s3_use_ssl": cfg.s3_use_ssl,
        "recorder_livekit_url": secrets.get("livekit_url", ""),
        "recorder_livekit_host_url": secrets.get("livekit_host_url") or "http://127.0.0.1:7880",
        "recorder_livekit_api_key": secrets.get("livekit_api_key", ""),
        "recorder_livekit_api_secret": secrets.get("livekit_api_secret", ""),
        "recorder_session_secret": secrets.get("session_secret", ""),
        "recorder_admin_emails": secrets.get("admin_emails", ""),
        "recorder_mail_api_url": secrets.get("mail_api_url", cfg.mail_api_url),
        "recorder_mail_domain": secrets.get("mail_domain", cfg.mail_domain),
        "recorder_mail_token": secrets.get("mail_token", ""),
        "recorder_mail_from": secrets.get("mail_from", cfg.mail_from),
        "recorder_traefik_host": cfg.traefik_host,
        "recorder_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "recorder_traefik_cert_resolver": cfg.traefik_cert_resolver,
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
        {"s3_endpoint": "minio:9000", "s3_use_ssl": True, "max_chunk_bytes": 8388608, "live_room_prefix": "x-"},
        ALL_SECRETS,
    ),
    "livekit host override": ({}, {**ALL_SECRETS, "livekit_host_url": "http://10.0.0.5:7880"}),
    "mail defaults": ({}, {"session_secret": "s", "admin_emails": "a@example.com", "mail_token": "t"}),
}


@pytest.mark.parametrize("name", VARIANTS)
def test_env_parity(tmp_path: Path, name: str) -> None:
    overrides, secrets = VARIANTS[name]
    cfg = make(tmp_path, **overrides)
    ours = render_env(cfg, SecretValues(SecretRef("secrets/prod/recorder.yml"), secrets)).reveal().decode()

    assert ours == render_ansible("recorder.env.j2", role_vars(cfg, secrets))


@pytest.mark.parametrize("overrides", [{}, {"systemd_nofile": 4096, "port": 10099}])
def test_unit_parity(tmp_path: Path, overrides: dict[str, Any]) -> None:
    cfg = make(tmp_path, **overrides)

    ours = render(TEMPLATE_PACKAGE, "recorder.service.j2", cfg=cfg)
    assert ours == render_ansible("recorder.service.j2", role_vars(cfg, {}))


@pytest.mark.parametrize(
    "overrides", [{}, {"traefik_cert_resolver": "letsencrypt", "traefik_entrypoints": ("web-secure", "alt")}]
)
def test_route_parity(tmp_path: Path, overrides: dict[str, Any]) -> None:
    cfg = make(tmp_path, **overrides)

    ours = render_route(cfg, traefik_config(cfg))
    assert ours == render_ansible("recorder-traefik.yml.j2", role_vars(cfg, {}))
