"""delve files are byte-identical to the delve_deploy role's output.

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
from ops_deploy.services.delve import DelveConfig
from ops_deploy.services.delve.deploy import TEMPLATE_PACKAGE, render_env, render_route, traefik_config

VENDORED = Path(__file__).parent / "parity" / "ansible"
REF = SecretRef("secrets/prod/delve.yml")


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
    return env.get_template(f"delve_deploy__{template}").render(**variables)


def flag(value: bool | None) -> Any:
    return "" if value is None else value


def optional(value: object | None) -> Any:
    """The role's empty string for a value left to Delve's default."""

    return "" if value is None else value


def role_vars(cfg: DelveConfig, secrets: SecretValues) -> dict[str, Any]:
    return {
        "delve_user": cfg.user,
        "delve_group": cfg.group,
        "delve_service_name": cfg.service_name,
        "delve_bin_path": str(cfg.bin_path),
        "delve_data_dir": str(cfg.data_dir),
        "delve_env_path": str(cfg.env_path),
        "delve_listen_address": cfg.listen_address,
        "delve_port": cfg.port,
        "delve_public_url": cfg.public_url,
        "delve_traefik_host": cfg.traefik_host,
        "delve_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "delve_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "delve_session_secret": secrets["session_secret"],
        "delve_dogfood_token": secrets.get("dogfood_token", ""),
        "delve_admin_emails": cfg.admin_emails,
        "delve_apple_client_id": cfg.apple_client_id,
        "delve_apple_server_notifications": flag(cfg.apple_server_notifications),
        "delve_profile_legacy_reregister": flag(cfg.profile_legacy_reregister),
        "delve_apple_signin_legacy_no_nonce": flag(cfg.apple_signin_legacy_no_nonce),
        "delve_storekit_root_certs_path": str(cfg.storekit_root_certs_path or ""),
        "delve_storekit_bundle_id": cfg.storekit_bundle_id,
        "delve_storekit_product_ids": cfg.storekit_product_ids,
        "delve_env": cfg.env,
        "delve_discovery_collector_service_name": cfg.collector_service_name,
        "delve_discovery_collector_calendar": cfg.discovery_collector_calendar,
        "delve_discovery_collector_randomized_delay_sec": cfg.discovery_collector_randomized_delay_sec,
        "delve_discovery_collector_concurrency": cfg.discovery_collector_concurrency,
        "delve_discovery_poll_interval_seconds": cfg.discovery_poll_interval_seconds,
        "delve_discovery_poll_jitter_seconds": cfg.discovery_poll_jitter_seconds,
        "delve_discovery_episode_ttl_seconds": cfg.discovery_episode_ttl_seconds,
        "delve_discovery_max_items_per_feed": cfg.discovery_max_items_per_feed,
        "delve_discovery_max_sources_per_run": cfg.discovery_max_sources_per_run,
        "delve_systemd_nofile": cfg.systemd_nofile,
        "delve_smart_skip_analysis": cfg.smart_skip_analysis,
        "delve_smart_skip_analysis_profile_path": str(cfg.profile_path),
        "delve_analysis_media_dir": str(optional(cfg.analysis_media_dir)),
        "delve_analysis_media_disk_cap_bytes": optional(cfg.analysis_media_disk_cap_bytes),
        "delve_ffprobe_path": str(optional(cfg.ffprobe_path)),
        "delve_ffmpeg_path": str(optional(cfg.ffmpeg_path)),
        "delve_voxhelm_url": cfg.voxhelm_url,
        "delve_voxhelm_token_path": str(cfg.voxhelm_token_file),
        "delve_voxhelm_timeout_seconds": optional(cfg.voxhelm_timeout_seconds),
        "delve_voxhelm_upload_timeout_seconds": optional(cfg.voxhelm_upload_timeout_seconds),
        "delve_voxhelm_poll_seconds": optional(cfg.voxhelm_poll_seconds),
        "delve_detector_url": cfg.detector_url,
        "delve_detector_api_key_path": str(cfg.detector_api_key_file),
        "delve_detector_timeout_seconds": optional(cfg.detector_timeout_seconds),
    }


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
    # ops-control's production analysis settings (the role defaults otherwise).
    "analysis": {
        "smart_skip_analysis": True,
        "analysis_media_dir": "/var/lib/delve-smart-skip-media",
        "analysis_media_disk_cap_bytes": 20000000000,
        "ffprobe_path": "/usr/bin/ffprobe",
        "ffmpeg_path": "/usr/bin/ffmpeg",
        "voxhelm_url": "http://studio.example.ts.net:8787",
        "detector_url": "http://studio.example.ts.net:8177",
    },
    # Switched on with Delve's defaults: media inside the data dir, no stages.
    "analysis-minimal": {"smart_skip_analysis": True},
    # Analysis settings without the switch render nothing.
    "analysis-off": {
        "analysis_media_dir": "/var/lib/delve-smart-skip-media",
        "voxhelm_url": "http://studio.example.ts.net:8787",
        "detector_url": "http://studio.example.ts.net:8177",
        "voxhelm_poll_seconds": 15,
    },
}
SECRETS: dict[str, dict[str, str]] = {
    "defaults": {"session_secret": "s" * 16},
    "playbook": {"session_secret": "fixture-session-secret-0123", "dogfood_token": "fixture-dogfood"},
    "everything": {"session_secret": "x$y`z(parens)&#'-0123456789", "dogfood_token": "t"},
    "analysis": {"session_secret": "s" * 16, "voxhelm_token": "v" * 64, "detector_api_key": "d" * 64},
    "analysis-minimal": {"session_secret": "s" * 16},
    "analysis-off": {"session_secret": "s" * 16},
}


@pytest.fixture(params=sorted(VARIANTS))
def case(request: pytest.FixtureRequest, tmp_path: Path) -> tuple[DelveConfig, SecretValues]:
    binary = tmp_path / "delved"
    binary.write_bytes(b"\x7fELF")
    profile = tmp_path / "profile.json"
    profile.write_text('{"taxonomy": "server-taxonomy-v1"}\n')
    variant = dict(VARIANTS[request.param])
    if variant.get("smart_skip_analysis"):
        variant["smart_skip_analysis_profile_src"] = profile
    cfg = DelveConfig(binary_path=binary, secrets=REF, **variant)
    return cfg, SecretValues(REF, SECRETS[request.param])


@pytest.mark.parametrize(
    "template",
    ["delve.service.j2", "delve-discovery-collect.service.j2", "delve-discovery-collect.timer.j2"],
)
def test_units(case: tuple[DelveConfig, SecretValues], template: str) -> None:
    cfg, secrets = case
    assert render(TEMPLATE_PACKAGE, template, cfg=cfg) == render_ansible(template, role_vars(cfg, secrets))


def test_env_file(case: tuple[DelveConfig, SecretValues]) -> None:
    cfg, secrets = case
    expected = render_ansible("delve.env.j2", role_vars(cfg, secrets))
    assert render_env(cfg, secrets).reveal().decode() == expected


def test_traefik_route(case: tuple[DelveConfig, SecretValues]) -> None:
    cfg, secrets = case
    expected = render_ansible("delve-traefik.yml.j2", role_vars(cfg, secrets))
    assert render_route(cfg, traefik_config(cfg), None) == expected
