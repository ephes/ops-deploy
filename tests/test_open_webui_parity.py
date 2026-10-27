"""open_webui's files are byte-identical to the open_webui_venv_deploy role's; defaults are the role's.

The three role templates are vendored under ``tests/parity/ansible`` (checked
against ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``;
last checked against ops-library main cf3a0c74, 2.75.2) and rendered here the
way Ansible's ``template`` module does. With ``OPS_LIBRARY_PATH`` set, the
config defaults of ``open_webui`` and ``encrypted_volume`` are compared with
the roles' ``defaults/main.yml``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.helpers import BasicAuth
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.infra import EncryptedVolumeConfig
from ops_deploy.services.open_webui import OpenWebUIConfig
from ops_deploy.services.open_webui.deploy import (
    environment,
    render_env,
    render_route,
    render_unit,
    role_vars,
    route_vars,
    traefik_config,
)

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGE_TEMPLATES = Path(__file__).parents[1] / "src" / "ops_deploy" / "services" / "open_webui" / "templates"
TEMPLATES = ("open-webui-traefik.yml.j2", "open-webui.env.j2", "open-webui.service.j2")
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
AUTH = BasicAuth(user="admin", password=SecretStr("parity-password"))


def ansible_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("yes", "on", "1", "true", "y", "t")


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = ansible_bool
    # Ansible's dict2items and string filters.
    env.filters["dict2items"] = lambda mapping: [{"key": k, "value": v} for k, v in mapping.items()]
    return env.get_template(f"open_webui_venv_deploy__{template}").render(**variables)


CONFIGS: list[dict[str, Any]] = [
    {"traefik_host": "open-webui.example.com"},
    {
        "traefik_host": "chat.example.org",
        "ollama_base_url": "http://ollama.example.test:11434",
        "data_dir": "/srv/data/open-webui/data",
        "extra_env": {"OFFLINE_MODE": "true", "ENABLE_VERSION_UPDATE_CHECK": "false"},
        "internal_ip_ranges": ("192.168.0.0/16", "fd7a:115c:a1e0::/48"),
        "traefik_entrypoints": ("web-secure", "websecure2"),
        "traefik_middlewares": ("extra@file",),
        "traefik_cert_resolver": "letsencrypt",
        "basic_auth_remove_header": False,
    },
    {
        "traefik_host": "chat.example.org",
        "basic_auth_enabled": False,
        "webui_auth_enabled": False,
        "openai_api_base_url": "https://api.example.test/v1",
        "use_host_flag": False,
        "extra_args": ("--workers", "2"),
        "systemd_hardening": True,
        "systemd_restart": "always",
        "systemd_restart_sec": 9,
        "host_port": 3100,
        "extra_env": {"OLLAMA_BASE_URL": "http://override.example.test:11434"},
    },
]


@pytest.mark.parametrize("template", TEMPLATES)
def test_package_templates_are_the_vendored_role_templates(template: str) -> None:
    assert (PACKAGE_TEMPLATES / template).read_text() == (VENDORED / f"open_webui_venv_deploy__{template}").read_text()


@pytest.mark.parametrize("fields", CONFIGS)
def test_env_unit_and_route_match_the_role(fields: dict[str, Any]) -> None:
    cfg = OpenWebUIConfig(**fields)
    variables = role_vars(cfg)
    assert render_env(cfg) == render_ansible("open-webui.env.j2", variables)
    assert render_unit(cfg) == render_ansible("open-webui.service.j2", variables)
    auth = AUTH if cfg.basic_auth_enabled else None
    route = traefik_config(cfg, auth)
    auth_hash = hash_password("parity-password") if auth else None
    expected = render_ansible(
        "open-webui-traefik.yml.j2", route_vars(cfg, user=auth.user if auth else "", auth_hash=auth_hash or "")
    )
    text = render_route(cfg, route, auth_hash)
    assert text == expected
    yaml.safe_load(text)


def test_extra_env_overrides_in_place_like_combine() -> None:
    cfg = OpenWebUIConfig(
        traefik_host="x.example.com", extra_env={"OLLAMA_BASE_URL": "http://o.example.test", "Z": "1"}
    )
    assert list(environment(cfg)) == [
        "OLLAMA_BASE_URL",
        "WEBUI_SECRET_KEY",
        "WEBUI_AUTH",
        "OPENAI_API_KEY",
        "OPENAI_API_BASE_URL",
        "Z",
    ]
    text = render_env(cfg)
    assert "WEBUI_SECRET_KEY" not in text
    assert "OPENAI_API_KEY" not in text
    assert text.splitlines()[1] == "OLLAMA_BASE_URL=http://o.example.test"


def role_defaults(role: str) -> dict[str, Any]:
    assert OPS_LIBRARY is not None
    loaded: dict[str, Any] = yaml.safe_load(Path(OPS_LIBRARY, "roles", role, "defaults", "main.yml").read_text())
    return loaded


@needs_ops_library
def test_open_webui_defaults_are_the_roles() -> None:
    role = role_defaults("open_webui_venv_deploy")
    cfg = OpenWebUIConfig(traefik_host="x.example.com")
    same = [
        "service_name",
        "user",
        "group",
        "site_dir",
        "data_dir",
        "log_dir",
        "python_security_floor_enabled",
        "uv_install_dir",
        "bind_host",
        "host_port",
        "use_host_flag",
        "systemd_restart",
        "systemd_restart_sec",
        "systemd_hardening",
        "ollama_base_url",
        "webui_auth_enabled",
        "openai_api_base_url",
        "traefik_enabled",
        "traefik_cert_resolver",
        "basic_auth_enabled",
        "basic_auth_remove_header",
        "healthcheck_enabled",
        "healthcheck_host",
        "healthcheck_path",
        "healthcheck_status",
        "healthcheck_timeout",
        "healthcheck_retries",
        "manage_uv",
    ]
    for name in same:
        assert getattr(cfg, name) == role[f"open_webui_{name}"], name
    assert list(cfg.extra_args) == role["open_webui_extra_args"]
    assert cfg.extra_env == role["open_webui_extra_env"]
    assert list(cfg.traefik_entrypoints) == role["open_webui_traefik_entrypoints"]
    assert list(cfg.traefik_middlewares) == role["open_webui_traefik_middlewares"]
    assert list(cfg.internal_ip_ranges) == role["open_webui_internal_ip_ranges"]
    assert role["open_webui_systemd_enabled"] is True
    assert role["open_webui_traefik_config_path"] == "/etc/traefik/dynamic/open-webui.yml"
    # Templated paths, resolved the way the role resolves them.
    assert role["open_webui_home"] == "/home/{{ open_webui_user }}"
    assert cfg.home_dir == "/home/openwebui"
    assert role["open_webui_env_path"] == "{{ open_webui_site_dir }}/open-webui.env"
    assert role["open_webui_venv_path"] == "{{ open_webui_site_dir }}/.venv"
    assert (cfg.env_file, cfg.venv) == ("/opt/open-webui/open-webui.env", "/opt/open-webui/.venv")
    assert cfg.security_constraints == "/opt/open-webui/.python-security-constraints.txt"
    assert role["open_webui_python_security_constraints_path"] == (
        "{{ open_webui_site_dir }}/.python-security-constraints.txt"
    )
    # Pinned here; the role installs the latest of a prefix.
    assert role["open_webui_package_spec"] == "open-webui"
    assert cfg.python_version.startswith(role["open_webui_python_version"] + ".")


@needs_ops_library
def test_encrypted_volume_defaults_are_the_roles() -> None:
    role = role_defaults("encrypted_volume_prepare")
    cfg = EncryptedVolumeConfig(device="/dev/sda", expected_luks_uuid="e301d851-3454-4b1b-a3a2-5e71f18af8d7")
    for name in (
        "mapper_name",
        "mount_point",
        "fs_type",
        "mount_opts",
        "fstab_dump",
        "fstab_passno",
        "keyfile_owner",
        "keyfile_group",
        "keyfile_mode",
        "crypttab_options",
        "mount_owner",
        "mount_group",
        "mount_mode",
    ):
        assert getattr(cfg, name) == role[f"encrypted_volume_{name}"], name
    assert list(cfg.packages) == role["encrypted_volume_packages"]
    assert role["encrypted_volume_keyfile_path"] == "/root/.luks-key-{{ encrypted_volume_mapper_name }}"
    assert cfg.keyfile == "/root/.luks-key-cryptdata"
    # The safety defaults the deploy hard-codes.
    assert role["encrypted_volume_allow_format"] is False
    assert role["encrypted_volume_use_keyfile"] is True
    assert role["encrypted_volume_device_by_id"] == ""
