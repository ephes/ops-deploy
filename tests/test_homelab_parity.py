"""homelab files are byte-identical to the homelab_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``;
last checked against ops-library main 540ede2b, 2.56.0) and rendered here the
way Ansible's ``template`` module does, with the role's variables derived from
``homelab_shared`` the way its defaults derive them. Identical bytes mean
Ansible and ops-deploy take turns on a host without rewriting the ``.env``,
the unit or the route, and so without restarting homelab.

With ``OPS_LIBRARY_PATH`` set to an ops-library checkout, the config defaults
and the role's source sync inputs are compared with the role itself.
"""

import os
from pathlib import Path, PurePosixPath
from typing import Any

import jinja2
import pytest
import yaml

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.homelab import HomelabConfig
from ops_deploy.services.homelab.deploy import (
    REQUIRED_SOURCE_PATHS,
    SOURCE_EXCLUDES,
    SOURCE_FILES,
    render_env,
    render_route,
    render_unit,
    traefik_config,
)
from tests.homelab_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGE_TEMPLATES = Path(__file__).parents[1] / "src" / "ops_deploy" / "services" / "homelab" / "templates"
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
SECRET_KEY = "homelab-parity-key_with-symbols!@#%^*=+-0123456789"


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["dirname"] = os.path.dirname
    return env.get_template(f"homelab_deploy__{template}").render(**variables)


def ansible_vars(cfg: HomelabConfig, user: str, auth_hash: str) -> dict[str, Any]:
    """The role's variables as ``homelab_shared/defaults/main.yml`` derives them from the site path."""

    site = str(cfg.site_path)
    return {
        "homelab_user": cfg.user,
        "homelab_group": cfg.group,
        "homelab_site_path": site,
        "homelab_cache_dir": f"{site}/cache",
        "homelab_database_path": f"{site}/db.sqlite3",
        "homelab_static_root": f"{site}/staticfiles",
        "homelab_media_root": f"{site}/media",
        "homelab_app_host": cfg.app_host,
        "homelab_app_port": cfg.app_port,
        "homelab_workers": cfg.workers,
        "homelab_django_settings_module": cfg.django_settings_module,
        "homelab_django_allowed_hosts": cfg.django_allowed_hosts,
        "homelab_django_admin_url": cfg.django_admin_url,
        "homelab_django_debug": cfg.django_debug,
        "homelab_secret_key": SECRET_KEY,
        "homelab_uv_path": str(cfg.uv_path),
        "homelab_traefik_host": cfg.traefik_host,
        "homelab_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "homelab_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "homelab_basic_auth_enabled": True,
        "homelab_basic_auth_user": user,
        "homelab_basic_auth_password_hash": auth_hash,
    }


CONFIGS: list[dict[str, Any]] = [
    {},
    {"traefik_host": "home.example.org", "django_allowed_hosts": "127.0.0.1,home.example.org"},
    {"django_debug": True, "workers": 2, "app_port": 10100, "django_admin_url": "hidden/"},
    {"user": "dash", "service_name": "dash", "group": "web", "home": "/srv/dash", "site_path": "/srv/dash/app"},
    {"traefik_cert_resolver": "letsencrypt", "internal_ip_ranges": ("10.0.0.0/8", "fd00:1234:5678::/64")},
    {"uv_path": "/opt/uv/bin/uv", "django_settings_module": "config.settings.local"},
]


def make(source: Path, **overrides: Any) -> tuple[HomelabConfig, SecretValues]:
    cfg = HomelabConfig(source_path=source, secrets=SecretRef("secrets/prod/homelab.yml"), **overrides)
    assert cfg.secrets is not None
    values = {"django_secret_key": SECRET_KEY, "basic_auth_password": "fixture-password", "basic_auth_user": "ops"}
    return cfg, SecretValues(cfg.secrets, values)


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.mark.parametrize("name", ["env.j2", "systemd.service.j2", "traefik.yml.j2"])
def test_shipped_templates_are_the_vendored_role_templates(name: str) -> None:
    assert (PACKAGE_TEMPLATES / name).read_bytes() == (VENDORED / f"homelab_deploy__{name}").read_bytes()


@pytest.mark.parametrize("overrides", CONFIGS)
def test_env_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    ours = render_env(cfg, secrets).reveal().decode()

    assert ours == render_ansible("env.j2", ansible_vars(cfg, "ops", ""))
    assert f"DJANGO_SECRET_KEY={SECRET_KEY}" in ours.splitlines()


@pytest.mark.parametrize("overrides", CONFIGS)
def test_unit_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, _ = make(source, **overrides)

    assert render_unit(cfg) == render_ansible("systemd.service.j2", ansible_vars(cfg, "ops", ""))


@pytest.mark.parametrize("overrides", CONFIGS)
def test_route_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)
    auth_hash = hash_password("fixture-password")

    ours = render_route(cfg, traefik_config(cfg, secrets), auth_hash)

    assert ours == render_ansible("traefik.yml.j2", ansible_vars(cfg, "ops", auth_hash))
    route = yaml.safe_load(ours)
    assert route["http"]["middlewares"]["homelab-auth"]["basicAuth"]["users"] == [f"ops:{auth_hash}"]


def test_route_path_is_the_roles_config_path(source: Path) -> None:
    cfg, secrets = make(source)

    assert traefik_config(cfg, secrets).path == PurePosixPath("/etc/traefik/dynamic/homelab.yml")


# -- against the role itself (OPS_LIBRARY_PATH) ------------------------------------------


def role_defaults() -> dict[str, Any]:
    """``homelab_shared/defaults/main.yml`` with its ``{{ ... }}`` references resolved."""

    assert OPS_LIBRARY is not None
    raw = yaml.safe_load(Path(OPS_LIBRARY, "roles", "homelab_shared", "defaults", "main.yml").read_text())
    env = jinja2.Environment(undefined=jinja2.ChainableUndefined)
    resolved = dict(raw)
    for _ in range(5):
        for key, value in raw.items():
            if isinstance(value, str) and "{{" in value and "lookup(" not in value:
                resolved[key] = env.from_string(value).render(**resolved)
    return resolved


@needs_ops_library
def test_config_defaults_are_the_roles(source: Path) -> None:
    defaults = role_defaults()
    cfg, secrets = make(source)
    route = traefik_config(cfg, secrets)

    ours = {
        "homelab_user": cfg.user,
        "homelab_group": cfg.group,
        "homelab_home": str(cfg.home),
        "homelab_site_path": str(cfg.site_path),
        "homelab_venv_path": str(cfg.venv_path),
        "homelab_cache_dir": str(cfg.cache_dir),
        "homelab_database_path": str(cfg.db_path),
        "homelab_env_file": str(cfg.env_path),
        "homelab_static_root": str(cfg.static_root),
        "homelab_media_root": str(cfg.media_root),
        "homelab_media_subdirs": list(cfg.media_subdirs),
        "homelab_app_port": cfg.app_port,
        "homelab_app_host": cfg.app_host,
        "homelab_workers": cfg.workers,
        "homelab_django_settings_module": cfg.django_settings_module,
        "homelab_django_allowed_hosts": cfg.django_allowed_hosts,
        "homelab_django_admin_url": cfg.django_admin_url,
        "homelab_django_debug": cfg.django_debug,
        "homelab_uv_path": str(cfg.uv_path),
        "homelab_python_version": cfg.python_version,
        "homelab_service_name": cfg.service_name,
        "homelab_systemd_unit_path": f"/etc/systemd/system/{cfg.service_name}.service",
        "homelab_traefik_host": cfg.traefik_host,
        "homelab_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "homelab_traefik_config_path": str(route.path),
        "homelab_basic_auth_user": cfg.basic_auth_user,
        "homelab_internal_ip_ranges": list(cfg.internal_ip_ranges),
        # Not configurable here: the playbook relies on these role defaults.
        "homelab_use_uv": True,
        "homelab_service_restart_on_change": True,
        "homelab_traefik_enabled": True,
        "homelab_basic_auth_enabled": True,
    }

    assert {key: defaults[key] for key in ours} == ours


@needs_ops_library
def test_source_sync_inputs_are_the_roles() -> None:
    assert OPS_LIBRARY is not None
    tasks = yaml.safe_load(Path(OPS_LIBRARY, "roles", "homelab_deploy", "tasks", "source.yml").read_text())
    by_name = {task["name"]: task for task in tasks}

    assert tuple(by_name["Validate required source paths exist"]["loop"]) == REQUIRED_SOURCE_PATHS
    src = by_name["Sync Django source code to target"]["ansible.posix.synchronize"]
    assert src["delete"] is False
    assert tuple(option.removeprefix("--exclude=") for option in src["rsync_opts"]) == SOURCE_EXCLUDES
    media = by_name["Sync media files if they exist"]["ansible.posix.synchronize"]
    assert media["delete"] is False
    assert media["rsync_opts"] == ["--exclude=.gitkeep"]
    copies = {Path(task["copy"]["dest"]).name: task["copy"]["mode"] for task in tasks if "copy" in task}
    assert copies == dict(SOURCE_FILES)
