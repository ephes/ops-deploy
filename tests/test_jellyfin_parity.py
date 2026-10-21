"""jellyfin's route is byte-identical to the jellyfin_deploy role's, and its inputs are the role's.

The role template is vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``;
last checked against ops-library main 540ede2b, 2.56.0) and rendered here the
way Ansible's ``template`` module does. Identical bytes mean Ansible and
ops-deploy take turns on a host without rewriting the route.

With ``OPS_LIBRARY_PATH`` set to an ops-library checkout, the config defaults,
the repository line, the key URL, the ffmpeg pick and the task layout are
compared with the role itself.
"""

import os
import re
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.helpers import BasicAuth
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.jellyfin import JellyfinConfig
from ops_deploy.services.jellyfin.deploy import (
    REPO_ARCH,
    REPO_ARCH_DEFAULT,
    REPO_FAMILY_DEFAULT,
    pick_ffmpeg,
    render_route,
    repository_line,
    traefik_config,
)

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGE_TEMPLATES = Path(__file__).parents[1] / "src" / "ops_deploy" / "services" / "jellyfin" / "templates"
TEMPLATE = "jellyfin-traefik.yml.j2"
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
REPO = {"repo_distro": "ubuntu", "repo_release": "noble", "repo_arch": "amd64"}


def ansible_bool(value: Any) -> bool:
    """Ansible's ``bool`` filter."""

    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("yes", "on", "1", "true", "y", "t")


def render_ansible(template: str, variables: dict[str, Any], *, loader: jinja2.BaseLoader | None = None) -> str:
    env = jinja2.Environment(
        loader=loader or jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = ansible_bool
    return env.get_template(template).render(**variables)


def ansible_vars(cfg: JellyfinConfig, user: str, auth_hash: str) -> dict[str, Any]:
    return {
        "jellyfin_basic_auth_enabled": cfg.basic_auth_enabled,
        "jellyfin_traefik_host": cfg.traefik_host,
        "jellyfin_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "jellyfin_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "jellyfin_traefik_middlewares": list(cfg.traefik_middlewares),
        "jellyfin_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "jellyfin_basic_auth_user": user,
        "jellyfin_basic_auth_password_hash": auth_hash,
        "jellyfin_basic_auth_remove_header": cfg.basic_auth_remove_header,
        "jellyfin_http_port": cfg.http_port,
    }


CONFIGS: list[dict[str, Any]] = [
    {},
    {
        "traefik_host": "media.example.org",
        "internal_ip_ranges": ("192.168.0.0/16", "100.64.0.0/10", "fd7a:115c:a1e0::/48", "fd50:3e45:c454::/64"),
    },
    {"traefik_cert_resolver": "letsencrypt", "traefik_entrypoints": ("websecure", "web-alt")},
    {"traefik_middlewares": ("crowdsec@file", "ratelimit"), "http_port": 18096},
    {"basic_auth_remove_header": False},
    {"basic_auth_enabled": False},
    {"basic_auth_enabled": False, "traefik_middlewares": ("extra",), "traefik_cert_resolver": "le"},
]


@pytest.mark.parametrize("name", [TEMPLATE])
def test_shipped_template_is_the_vendored_role_template(name: str) -> None:
    assert (PACKAGE_TEMPLATES / name).read_bytes() == (VENDORED / f"jellyfin_deploy__{name}").read_bytes()


@pytest.mark.parametrize("overrides", CONFIGS)
def test_route_matches_role(overrides: dict[str, Any]) -> None:
    cfg = JellyfinConfig(**{**REPO, **overrides})
    auth = BasicAuth(user="ops", password=SecretStr("fixture-password")) if cfg.basic_auth_enabled else None
    auth_hash = hash_password("fixture-password") if auth else None

    ours = render_route(cfg, traefik_config(cfg, auth), auth_hash)

    expected = render_ansible(f"jellyfin_deploy__{TEMPLATE}", ansible_vars(cfg, "ops", auth_hash or ""))
    assert ours == expected
    route = yaml.safe_load(ours)
    if auth is not None:
        assert route["http"]["middlewares"]["jellyfin-auth"]["basicAuth"]["users"] == [f"ops:{auth_hash}"]
        assert (
            route["http"]["middlewares"]["jellyfin-auth"]["basicAuth"]["removeHeader"] is cfg.basic_auth_remove_header
        )
    else:
        assert "jellyfin-auth" not in route["http"]["middlewares"]


def test_route_path_is_the_roles_config_path() -> None:
    cfg = JellyfinConfig(**REPO)

    assert str(traefik_config(cfg, None).path) == "/etc/traefik/dynamic/jellyfin.yml"


# -- against the role itself (OPS_LIBRARY_PATH) ------------------------------------------


def role_file(*parts: str) -> Path:
    assert OPS_LIBRARY is not None
    return Path(OPS_LIBRARY, "roles", *parts)


def role_defaults() -> dict[str, Any]:
    """Both roles' defaults with the plain ``{{ ... }}`` references resolved (not the fact-based ones)."""

    raw = {
        **yaml.safe_load(role_file("jellyfin_shared", "defaults", "main.yml").read_text()),
        **yaml.safe_load(role_file("jellyfin_deploy", "defaults", "main.yml").read_text()),
    }
    env = jinja2.Environment(undefined=jinja2.ChainableUndefined)
    resolved = dict(raw)
    for _ in range(5):
        for key, value in raw.items():
            if isinstance(value, str) and "{{" in value and "ansible_" not in value and "lookup(" not in value:
                resolved[key] = env.from_string(value).render(**resolved)
    return resolved


@needs_ops_library
def test_config_defaults_are_the_roles() -> None:
    defaults = role_defaults()
    cfg = JellyfinConfig(**REPO)

    ours = {
        "jellyfin_user": cfg.user,
        "jellyfin_group": cfg.group,
        "jellyfin_service_name": "jellyfin",
        "jellyfin_service_enabled": cfg.service_enabled,
        "jellyfin_service_state": "started",
        "jellyfin_data_dir": str(cfg.data_dir),
        "jellyfin_config_dir": str(cfg.config_dir),
        "jellyfin_log_dir": str(cfg.log_dir),
        "jellyfin_media_directories": [str(p) for p in cfg.media_directories],
        "jellyfin_media_dir_owner": cfg.media_dir_owner,
        "jellyfin_media_dir_group": cfg.media_dir_group,
        "jellyfin_media_dir_mode": cfg.media_dir_mode,
        "jellyfin_create_media_dirs": cfg.create_media_dirs,
        "jellyfin_http_port": cfg.http_port,
        "jellyfin_repo_base": cfg.repo_base,
        "jellyfin_repo_component": cfg.repo_component,
        "jellyfin_repo_list_file": str(cfg.repo_list_file),
        "jellyfin_repo_keyring": str(cfg.repo_keyring),
        "jellyfin_repo_arch_map": REPO_ARCH,
        "jellyfin_ffmpeg_candidates": list(cfg.ffmpeg_candidates),
        "jellyfin_packages_base": list(cfg.packages_base),
        "jellyfin_traefik_enabled": cfg.traefik_enabled,
        "jellyfin_traefik_host": cfg.traefik_host,
        "jellyfin_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "jellyfin_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "jellyfin_traefik_config_path": str(traefik_config(cfg, None).path),
        "jellyfin_traefik_middlewares": list(cfg.traefik_middlewares),
        "jellyfin_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "jellyfin_basic_auth_enabled": cfg.basic_auth_enabled,
        "jellyfin_basic_auth_remove_header": cfg.basic_auth_remove_header,
        "jellyfin_configure_repo": cfg.configure_repo,
        "jellyfin_healthcheck_enabled": cfg.healthcheck_enabled,
        "jellyfin_healthcheck_url": cfg.health_url,
        "jellyfin_healthcheck_timeout": cfg.healthcheck_timeout,
        "jellyfin_healthcheck_retries": cfg.healthcheck_retries,
        "jellyfin_healthcheck_expected_statuses": list(cfg.healthcheck_expected_statuses),
    }

    assert {key: defaults[key] for key in ours} == ours
    assert {k.lower(): v for k, v in defaults["jellyfin_repo_family_map"].items()} == {
        "debian": "debian",
        "ubuntu": "ubuntu",
    }
    assert "default('debian')" in defaults["jellyfin_repo_distro"]
    assert REPO_FAMILY_DEFAULT == "debian"
    assert "default('amd64')" in defaults["jellyfin_repo_arch"].rsplit("]", 1)[1]
    assert REPO_ARCH_DEFAULT == "amd64"
    assert defaults["jellyfin_repo_release"] == "{{ ansible_facts.distribution_release | default('bookworm') }}"


@needs_ops_library
@pytest.mark.parametrize("repo", [REPO, {"repo_distro": "debian", "repo_release": "trixie", "repo_arch": "arm64"}])
def test_repository_line_and_key_url_are_the_roles(repo: dict[str, str]) -> None:
    cfg = JellyfinConfig(**repo)
    tasks = {
        task["name"]: task for task in yaml.safe_load(role_file("jellyfin_deploy", "tasks", "repo.yml").read_text())
    }
    values = {f"jellyfin_{key}": value for key, value in repo.items()} | {
        "jellyfin_repo_base": cfg.repo_base,
        "jellyfin_repo_component": cfg.repo_component,
        "jellyfin_repo_keyring": str(cfg.repo_keyring),
    }
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)

    repository = tasks["Configure Jellyfin apt repository"]["ansible.builtin.apt_repository"]
    assert env.from_string(repository["repo"]).render(**values) + "\n" == repository_line(cfg)
    # apt_repository's ``filename`` (without .list) names the list file.
    assert "jellyfin_repo_list_file | basename" in repository["filename"]
    assert repository["update_cache"] is True
    shared = yaml.safe_load(role_file("jellyfin_shared", "defaults", "main.yml").read_text())
    key_url = shared["jellyfin_repo_key_url"]
    assert env.from_string(key_url).render(**values) == cfg.key_url
    convert = tasks["Convert Jellyfin repository key to keyring"]["ansible.builtin.command"]["argv"]
    assert convert[:4] == ["gpg", "--batch", "--yes", "--dearmor"]
    mode = tasks["Set Jellyfin keyring permissions"]["ansible.builtin.file"]
    assert (mode["owner"], mode["group"], mode["mode"]) == ("root", "root", "0644")


@needs_ops_library
def test_ffmpeg_pick_is_the_roles() -> None:
    tasks = {
        task["name"]: task for task in yaml.safe_load(role_file("jellyfin_deploy", "tasks", "packages.yml").read_text())
    }
    pick = tasks["Select first available Jellyfin ffmpeg package"]["ansible.builtin.set_fact"][
        "jellyfin_ffmpeg_package"
    ]
    # The regex as written (plain Jinja2 turns a doubled backslash in a string literal into one). ansible-core 2.19
    # and later keep both backslashes in this folded scalar, so the role's pick never
    # matches there; the deploy ports the pick as written (see docs/services/jellyfin.md).
    role_regex = re.search(r"'search', '(.+?)'\)", pick)
    assert role_regex is not None
    assert role_regex.group(1).replace("\\\\", "\\") == r"Candidate:\s+(?!\(none\))"
    cfg = JellyfinConfig(**REPO)
    policies = {
        "jellyfin-ffmpeg6": "jellyfin-ffmpeg6:\n  Installed: (none)\n  Candidate: (none)",
        "jellyfin-ffmpeg5": "jellyfin-ffmpeg5:\n  Installed: (none)\n  Candidate: 5.1.4-3",
        "jellyfin-ffmpeg": "jellyfin-ffmpeg:\n  Installed: (none)\n  Candidate: 4.4.1-4",
    }
    assert pick_ffmpeg(cfg, policies) == "jellyfin-ffmpeg5"
    assert pick_ffmpeg(cfg, {}) is None
    install = tasks["Install Jellyfin packages"]["ansible.builtin.apt"]
    assert (install["state"], install["update_cache"]) == ("present", True)


@needs_ops_library
def test_task_layout_is_the_one_ported() -> None:
    main = yaml.safe_load(role_file("jellyfin_deploy", "tasks", "main.yml").read_text())
    assert [task["ansible.builtin.import_tasks"] for task in main] == [
        "validate.yml",
        "repo.yml",
        "packages.yml",
        "directories.yml",
        "traefik.yml",
        "service.yml",
        "health.yml",
    ]
    directories = yaml.safe_load(role_file("jellyfin_deploy", "tasks", "directories.yml").read_text())
    modes = [task["ansible.builtin.file"]["mode"] for task in directories]
    assert modes == ["0750", "0750", "0750", "{{ jellyfin_media_dir_mode }}"]
    service = yaml.safe_load(role_file("jellyfin_deploy", "tasks", "service.yml").read_text())[0]
    assert service["ansible.builtin.systemd"]["state"] == "{{ jellyfin_service_state }}"
    # The restart handler exists but no task notifies it: a deploy never restarts Jellyfin.
    tasks_dir = role_file("jellyfin_deploy", "tasks")
    notified = {
        task.get("notify") for path in tasks_dir.glob("*.yml") for task in yaml.safe_load(path.read_text()) or []
    }
    assert notified == {None, "reload traefik"}
    health = yaml.safe_load(role_file("jellyfin_deploy", "tasks", "health.yml").read_text())
    assert health[1]["delay"] == 3
