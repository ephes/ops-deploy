"""vaultwarden files are byte-identical to the vaultwarden_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``;
last checked against ops-library main 540ede2b, 2.56.0) and rendered here the
way Ansible's ``template`` module does. Identical bytes mean Ansible and
ops-deploy take turns on a host without rewriting the environment file, the
drop-in or the route, and so without restarting Vaultwarden.

With ``OPS_LIBRARY_PATH`` set to an ops-library checkout, the config defaults,
paths, owners, modes, packages and the config.json settings are compared with
the role itself.
"""

import json
import os
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.vaultwarden import VaultwardenConfig, render_dropin, render_env, render_route
from ops_deploy.services.vaultwarden.deploy import (
    CONFIG_JSON,
    DATA_DIR,
    DROPIN,
    DROPIN_DIR,
    ENV_PATH,
    KEYRING,
    KEYRING_DIR,
    LOG_DIR,
    PACKAGES,
    PREREQUISITES,
    ROUTE,
    SOURCES_LIST,
    SUPPORTED_RELEASES,
    UBUNTU_SUITE,
    smtp_settings,
    sources_line,
)

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGE_TEMPLATES = Path(__file__).parents[1] / "src" / "ops_deploy" / "services" / "vaultwarden" / "templates"
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
TEMPLATES = ("vaultwarden.env.j2", "vaultwarden-override.conf.j2", "traefik-vaultwarden.yml.j2")
SECRETS = {
    "admin_token": "$argon2id$v=19$m=65540,t=3,p=4$parity-salt$parity-hash",
    "smtp_username": "vault@example.com",
    "smtp_password": "parity smtp password with spaces & #",
}


def ansible_bool(value: Any) -> bool:
    # ansible.plugins.filter.core.to_bool for the values seen here.
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
    return env.get_template(f"vaultwarden_deploy__{template}").render(**variables)


def ansible_vars(cfg: VaultwardenConfig, secrets: dict[str, str]) -> dict[str, Any]:
    """The role's variables as a playbook sets them, ``vaultwarden_hostname`` as traefik.yml derives it."""

    variables: dict[str, Any] = {
        f"vaultwarden_{name}": getattr(cfg, name)
        for name in (
            "domain",
            "rocket_address",
            "rocket_port",
            "websocket_enabled",
            "signups_allowed",
            "invitations_allowed",
            "show_password_hint",
            "org_creation_users",
            "smtp_host",
            "smtp_port",
            "smtp_security",
            "smtp_from",
            "smtp_from_name",
            "smtp_auth_mechanism",
            "smtp_accept_invalid_certs",
            "smtp_accept_invalid_hostnames",
            "experimental_client_feature_flags",
            "sends_allowed",
            "emergency_access_allowed",
            "icon_service",
            "log_level",
            "traefik_entrypoint",
            "traefik_certresolver",
        )
    }
    if cfg.smtp_debug is not None:
        variables["vaultwarden_smtp_debug"] = cfg.smtp_debug
    host = cfg.domain.split("://", 1)[1].split("/", 1)[0]
    variables.update(
        vaultwarden_hostname=host,
        vaultwarden_admin_enabled=secrets.get("admin_enabled", "true") == "true",
        vaultwarden_admin_token=secrets.get("admin_token", ""),
        vaultwarden_smtp_username=secrets.get("smtp_username", ""),
        vaultwarden_smtp_password=secrets.get("smtp_password", ""),
    )
    return variables


# The playbook's role vars (ops-control) first, then variations.
PLAYBOOK: dict[str, Any] = {
    "domain": "https://vault.example.com",
    "smtp_host": "localhost",
    "smtp_port": 587,
    "smtp_security": "starttls",
    "smtp_from": "vault@example.com",
    "smtp_from_name": "Vaultwarden",
    "smtp_auth_mechanism": "Plain",
    "smtp_accept_invalid_certs": True,
    "smtp_accept_invalid_hostnames": True,
    "traefik_entrypoint": "web-secure",
}
CONFIGS: list[dict[str, Any]] = [
    PLAYBOOK,
    {"domain": "https://vault.example.org"},
    {**PLAYBOOK, "smtp_debug": True, "smtp_accept_invalid_certs": False, "traefik_certresolver": "letsencrypt"},
    {**PLAYBOOK, "smtp_debug": False, "experimental_client_feature_flags": "", "signups_allowed": True},
    {
        "domain": "http://vault.example.net/sub/path",
        "rocket_address": "0.0.0.0",
        "rocket_port": 8080,
        "websocket_enabled": False,
        "org_creation_users": "a@example.com,b@example.com",
        "icon_service": "duckduckgo",
        "log_level": "warn",
        "sends_allowed": False,
        "emergency_access_allowed": False,
        "show_password_hint": True,
        "invitations_allowed": False,
    },
]
SECRET_SETS: list[dict[str, str]] = [
    SECRETS,
    {**SECRETS, "admin_enabled": "false"},
    {**SECRETS, "smtp_username": "", "smtp_password": ""},
    {"admin_token": "plain-token", "admin_enabled": "true"},
]


def make(overrides: dict[str, Any], secrets: dict[str, str]) -> tuple[VaultwardenConfig, SecretValues]:
    cfg = VaultwardenConfig(secrets=SecretRef("secrets/prod/vaultwarden.yml"), **overrides)
    assert cfg.secrets is not None
    return cfg, SecretValues(cfg.secrets, secrets)


@pytest.mark.parametrize("name", TEMPLATES)
def test_shipped_templates_are_the_vendored_role_templates(name: str) -> None:
    assert (PACKAGE_TEMPLATES / name).read_bytes() == (VENDORED / f"vaultwarden_deploy__{name}").read_bytes()


@pytest.mark.parametrize("secrets", SECRET_SETS)
@pytest.mark.parametrize("overrides", CONFIGS)
def test_env_matches_role(overrides: dict[str, Any], secrets: dict[str, str]) -> None:
    cfg, values = make(overrides, secrets)

    ours = render_env(cfg, values).reveal().decode()

    assert ours == render_ansible("vaultwarden.env.j2", ansible_vars(cfg, secrets))


def test_env_of_the_playbook_settings() -> None:
    cfg, values = make(PLAYBOOK, SECRETS)
    lines = render_env(cfg, values).reveal().decode().splitlines()

    assert f"ADMIN_TOKEN={SECRETS['admin_token']}" in lines
    assert f"SMTP_PASSWORD={SECRETS['smtp_password']}" in lines
    assert "SMTP_AUTH_MECHANISM=Plain" in lines
    assert "SMTP_ACCEPT_INVALID_CERTS=true" in lines
    assert not any(line.startswith("SMTP_DEBUG") for line in lines)

    _, disabled = make(PLAYBOOK, {**SECRETS, "admin_enabled": "false"})
    text = render_env(cfg, disabled).reveal().decode()
    assert "# Admin panel disabled (vaultwarden_admin_enabled=False)\n" in text
    assert SECRETS["admin_token"] not in text


@pytest.mark.parametrize("overrides", CONFIGS)
def test_dropin_matches_role(overrides: dict[str, Any]) -> None:
    cfg, _ = make(overrides, SECRETS)

    assert render_dropin(cfg) == render_ansible("vaultwarden-override.conf.j2", ansible_vars(cfg, SECRETS))


@pytest.mark.parametrize("overrides", CONFIGS)
def test_route_matches_role(overrides: dict[str, Any]) -> None:
    cfg, _ = make(overrides, SECRETS)

    ours = render_route(cfg)

    assert ours == render_ansible("traefik-vaultwarden.yml.j2", ansible_vars(cfg, SECRETS))
    route = yaml.safe_load(ours)["http"]
    assert route["routers"]["vaultwarden"]["entryPoints"] == [cfg.traefik_entrypoint]
    url = route["services"]["vaultwarden"]["loadBalancer"]["servers"][0]["url"]
    assert url == f"http://{cfg.rocket_address}:{cfg.rocket_port}"


# -- against the role itself (OPS_LIBRARY_PATH) ------------------------------------------


def role_file(*parts: str) -> Any:
    assert OPS_LIBRARY is not None
    return yaml.safe_load(Path(OPS_LIBRARY, "roles", "vaultwarden_deploy", *parts).read_text())


def tasks(name: str) -> dict[str, dict[str, Any]]:
    """The role's task file ``name`` by task name (blocks flattened)."""

    found: dict[str, dict[str, Any]] = {}
    for task in role_file("tasks", name):
        found[task["name"]] = task
        for inner in task.get("block", ()):
            found[inner["name"]] = inner
    return found


@needs_ops_library
def test_config_defaults_are_the_roles() -> None:
    defaults = role_file("defaults", "main.yml")
    cfg = VaultwardenConfig(domain="https://vault.example.com")
    skipped = {
        # Not ported: package pins and the apt hold (the playbook sets none).
        "vaultwarden_package_version",
        "vaultwarden_web_vault_package_version",
        "vaultwarden_packages_hold",
        # The host's release, or its required value.
        "vaultwarden_debian_codename",
        "vaultwarden_domain",
        "vaultwarden_admin_token",
        # The secrets file's admin_enabled (default true), smtp_username, smtp_password.
        "vaultwarden_admin_enabled",
        "vaultwarden_smtp_username",
        "vaultwarden_smtp_password",
        # Always started and enabled; Molecule helpers.
        "vaultwarden_service_enabled",
        "vaultwarden_service_state",
        "vaultwarden_skip_install",
        "vaultwarden_skip_repo",
        "vaultwarden_skip_handlers",
    }
    ours = {key: getattr(cfg, key.removeprefix("vaultwarden_")) for key in defaults if key not in skipped}

    assert ours == {key: defaults[key] for key in ours}
    assert defaults["vaultwarden_admin_enabled"] is True
    assert (defaults["vaultwarden_service_enabled"], defaults["vaultwarden_service_state"]) == (True, "started")
    assert defaults["vaultwarden_packages_hold"] is None
    assert defaults["vaultwarden_package_version"] == defaults["vaultwarden_web_vault_package_version"] == ""


@needs_ops_library
def test_files_owners_and_modes_are_the_roles() -> None:
    configure = tasks("configure.yml")
    env = configure["configure | Deploy Vaultwarden environment configuration"]["ansible.builtin.template"]
    assert (env["dest"], env["owner"], env["group"], env["mode"]) == (str(ENV_PATH), "root", "vaultwarden", "0640")
    stat = configure["configure | Check if config.json exists (admin panel was used)"]["ansible.builtin.stat"]
    assert stat["path"] == str(CONFIG_JSON)
    copy = configure["configure | Update SMTP settings in config.json"]["ansible.builtin.copy"]
    assert (copy["dest"], copy["owner"], copy["group"], copy["mode"]) == (
        str(CONFIG_JSON),
        "vaultwarden",
        "vaultwarden",
        "0600",
    )
    assert copy["content"] == "{{ updated_config | to_nice_json }}"
    dropin_dir = configure["configure | Ensure systemd override directory exists"]["ansible.builtin.file"]
    assert (dropin_dir["path"], dropin_dir["mode"]) == (str(DROPIN_DIR), "0755")
    dropin = configure["configure | Deploy systemd override for security hardening"]["ansible.builtin.template"]
    assert (dropin["dest"], dropin["mode"]) == (str(DROPIN), "0644")

    packages = tasks("packages.yml")
    for path in (DATA_DIR, LOG_DIR):
        task = next(
            t["ansible.builtin.file"]
            for t in packages.values()
            if t.get("ansible.builtin.file", {}).get("path") == str(path)
        )
        assert (task["owner"], task["group"], task["mode"]) == ("vaultwarden", "vaultwarden", "0750")
    resolved = packages["packages | Resolve package specifications and pin state"]["ansible.builtin.set_fact"]
    assert tuple(resolved["vaultwarden_package_names"]) == PACKAGES

    route = tasks("traefik.yml")["traefik | Deploy Traefik dynamic configuration for Vaultwarden"]
    assert (route["ansible.builtin.template"]["dest"], route["ansible.builtin.template"]["mode"]) == (
        str(ROUTE),
        "0644",
    )


@needs_ops_library
def test_repository_is_the_roles() -> None:
    repository = tasks("repository.yml")
    assert tuple(repository["repository | Install apt prerequisites"]["ansible.builtin.apt"]["name"]) == PREREQUISITES
    keyrings = repository["repository | Create keyrings directory"]["ansible.builtin.file"]
    assert (keyrings["path"], keyrings["mode"]) == (str(KEYRING_DIR), "0755")
    key = repository["repository | Download Vaultwarden repository GPG key"]["ansible.builtin.get_url"]
    assert (key["dest"], key["mode"]) == (str(KEYRING), "0644")
    assert "force" not in key
    repo = repository["repository | Add Vaultwarden apt repository"]["ansible.builtin.apt_repository"]
    assert repo["filename"] == SOURCES_LIST.stem
    cfg = VaultwardenConfig(domain="https://vault.example.com")
    line = jinja2.Template(repo["repo"]).render(
        vaultwarden_apt_repo_url=cfg.apt_repo_url, vaultwarden_debian_codename="bookworm"
    )
    assert sources_line(cfg, "bookworm") == f"{line}\n"

    validate = tasks("validate.yml")
    codenames = validate["validate | Validate Debian codename is supported"]["ansible.builtin.assert"]["that"][0]
    assert codenames == f"vaultwarden_debian_codename in {list(SUPPORTED_RELEASES)}"
    mapping = validate["validate | Map Ubuntu release to Debian codename"]["ansible.builtin.set_fact"]
    assert "'bookworm' if ansible_distribution_release in ['jammy', 'noble']" in mapping["vaultwarden_debian_codename"]
    assert UBUNTU_SUITE == {"jammy": "bookworm", "noble": "bookworm"}


@needs_ops_library
def test_config_json_settings_are_the_roles() -> None:
    task = tasks("configure.yml")["configure | Update SMTP settings in config.json"]
    base = task["vars"]["smtp_base"]
    cfg = VaultwardenConfig(domain="https://vault.example.com", smtp_host="localhost", smtp_from="v@example.com")

    assert set(smtp_settings(cfg)) == set(base)
    assert "smtp_debug" in task["vars"]["smtp_optional"]
    assert "smtp_debug" not in smtp_settings(cfg)
    debug = VaultwardenConfig(
        domain="https://vault.example.com", smtp_host="h", smtp_from="v@example.com", smtp_debug=False
    )
    assert smtp_settings(debug)["smtp_debug"] is False
    # The JSON types the role's filters produce: int for the port, booleans for the flags.
    assert base["smtp_port"] == "{{ vaultwarden_smtp_port | int }}"
    assert all("| bool" in base[key] for key in ("smtp_accept_invalid_certs", "smtp_accept_invalid_hostnames"))
    assert json.dumps(smtp_settings(cfg)["smtp_port"]) == "587"
    when = tasks("configure.yml")["configure | Sync SMTP settings to config.json if it exists"]["when"]
    assert when == [
        "vaultwarden_config_json.stat.exists",
        "vaultwarden_smtp_host is defined",
        "vaultwarden_smtp_host | length > 0",
    ]


@needs_ops_library
def test_health_check_is_the_roles() -> None:
    uri = tasks("health.yml")["health | Wait for Vaultwarden to be ready"]
    assert (
        uri["ansible.builtin.uri"]["url"]
        == "http://{{ vaultwarden_rocket_address }}:{{ vaultwarden_rocket_port }}/alive"
    )
    assert (uri["retries"], uri["delay"]) == ("{{ (vaultwarden_healthcheck_timeout / 5) | int }}", 5)
