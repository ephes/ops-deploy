"""vaultwarden: the Bitwarden-compatible password manager from its vendor's .deb packages.

Port of the ``vaultwarden_deploy`` Ansible role (deploy only) and of the port
preflight in ops-control's ``deploy-vaultwarden.yml``. The packages come from
the vendor's apt repository (signing key and ``vaultwarden.list`` as the role
writes them) and own the binary, the unit and the ``vaultwarden`` user; this
deploy writes ``/etc/vaultwarden.env``, the systemd drop-in and the Traefik
route byte-identical to the role's (``tests/test_vaultwarden_parity.py``), so
Ansible and ops-deploy can take turns on a host without rewriting a file or
restarting anything.

When ``data/config.json`` exists (the admin panel saved settings, which then
override the environment file), the role's SMTP settings are merged into it on
the host by ``files/smtp_config_sync.py``: every other key is kept, the file
never leaves the host, and it is rewritten only when a setting differs in
value or JSON type, not when the bytes merely differ from Ansible's
``to_nice_json`` layout. A rewrite uses that layout.

Unlike the role, Traefik is never restarted (its file provider watches the
directory), systemd is reloaded only when the drop-in changed, and Vaultwarden
restarts only when a package was installed or a file it reads changed. Package
version pins and the apt hold are not ported: the playbook pins nothing and
leaves the hold unmanaged, so this deploy never touches either.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from collections.abc import Mapping
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar

import jinja2
import yaml
from pydantic import Field, field_validator, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import apt, files, server
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import require_linux
from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import http_check, mark_read_only, service_rollout
from ops_deploy.helpers.probes import probe, stdin_arguments, verify_probe
from ops_deploy.helpers.traefik import DYNAMIC_DIR
from ops_deploy.infra._common import codename, directory
from ops_deploy.ops import secret_file

TEMPLATE_PACKAGE = "ops_deploy.services.vaultwarden"
FILES = Path(__file__).parent / "files"
SMTP_SYNC = (FILES / "smtp_config_sync.py").read_text()

UNIT = "vaultwarden.service"
PACKAGES = ("vaultwarden", "vaultwarden-web-vault")
PREREQUISITES = ("apt-transport-https", "ca-certificates", "curl", "gnupg")
# Fixed by the packages (the role's defaults/main.yml header).
ENV_PATH = PurePosixPath("/etc/vaultwarden.env")
DATA_DIR = PurePosixPath("/var/lib/vaultwarden/data")
LOG_DIR = PurePosixPath("/var/log/vaultwarden")
CONFIG_JSON = DATA_DIR / "config.json"
DROPIN_DIR = PurePosixPath("/etc/systemd/system/vaultwarden.service.d")
DROPIN = DROPIN_DIR / "override.conf"
ROUTE = DYNAMIC_DIR / "vaultwarden.yml"
KEYRING_DIR = PurePosixPath("/etc/apt/keyrings")
KEYRING = KEYRING_DIR / "vaultwarden-deb-repo-keyring.gpg"
SOURCES_LIST = PurePosixPath("/etc/apt/sources.list.d/vaultwarden.list")
# validate.yml: the releases the role accepts; Ubuntu's use the bookworm suite.
SUPPORTED_RELEASES = ("bullseye", "bookworm", "trixie", "jammy", "noble")
UBUNTU_SUITE = {"jammy": "bookworm", "noble": "bookworm"}
PLACEHOLDER = "CHANGEME"

_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
# Rendered unquoted into YAML (``- websecure``, ``certResolver: x``).
_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
# One line of the environment file: no control characters.
EnvText = Annotated[str, Field(pattern=r"^[^\x00-\x1f\x7f]*$", max_length=1024)]
RepoUrl = Annotated[str, Field(pattern=r"^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?$")]


def _yaml_word(value: str) -> bool:
    """A plain word that YAML reads back as the same string (not ``true``, ``1``, ``null``)."""

    return bool(_WORD.fullmatch(value)) and yaml.safe_load(value) == value


def traefik_hostname(domain: str) -> str:
    """traefik.yml's ``vaultwarden_hostname``: the domain without scheme and path."""

    return re.sub(r"/.*$", "", re.sub(r"^https?://", "", domain))


class VaultwardenConfig(BaseServiceConfig):
    """The ``vaultwarden_*`` variables the deploy uses, without the prefix (the role's defaults).

    ``service_name``, ``user`` and ``site_path`` are what the packages install
    and cannot be changed.
    """

    # admin_token is required while the admin panel is enabled (check_secrets).
    required_secret_keys: ClassVar[tuple[str, ...]] = ()

    service_name: ServiceName = "vaultwarden"
    user: UnixUser = "vaultwarden"
    site_path: PurePosixPath = PurePosixPath("/var/lib/vaultwarden")
    # Required: the public URL, e.g. ``https://vault.example.com``.
    domain: str
    apt_repo_url: RepoUrl = "https://vaultwarden-deb.pages.dev"
    rocket_address: str = "127.0.0.1"
    rocket_port: int = Field(default=8000, ge=1, le=65535)
    websocket_enabled: bool = True
    signups_allowed: bool = False
    invitations_allowed: bool = True
    show_password_hint: bool = False
    org_creation_users: EnvText = "all"
    smtp_host: EnvText = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_security: EnvText = "starttls"
    smtp_from: EnvText = ""
    smtp_from_name: EnvText = "Vaultwarden"
    # The template's ``default('Plain')``; the role has no default variable.
    smtp_auth_mechanism: EnvText = "Plain"
    smtp_accept_invalid_certs: bool = False
    smtp_accept_invalid_hostnames: bool = False
    # None: undefined, as in the role (no SMTP_DEBUG line, and config.json's
    # smtp_debug is left alone); True/False is written to both.
    smtp_debug: bool | None = None
    experimental_client_feature_flags: EnvText = "ssh-key-vault-item,ssh-agent"
    sends_allowed: bool = True
    emergency_access_allowed: bool = True
    icon_service: EnvText = "internal"
    log_level: EnvText = "info"
    traefik_enabled: bool = True
    traefik_entrypoint: str = "websecure"
    traefik_certresolver: str = ""
    healthcheck_enabled: bool = True
    healthcheck_timeout: int = Field(default=30, ge=5, le=600)

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        if not re.fullmatch(r"https?://[^\s/]+(/[^\s]*)?", value) or len(value) > 1024:
            raise ValueError("domain must be an http(s) URL such as https://vault.example.com")
        if not re.fullmatch(r"[!-~]+", value):
            raise ValueError("domain must be printable ASCII without spaces (use the IDN-encoded name)")
        if not _HOSTNAME.fullmatch(traefik_hostname(value)):
            raise ValueError("domain must name a DNS host name without a port")
        return value

    @field_validator("rocket_address")
    @classmethod
    def _address(cls, value: str) -> str:
        # Rendered as http://<address>:<port> without brackets, as the role does.
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError("rocket_address must be an IPv4 address") from None
        return value

    @field_validator("traefik_entrypoint")
    @classmethod
    def _entrypoint(cls, value: str) -> str:
        if not _yaml_word(value):
            raise ValueError("traefik_entrypoint must be a plain name")
        return value

    @field_validator("traefik_certresolver")
    @classmethod
    def _resolver(cls, value: str) -> str:
        if value and not _yaml_word(value):
            raise ValueError("traefik_certresolver must be a plain name")
        return value

    @model_validator(mode="after")
    def _role_rules(self) -> VaultwardenConfig:
        fixed = {
            "service_name": "vaultwarden",
            "user": "vaultwarden",
            "site_path": PurePosixPath("/var/lib/vaultwarden"),
        }
        if any(getattr(self, name) != value for name, value in fixed.items()):
            raise ValueError("service_name, user and site_path are fixed by the vaultwarden packages")
        if self.smtp_host and not self.smtp_from:
            raise ValueError("smtp_from must be set when smtp_host is configured")
        return self

    @property
    def hostname(self) -> str:
        return traefik_hostname(self.domain)


# -- secrets ----------------------------------------------------------------------------


def admin_enabled(secrets: SecretValues) -> bool:
    """The playbook's ``admin_enabled | default(true)`` from the secrets file (a YAML boolean)."""

    value = secrets.get("admin_enabled", "true")
    if value not in ("true", "false"):
        raise ValueError("admin_enabled must be a boolean (true or false)")
    return value == "true"


def check_secrets(secrets: SecretValues) -> None:
    """The role's admin token assertion, plus single-line values; errors never quote values."""

    if admin_enabled(secrets):
        token = secrets.get("admin_token", "")
        if not token or PLACEHOLDER in token:
            raise ValueError("admin_token must be set and not a placeholder while the admin panel is enabled")
    for key in ("admin_token", "smtp_username", "smtp_password"):
        if any(char in secrets.get(key, "") for char in "\r\n\x00"):
            raise ValueError(f"{key} must be a single line")


# -- the role's templates -----------------------------------------------------------------


def _ansible_bool(value: Any) -> bool:
    """Ansible's ``bool`` filter for the values these templates see."""

    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("yes", "on", "1", "true", "y", "t")


@cache
def _templates() -> jinja2.Environment:
    # Rendered like Ansible's template module (trim_blocks), for byte parity.
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["bool"] = _ansible_bool
    return env


def role_vars(cfg: VaultwardenConfig, **extra: Any) -> dict[str, Any]:
    """The role's variables the templates read (``vaultwarden_smtp_debug`` only when set)."""

    variables: dict[str, Any] = {
        "vaultwarden_domain": cfg.domain,
        "vaultwarden_hostname": cfg.hostname,
        "vaultwarden_rocket_address": cfg.rocket_address,
        "vaultwarden_rocket_port": cfg.rocket_port,
        "vaultwarden_websocket_enabled": cfg.websocket_enabled,
        "vaultwarden_signups_allowed": cfg.signups_allowed,
        "vaultwarden_invitations_allowed": cfg.invitations_allowed,
        "vaultwarden_show_password_hint": cfg.show_password_hint,
        "vaultwarden_org_creation_users": cfg.org_creation_users,
        "vaultwarden_smtp_host": cfg.smtp_host,
        "vaultwarden_smtp_port": cfg.smtp_port,
        "vaultwarden_smtp_security": cfg.smtp_security,
        "vaultwarden_smtp_from": cfg.smtp_from,
        "vaultwarden_smtp_from_name": cfg.smtp_from_name,
        "vaultwarden_smtp_auth_mechanism": cfg.smtp_auth_mechanism,
        "vaultwarden_smtp_accept_invalid_certs": cfg.smtp_accept_invalid_certs,
        "vaultwarden_smtp_accept_invalid_hostnames": cfg.smtp_accept_invalid_hostnames,
        "vaultwarden_experimental_client_feature_flags": cfg.experimental_client_feature_flags,
        "vaultwarden_sends_allowed": cfg.sends_allowed,
        "vaultwarden_emergency_access_allowed": cfg.emergency_access_allowed,
        "vaultwarden_icon_service": cfg.icon_service,
        "vaultwarden_log_level": cfg.log_level,
        "vaultwarden_traefik_entrypoint": cfg.traefik_entrypoint,
        "vaultwarden_traefik_certresolver": cfg.traefik_certresolver,
        **extra,
    }
    if cfg.smtp_debug is not None:
        variables["vaultwarden_smtp_debug"] = cfg.smtp_debug
    return variables


def render(template: str, variables: dict[str, Any]) -> str:
    return _templates().get_template(template).render(**variables)


def render_env(cfg: VaultwardenConfig, secrets: SecretValues) -> SecretContent:
    """The role's ``vaultwarden.env.j2`` (admin token and SMTP credentials included)."""

    return SecretContent(
        render(
            "vaultwarden.env.j2",
            role_vars(
                cfg,
                vaultwarden_admin_enabled=admin_enabled(secrets),
                vaultwarden_admin_token=secrets.get("admin_token", ""),
                vaultwarden_smtp_username=secrets.get("smtp_username", ""),
                vaultwarden_smtp_password=secrets.get("smtp_password", ""),
            ),
        )
    )


def render_dropin(cfg: VaultwardenConfig) -> str:
    return render("vaultwarden-override.conf.j2", role_vars(cfg))


def render_route(cfg: VaultwardenConfig) -> str:
    return render("traefik-vaultwarden.yml.j2", role_vars(cfg))


def sources_line(cfg: VaultwardenConfig, suite: str) -> str:
    """The line ``apt_repository`` keeps in ``vaultwarden.list``."""

    return f"deb [signed-by={KEYRING}] {cfg.apt_repo_url} {suite} main\n"


def repo_suite(release: str) -> str:
    """validate.yml: a supported release; Ubuntu's map to the bookworm suite."""

    if release not in SUPPORTED_RELEASES:
        raise DeployError(f"vaultwarden: unsupported release {release!r} (supported: {', '.join(SUPPORTED_RELEASES)})")
    return UBUNTU_SUITE.get(release, release)


def smtp_settings(cfg: VaultwardenConfig) -> dict[str, Any]:
    """configure.yml's ``smtp_base`` (plus ``smtp_debug`` when set), with the JSON types it writes."""

    settings: dict[str, Any] = {
        "smtp_host": cfg.smtp_host,
        "smtp_port": cfg.smtp_port,
        "smtp_security": cfg.smtp_security,
        "smtp_from": cfg.smtp_from,
        "smtp_from_name": cfg.smtp_from_name,
        "smtp_accept_invalid_certs": cfg.smtp_accept_invalid_certs,
        "smtp_accept_invalid_hostnames": cfg.smtp_accept_invalid_hostnames,
    }
    if cfg.smtp_debug is not None:
        settings["smtp_debug"] = cfg.smtp_debug
    return settings


def smtp_request(cfg: VaultwardenConfig) -> str:
    """The stdin of ``smtp_config_sync.py`` (non-secret settings; one JSON line)."""

    request: Mapping[str, Any] = {
        "path": str(CONFIG_JSON),
        "owner": cfg.user,
        "group": cfg.user,
        "settings": smtp_settings(cfg),
    }
    return json.dumps(request, sort_keys=True) + "\n"


def smtp_command(action: str) -> str:
    return shlex.join(["python3", "-I", "-c", SMTP_SYNC, action])


# -- the role's task files ------------------------------------------------------------------


def preflight_addresses(cfg: VaultwardenConfig) -> tuple[str, ...] | None:
    """Listener addresses (as ``ss`` prints them) that collide with the Rocket bind; None: any.

    The playbook's ``bind: loopback`` set (loopback and wildcard addresses),
    plus the configured address when it is another one; a wildcard bind
    collides with a listener on any address.
    """

    if cfg.rocket_address == "0.0.0.0":
        return None
    loopback = ("127.0.0.1", "0.0.0.0", "[::1]", "[::]", "*", "[::ffff:127.0.0.1]")
    own = (cfg.rocket_address, f"[::ffff:{cfg.rocket_address}]")
    return tuple(dict.fromkeys((*loopback, *own)))


def _port_preflight(cfg: VaultwardenConfig) -> OperationMeta:
    """The playbook's port preflight: nothing but vaultwarden may listen on the Rocket port.

    Like ``common/preflight_ports.yml`` with ``bind: loopback`` and
    ``vaultwarden.service`` as the allowed owner: a TCP listener on the port at
    a loopback or wildcard address, or at the configured Rocket address (any
    address when that is the wildcard), fails the deploy unless every process
    behind it runs in that unit. Read-only; runs before any change.
    """

    addresses = preflight_addresses(cfg)
    match = "*" if addresses is None else "|".join(f'"{address}"' for address in addresses)
    script = (
        f"out=$(ss -Hltnp 'sport = :{cfg.rocket_port}') || exit 1; "
        "printf '%s\\n' \"$out\" | { bad=0; "
        "while read -r _state _recv _send local _peer users; do "
        # No listener: printf still emits one empty line, which a wildcard bind would match.
        '[ -n "$local" ] || continue; '
        f'case "${{local%:*}}" in {match}) ;; *) continue ;; esac; '
        "pids=$(printf '%s' \"$users\" | grep -o 'pid=[0-9]*' | cut -d= -f2); "
        '[ -n "$pids" ] || bad=1; '
        "for pid in $pids; do "
        f"grep -qx '0::/system.slice/{UNIT}' /proc/$pid/cgroup 2>/dev/null || bad=1; done; "
        '[ "$bad" = 0 ] || echo "port in use: $local $users" >&2; '
        'done; [ "$bad" = 0 ]; }'
    )
    return mark_read_only(
        server.shell(name=f"Port preflight tcp/{cfg.rocket_port}", commands=[f"sh -c {shlex.quote(script)}"])
    )


def _repository(cfg: VaultwardenConfig, suite: str) -> None:
    """repository.yml: prerequisites, signing key (downloaded once) and ``vaultwarden.list``."""

    apt.packages(name="Install apt prerequisites", packages=list(PREREQUISITES), update=True, cache_time=3600)
    files.directory(name=f"Ensure {KEYRING_DIR}", path=str(KEYRING_DIR), user="root", group="root", mode="0755")
    # The role's get_url without force: an existing key is kept, only its mode is set.
    key = files.download(
        name="Download Vaultwarden repository GPG key",
        src=f"{cfg.apt_repo_url}/vaultwarden-deb-repo-keyring.gpg",
        dest=str(KEYRING),
        mode="0644",
    )
    repo = files.put(
        name="Add Vaultwarden apt repository",
        src=StringIO(sources_line(cfg, suite)),
        dest=str(SOURCES_LIST),
        user="root",
        group="root",
        mode="0644",
    )
    apt.update(name="Update apt cache after adding repository", _if=any_changed(repo, key))


def _packages() -> OperationMeta:
    """packages.yml without pins or hold: install, then read back a version for each package."""

    install = apt.packages(name="Install Vaultwarden packages", packages=list(PACKAGES))
    script = (
        "for p in " + " ".join(PACKAGES) + "; do "
        "v=$(dpkg-query -W -f '${Version}' \"$p\") || exit 1; "
        '[ -n "$v" ] || { echo "no installed version for $p" >&2; exit 1; }; '
        'echo "$p $v"; done'
    )
    mark_read_only(server.shell(name="Read installed package versions", commands=[f"sh -c {shlex.quote(script)}"]))
    return install


def _smtp_sync(cfg: VaultwardenConfig) -> OperationMeta | None:
    """configure.yml's config.json SMTP sync, when it exists and SMTP is configured.

    A read-only check while planning decides; the merge runs on the host, so
    the file (which holds the admin token once the admin panel saved it) never
    reaches the controller.
    """

    if not cfg.smtp_host:
        return None
    request = smtp_request(cfg)
    name = "vaultwarden config.json SMTP settings"
    state = probe(smtp_command("check"), name=name, stdin=request)
    sync = server.shell(
        name="Sync SMTP settings to config.json",
        commands=[smtp_command("apply")],
        _if=lambda: state not in ("absent", "current"),
        **stdin_arguments(request),
    )
    if state is None:
        verify_probe(smtp_command("check"), name=name, expect="current", stdin=request)
    return sync


@deploy("Deploy Vaultwarden")
def deploy_vaultwarden(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    require_linux("vaultwarden")
    check_secrets(secrets)
    env_content = render_env(cfg, secrets)
    suite = repo_suite(codename())

    _port_preflight(cfg)

    # repository.yml, packages.yml
    _repository(cfg, suite)
    install = _packages()
    for path in (DATA_DIR, LOG_DIR):
        directory(str(path), user=cfg.user, group=cfg.user, mode="0750")

    # configure.yml
    env = secret_file(
        name=f"Deploy {ENV_PATH}",
        path=ENV_PATH,
        content=env_content,
        user="root",
        group=cfg.user,
        mode="0640",
    )
    smtp = _smtp_sync(cfg)
    files.directory(name=f"Ensure {DROPIN_DIR}", path=str(DROPIN_DIR), user="root", group="root", mode="0755")
    dropin = files.put(
        name="Deploy systemd override for security hardening",
        src=StringIO(render_dropin(cfg)),
        dest=str(DROPIN),
        user="root",
        group="root",
        mode="0644",
    )

    # traefik.yml: no Traefik restart, its file provider watches the directory.
    if cfg.traefik_enabled:
        files.directory(
            name="Ensure Traefik dynamic directory", path=str(DYNAMIC_DIR), user="root", group="root", mode="0755"
        )
        files.put(
            name="Write Traefik route vaultwarden",
            src=StringIO(render_route(cfg)),
            dest=str(ROUTE),
            user="root",
            group="root",
            mode="0644",
        )

    # service.yml and the role's handlers.
    restart = [op for op in (install, env, smtp) if op is not None]
    service_rollout(UNIT, units=[dropin], restart_when=restart)

    # health.yml
    if cfg.healthcheck_enabled:
        http_check(
            f"http://{cfg.rocket_address}:{cfg.rocket_port}/alive",
            retries=cfg.healthcheck_timeout // 5,
            delay=5,
            name="Wait for Vaultwarden to be ready",
        )
