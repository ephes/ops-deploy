"""Base Traefik: binary, static config, unit, logs and firewall (the ``traefik_deploy`` role).

Only the role's full deploy is ported. Hosts enrolled in the guarded Traefik
transaction workflow (``transaction_required``, or a
``/var/lib/traefik-transactions`` directory) are refused before any change,
exactly as the role's ``guard.yml`` refuses them. The role's transaction engine
is ported as :mod:`ops_deploy.infra.traefik_tx.engine` (run detached by
:mod:`ops_deploy.infra.traefik_tx.transport`, which no deploy uses); its prepare
and health-probe entries are not ported.

Nothing reaches the live proxy unchecked: the static config and the
file-provider certificate list are parsed on the controller before any
operation is added, the certificate files must exist on the host before the
list is written (Traefik watches that directory and loads it at once), and a
new binary must report the wanted version before Traefik is restarted.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Literal

import yaml
from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Which
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import (
    AbsolutePath,
    RoleConfig,
    Version,
    ensure_curl,
    output,
    release_install_script,
    require_linux,
    require_systemd,
)
from ops_deploy.base._units import ACTIVE, ENABLED, unit_states
from ops_deploy.helpers import mark_read_only, wait_port
from ops_deploy.infra._common import directory

Port = Annotated[int, Field(ge=1, le=65535)]
Checksum = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
# Goes into a TOML basic string: no quotes, backslashes or control characters.
Email = Annotated[str, Field(pattern=r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")]
BindAddress = Annotated[str, Field(pattern=r"^[A-Za-z0-9.:\[\]-]+$")]
WebUnit = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+\.service$")]
Entrypoint = Literal["web", "web-secure", "traefik"]

TRANSACTION_STATE = "/var/lib/traefik-transactions"
UNIT_PATH = "/etc/systemd/system/traefik.service"
LOGROTATE_PATH = "/etc/logrotate.d/traefik"
# uname -m -> the release archive's architecture.
ARCHITECTURES = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armv7", "armv6l": "armv6"}
_VERSION = re.compile(r"Version:\s+v?([0-9.]+)")


class FileCertificate(RoleConfig):
    cert_file: AbsolutePath
    key_file: AbsolutePath


class TraefikDeployConfig(RoleConfig):
    version: Version = "3.7.13"
    # The release's ``sha256:<hex>``. The role skips the check when it is empty;
    # here it is required, so nothing unverified is ever installed.
    checksum: Checksum
    # None: from ``uname -m``.
    arch: Literal["amd64", "arm64", "armv7", "armv6"] | None = None
    letsencrypt_email: Email

    config_dir: AbsolutePath = "/etc/traefik"
    # None: below ``config_dir`` (dynamic, acme, traefik.toml, acme/acme.json).
    dynamic_dir: AbsolutePath | None = None
    acme_dir: AbsolutePath | None = None
    static_config: AbsolutePath | None = None
    acme_storage: AbsolutePath | None = None
    log_dir: AbsolutePath = "/var/log/traefik"
    binary_path: AbsolutePath = "/usr/local/bin/traefik"
    file_certificates: tuple[FileCertificate, ...] = ()

    log_level: Literal["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "PANIC"] = "INFO"
    log_format: Literal["json", "common"] = "json"
    dashboard_enabled: bool = True
    dashboard_port: Port = 8090
    dashboard_firewall_open: bool = False
    http_port: Port = 80
    https_port: Port = 443
    http_redirect_to_https: bool = True
    metrics_enabled: bool = True
    metrics_bind_address: BindAddress = "127.0.0.1"
    metrics_port: Port = 8080
    force_update: bool = False
    configure_firewall: bool = True
    logrotate_days: int = Field(default=7, ge=1)
    mask_conflicting_web_services: bool = True
    conflicting_web_services: tuple[WebUnit, ...] = (
        "nginx.service",
        "apache2.service",
        "caddy.service",
        "lighttpd.service",
    )
    # Refuse the host, as the role does for transaction-managed hosts.
    transaction_required: bool = False
    alias_policy: dict[Entrypoint, Literal["delete"]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _alias_policy_is_complete(self) -> TraefikDeployConfig:
        # The role's assert: a policy covers every rendered entrypoint, and
        # only releases from 3.7.12 on know the setting.
        if self.alias_policy:
            expected = {"web", "web-secure"}
            if self.dashboard_enabled or self.metrics_enabled:
                expected.add("traefik")
            if set(self.alias_policy) != expected:
                raise ValueError(f"alias_policy must cover exactly the entrypoints {sorted(expected)}")
            if tuple(int(part) for part in self.version.split(".")) < (3, 7, 12):
                raise ValueError("alias_policy needs Traefik 3.7.12 or newer")
        return self

    @model_validator(mode="after")
    def _listeners_can_bind(self) -> TraefikDeployConfig:
        # Traefik exits when two entrypoints share a port or an address does
        # not parse; refuse such a config instead of restarting into it.
        ports = [self.http_port, self.https_port]
        if self.dashboard_enabled:
            ports.append(self.dashboard_port)
        elif self.metrics_enabled:
            ports.append(self.metrics_port)
            address = self.metrics_bind_address
            if ":" in address and not (address.startswith("[") and address.endswith("]")):
                raise ValueError("an IPv6 metrics_bind_address must be written in brackets, e.g. [::1]")
        if len(set(ports)) != len(ports):
            raise ValueError(f"entrypoint ports must differ: {ports}")
        return self

    @property
    def dynamic_path(self) -> str:
        return self.dynamic_dir or f"{self.config_dir}/dynamic"

    @property
    def acme_path(self) -> str:
        return self.acme_dir or f"{self.config_dir}/acme"

    @property
    def static_path(self) -> str:
        return self.static_config or f"{self.config_dir}/traefik.toml"

    @property
    def acme_storage_path(self) -> str:
        return self.acme_storage or f"{self.acme_path}/acme.json"


def _alias(cfg: TraefikDeployConfig, entrypoint: Entrypoint) -> str:
    policy = cfg.alias_policy.get(entrypoint)
    return f'    http.aliasHeadersStrategy = "{policy}"\n' if policy else ""


def render_static(cfg: TraefikDeployConfig) -> str:
    """``traefik.toml.j2`` from the role, byte for byte."""

    api = "[api]\n  dashboard = true\n  debug = false\n" if cfg.dashboard_enabled else ""
    redirect = (
        '    [entryPoints.web.http.redirections.entryPoint]\n      to = "web-secure"\n'
        '      scheme = "https"\n      permanent = true\n'
        if cfg.http_redirect_to_https
        else ""
    )
    if cfg.dashboard_enabled:
        traefik_entry = (
            "  # Dashboard/API entrypoint (moved from default 8080 to avoid UniFi conflict)\n"
            f'  [entryPoints.traefik]\n{_alias(cfg, "traefik")}    address = ":{cfg.dashboard_port}"\n'
        )
    elif cfg.metrics_enabled:
        traefik_entry = (
            '  # Metrics-only entrypoint. Prometheus metrics default to the "traefik"\n'
            "  # entrypoint, and when nothing defines it Traefik creates it implicitly on\n"
            "  # :8080 on every interface - which put /metrics on the public internet on a\n"
            "  # host with the dashboard disabled. Define it explicitly and bind it.\n"
            f"  [entryPoints.traefik]\n{_alias(cfg, 'traefik')}"
            f'    address = "{cfg.metrics_bind_address}:{cfg.metrics_port}"\n'
        )
    else:
        traefik_entry = ""
    metrics = (
        "# Optional: Enable metrics\n[metrics]\n  [metrics.prometheus]\n"
        '    entryPoint = "traefik"\n    addEntryPointsLabels = true\n'
        "    addServicesLabels = true\n    buckets = [0.1,0.3,1.2,5.0]\n"
        if cfg.metrics_enabled
        else ""
    )
    return (
        "# Traefik static configuration\n# This file configures the core Traefik settings\n\n"
        "[global]\n  checkNewVersion = true\n  sendAnonymousUsage = false\n\n"
        f"{api}\n"
        f'[log]\n  level = "{cfg.log_level}"\n  filePath = "{cfg.log_dir}/traefik.log"\n'
        f'  format = "{cfg.log_format}"\n\n'
        f'[accessLog]\n  filePath = "{cfg.log_dir}/access.log"\n  format = "{cfg.log_format}"\n'
        "  bufferingSize = 100\n\n"
        f'[providers.file]\n  directory = "{cfg.dynamic_path}"\n  watch = true\n\n'
        f"[entryPoints]\n  [entryPoints.web]\n{_alias(cfg, 'web')}"
        f'    address = ":{cfg.http_port}"\n{redirect}\n'
        f"  [entryPoints.web-secure]\n{_alias(cfg, 'web-secure')}"
        f'    address = ":{cfg.https_port}"\n\n'
        f"{traefik_entry}\n"
        f'[certificatesResolvers.letsencrypt.acme]\n  email = "{cfg.letsencrypt_email}"\n'
        f'  storage = "{cfg.acme_storage_path}"\n  keyType = "EC256"\n'
        '  [certificatesResolvers.letsencrypt.acme.httpChallenge]\n    entryPoint = "web"\n\n'
        f"{metrics}"
    )


def render_certificates(cfg: TraefikDeployConfig) -> str:
    """``dynamic/certificates.yml.j2`` from the role, byte for byte."""

    entries = "".join(
        f'    - certFile: "{cert.cert_file}"\n      keyFile: "{cert.key_file}"\n' for cert in cfg.file_certificates
    )
    return f"# Managed by Ansible - File provider certificates\ntls:\n  certificates:\n{entries}"


def render_unit(cfg: TraefikDeployConfig) -> str:
    """``traefik.service.j2`` from the role, byte for byte."""

    return (
        "[Unit]\nDescription=Traefik\nDocumentation=https://doc.traefik.io/traefik/\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=simple\nUser=root\nGroup=root\n"
        f"ExecStart={cfg.binary_path} --configfile={cfg.static_path}\n"
        "Restart=on-failure\nRestartSec=5\nStandardOutput=journal\nStandardError=journal\n"
        "SyslogIdentifier=traefik\nKillMode=mixed\nKillSignal=SIGTERM\n\n"
        "# Security hardening\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\n"
        f"ProtectHome=true\nReadWritePaths={cfg.config_dir} {cfg.log_dir}\n"
        "ProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\n"
        "RestrictRealtime=true\nRestrictSUIDSGID=true\nPrivateDevices=true\nLockPersonality=true\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def render_logrotate(cfg: TraefikDeployConfig) -> str:
    """The role's ``/etc/logrotate.d/traefik`` content (``traefik.logrotate.j2``)."""

    rotation = (
        f"    daily\n    rotate {cfg.logrotate_days}\n    compress\n    delaycompress\n    missingok\n    notifempty\n"
    )
    return (
        "# Managed by Ansible (traefik_deploy) - Traefik log rotation\n"
        "# logrotate processes the blocks in order: traefik.log first, so the line\n"
        "# Traefik logs on receiving SIGUSR1 lands in the fresh file.\n"
        "\n"
        "# SIGUSR1 reopens only the access log; Traefik never reopens its own log.\n"
        "# It writes that file with O_APPEND, so copytruncate keeps it in place; lines\n"
        "# written between the copy and the truncate are lost (the file is small).\n"
        f"{cfg.log_dir}/traefik.log {{\n{rotation}    copytruncate\n}}\n"
        "\n"
        "# The access log is renamed and Traefik reopens it on SIGUSR1. The unit has no\n"
        "# ExecReload, so `systemctl reload` fails; without the signal Traefik keeps\n"
        "# writing to the renamed access.log.1 and the fresh access.log stays empty,\n"
        "# which `notifempty` then never rotates again.\n"
        f"{cfg.log_dir}/access.log {{\n{rotation}    create 0644 root root\n"
        "    postrotate\n"
        "        if systemctl is-active --quiet traefik.service; then\n"
        "            systemctl kill --signal=USR1 --kill-whom=main traefik.service\n"
        "        fi\n"
        "    endscript\n}\n"
    )


def validate_static(content: str) -> None:
    """Refuse a static config Traefik could not start with: TOML that does not parse."""

    try:
        parsed = tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        raise DeployError(f"traefik_deploy: the rendered static config is not valid TOML: {error}") from None
    for section in ("entryPoints", "providers", "certificatesResolvers"):
        if not isinstance(parsed.get(section), dict):
            raise DeployError(f"traefik_deploy: the rendered static config has no [{section}]")


def validate_certificates(content: str) -> None:
    """Refuse a certificate list Traefik's file provider would reject."""

    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as error:
        raise DeployError(f"traefik_deploy: the rendered certificate list is not valid YAML: {error}") from None
    entries = (parsed or {}).get("tls", {}).get("certificates") if isinstance(parsed, dict) else None
    if not isinstance(entries, list) or not all(
        isinstance(entry, dict) and set(entry) == {"certFile", "keyFile"} for entry in entries
    ):
        raise DeployError("traefik_deploy: the rendered certificate list is malformed")


def installed_version(binary: str) -> str:
    match = _VERSION.search(output(f"{shlex.quote(binary)} version"))
    return match.group(1) if match else ""


def refuse_transaction_managed(required: bool, what: str) -> None:
    """The role's ``guard.yml``: transaction-managed hosts are never written."""

    enrolled = output(f"test -e {TRANSACTION_STATE} && echo enrolled").strip() == "enrolled"
    if required or enrolled:
        raise DeployError(
            f"{what}: this host requires the guarded Traefik transaction workflow. "
            "Full deploy, restore and removal cannot bypass pending or recovery records."
        )


def _put(name: str, content: str, dest: str) -> OperationMeta:
    return files.put(name=name, src=StringIO(content), dest=dest, user="root", group="root", mode="0644")


def _install_binary(cfg: TraefikDeployConfig) -> OperationMeta | None:
    current = installed_version(cfg.binary_path)
    if current == cfg.version and not cfg.force_update:
        host.noop(f"Traefik {cfg.version} is installed")
        return None
    arch = cfg.arch or ARCHITECTURES.get(output("uname -m").strip())
    if arch is None:
        raise DeployError("traefik_deploy: unknown host architecture; set arch")
    ensure_curl("traefik_deploy")
    binary = PurePosixPath(cfg.binary_path)
    script = release_install_script(
        url=(
            f"https://github.com/traefik/traefik/releases/download/v{cfg.version}/"
            f"traefik_v{cfg.version}_linux_{arch}.tar.gz"
        ),
        sha256=cfg.checksum.removeprefix("sha256:"),
        binaries={"traefik": binary.name},
        install_dir=str(binary.parent),
    )
    installed = server.shell(name=f"Install Traefik {cfg.version}", commands=[script])
    # A replaced binary must work before the restart below puts it live.
    expected = f"Version:[[:space:]]+v?{re.escape(cfg.version)}$"
    server.shell(
        name=f"Check the installed Traefik is {cfg.version}",
        commands=[f"{shlex.quote(cfg.binary_path)} version | grep -Eq {shlex.quote(expected)}"],
        _if=installed.did_change,
    )
    return installed


def _firewall(cfg: TraefikDeployConfig) -> None:
    if not cfg.configure_firewall or not host.get_fact(Which, command="ufw"):
        return
    if not host.get_fact(Which, command="apt-get"):
        return  # the role only manages UFW on Debian-family hosts
    ports = [cfg.http_port, cfg.https_port]
    if cfg.dashboard_enabled and cfg.dashboard_firewall_open:
        ports.append(cfg.dashboard_port)
    # ``ufw show added`` lists the rules community.general.ufw adds as ``ufw allow <port>/tcp``.
    added = set(output("ufw show added").splitlines())
    for port in ports:
        if f"ufw allow {port}/tcp" not in added:
            server.shell(name=f"Allow {port}/tcp in UFW", commands=[f"ufw allow {port}/tcp"])


def _disarm_web_servers(cfg: TraefikDeployConfig) -> None:
    """The role's ``web_conflicts.yml``: stop, disable and mask installed distro web servers."""

    if not cfg.mask_conflicting_web_services:
        return
    states = unit_states(list(cfg.conflicting_web_services))
    for unit, state in states.items():
        if state.get("LoadState", "not-found") == "not-found":
            continue
        quoted = shlex.quote(unit)
        commands = []
        if state.get("ActiveState") in ACTIVE:
            commands.append(f"systemctl stop {quoted}")
        if state.get("UnitFileState") in ENABLED:
            commands.append(f"systemctl disable {quoted}")
        if state.get("UnitFileState") != "masked":
            commands.append(f"systemctl mask {quoted}")
        if state.get("ActiveState") == "failed":
            commands.append(f"systemctl reset-failed {quoted}")
        if commands:
            server.shell(name=f"Disarm {unit}", commands=commands)


@deploy("Traefik")
def deploy_traefik(cfg: TraefikDeployConfig) -> None:
    """Install Traefik, write its static config and unit, and keep it running."""

    require_linux("traefik_deploy")
    require_systemd("traefik_deploy")
    refuse_transaction_managed(cfg.transaction_required, "traefik_deploy")
    static = render_static(cfg)
    validate_static(static)
    certificates = render_certificates(cfg) if cfg.file_certificates else None
    if certificates is not None:
        validate_certificates(certificates)
        for cert in cfg.file_certificates:
            for path in (cert.cert_file, cert.key_file):
                if output(f"test -f {shlex.quote(path)} && echo present").strip() != "present":
                    raise DeployError(f"traefik_deploy: certificate file {path} is missing on the host")

    for path, mode in (
        (cfg.config_dir, "0755"),
        (cfg.dynamic_path, "0755"),
        (cfg.acme_path, "0700"),
        (cfg.log_dir, "0755"),
    ):
        directory(path, user="root", group="root", mode=mode)

    binary = _install_binary(cfg)
    changes = [_put("Write the Traefik static config", static, cfg.static_path)]
    if certificates is not None:
        changes.append(
            _put("Write the file-provider certificates", certificates, f"{cfg.dynamic_path}/certificates.yml")
        )
    unit = _put("Write the Traefik unit", render_unit(cfg), UNIT_PATH)
    changes.append(unit)
    if binary is not None:
        changes.append(binary)

    files.file(
        name="Ensure the ACME store",
        path=cfg.acme_storage_path,
        present=True,
        touch=False,
        user="root",
        group="root",
        mode="0600",
    )
    _put("Configure Traefik log rotation", render_logrotate(cfg), LOGROTATE_PATH)
    _firewall(cfg)
    _disarm_web_servers(cfg)

    systemd.daemon_reload(name="Reload systemd for the Traefik unit", _if=unit.did_change)
    systemd.service(name="Ensure Traefik", service="traefik.service", running=True, enabled=True)
    # The role restarts on config and unit changes only; a replaced binary
    # keeps running the old one, so it restarts here too.
    systemd.service(
        name="Restart Traefik for the new configuration",
        service="traefik.service",
        running=None,
        restarted=True,
        _if=any_changed(*changes),
    )
    wait_port(cfg.http_port, name=f"Wait for Traefik on port {cfg.http_port}")
    mark_read_only(server.shell(name="Check Traefik is active", commands=["systemctl is-active --quiet traefik"]))
