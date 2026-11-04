"""Port of the ``unifi_remove`` role: its defaults, flags, order and ignored failures.

Never dispatched without ``confirm``. Every destructive flag keeps the role's
default; a caller opts in exactly as with ``-e unifi_remove_*=true``.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from importlib.resources import files as resources
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import Field, StrictBool, model_validator
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.operations import server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, output, require_linux
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.probes import probe
from ops_deploy.ops import secret_stdin
from ops_deploy.services._lifecycle.ansible_remove import absent, service_absent, user_absent

HOST = resources("ops_deploy.services.unifi").joinpath("files/remove_host.py").read_text()
Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]+$")]
MongoName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+$")]
Port = Annotated[int, Field(ge=1, le=65535)]


class FirewallRule(RoleConfig):
    port: Port
    proto: Literal["tcp", "udp"]
    comment: str = ""


class UnifiRemoveConfig(RoleConfig):
    """``unifi_remove``'s defaults; paths derive from the names as the role's do."""

    confirm: StrictBool = False
    service_name: ServiceName = "unifi"
    user: UnixUser = "unifi"
    group: UnixUser = "unifi"
    home_dir: AbsolutePath = "/home/unifi"
    install_dir: AbsolutePath = "/usr/lib/unifi"
    cache_dir: AbsolutePath = "/home/unifi/cache"
    data_dir: AbsolutePath = "/usr/lib/unifi/data"
    logs_dir: AbsolutePath = "/usr/lib/unifi/logs"
    backup_dir: AbsolutePath = "/usr/lib/unifi/data/backup"
    systemd_unit_path: AbsolutePath = "/etc/systemd/system/unifi.service"
    mongodb_jvm_args_path: AbsolutePath = "/etc/unifi-secrets/mongodb.jvmargs"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/unifi.yml"
    firewall_rules: tuple[FirewallRule, ...] = (
        FirewallRule(port=8080, proto="tcp", comment="UniFi device communication"),
        FirewallRule(port=8443, proto="tcp", comment="UniFi web admin"),
        FirewallRule(port=3478, proto="udp", comment="UniFi STUN"),
        FirewallRule(port=10001, proto="udp", comment="UniFi discovery"),
        FirewallRule(port=6789, proto="tcp", comment="UniFi speed test"),
    )
    stop_services: StrictBool = True
    services: tuple[ServiceName, ...] = ("unifi",)
    stop_mongod: StrictBool = True
    remove_service_units: StrictBool = True
    remove_packages: StrictBool = True
    unifi_packages: tuple[Package, ...] = ("unifi",)
    mongodb_packages: tuple[Package, ...] = (
        "mongodb-org",
        "mongodb-org-server",
        "mongodb-org-shell",
        "mongodb-org-mongos",
        "mongodb-org-tools",
    )
    java_packages: tuple[Package, ...] = ("openjdk-17-jre-headless",)
    manage_firewall: StrictBool = True
    manage_traefik: StrictBool = True
    delete_cache: StrictBool = True
    delete_logs: StrictBool = False
    delete_data: StrictBool = False
    delete_home: StrictBool = False
    delete_backup_dir: StrictBool = False
    remove_user: StrictBool = False
    remove_group: StrictBool = False
    drop_mongodb_database: StrictBool = False
    drop_mongodb_user: StrictBool = False
    mongodb_database: MongoName = "unifi"
    mongodb_user: MongoName = "unifi"
    mongodb_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.:-]+$")] = "127.0.0.1"
    mongodb_port: Port = 27017
    mongodb_auth_db: MongoName = "admin"
    # The role's pre-removal unifi_backup is not ported.
    trigger_backup: Literal[False] = False

    @model_validator(mode="before")
    @classmethod
    def dependent_paths(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        service = str(data.get("service_name", "unifi"))
        data.setdefault("home_dir", "/home/" + str(data.get("user", "unifi")))
        data.setdefault("cache_dir", str(data["home_dir"]) + "/cache")
        data.setdefault("data_dir", str(data.get("install_dir", "/usr/lib/unifi")) + "/data")
        data.setdefault("logs_dir", str(data.get("install_dir", "/usr/lib/unifi")) + "/logs")
        data.setdefault("backup_dir", str(data["data_dir"]) + "/backup")
        data.setdefault("systemd_unit_path", f"/etc/systemd/system/{service}.service")
        data.setdefault("mongodb_jvm_args_path", f"/etc/{service}-secrets/mongodb.jvmargs")
        data.setdefault("services", (service,))
        return data

    @model_validator(mode="after")
    def bounded(self) -> Self:
        for value in self.model_dump().values():
            if isinstance(value, str) and value.startswith("/"):
                path = PurePosixPath(value)
                if len(path.parts) < 3 or ".." in path.parts:
                    raise ValueError("removal paths must not be root, a top-level directory or contain traversal")
        if "root" in (self.user, self.group):
            raise ValueError("root cannot be the UniFi service account")
        return self


def _host(*args: str) -> str:
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", HOST, *args])


@operation()
def _purge(packages: tuple[str, ...]) -> Generator[Any, None, None]:
    # The apt module (state: absent, purge: true) at execution time: only names
    # dpkg knows; its apt-get command line.
    raw = probe(_host("packages", *packages), name="UniFi removal package state")
    try:
        selected = json.loads(raw) if raw is not None else None
    except ValueError:
        selected = None
    if not isinstance(selected, list) or any(name not in packages for name in selected):
        raise DeployError("Cannot establish the UniFi removal package state")
    if selected:
        yield StringCommand(
            shlex.join(
                [
                    "env",
                    "DEBIAN_FRONTEND=noninteractive",
                    "apt-get",
                    "-q",
                    "-y",
                    "-o",
                    "Dpkg::Options::=--force-confdef",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                    "--purge",
                    "remove",
                    "--",
                    *selected,
                ]
            )
        )


def _mongo(cfg: UnifiRemoveConfig, action: str, password: str) -> None:
    payload = {
        "action": action,
        "host": cfg.mongodb_host,
        "port": cfg.mongodb_port,
        "auth_db": cfg.mongodb_auth_db,
        "database": cfg.mongodb_database,
        "user": cfg.mongodb_user,
        "password": password,
    }
    secret_stdin(
        name=f"UniFi MongoDB {action} (failures ignored, as the role's)",
        command=_host("mongo"),
        content=SecretContent(json.dumps(payload)),
    )


@deploy("Remove UniFi")
def remove_unifi(cfg: UnifiRemoveConfig, secrets: SecretValues | None = None) -> None:
    """``secrets`` may hold ``mongodb_password``; without one the drops are skipped, as in the role."""

    if not cfg.confirm:
        raise DeployError("UniFi removal requires confirm=true")
    require_linux("UniFi removal")
    password = (secrets.get("mongodb_password") if secrets is not None else None) or ""
    if cfg.stop_services:
        for service in cfg.services:
            service_absent(
                name=f"Stop and disable {service}",
                service=service,
                label="UniFi removal",
                _ignore_errors=True,
            )
    if cfg.remove_service_units:
        absent(f"Remove {cfg.systemd_unit_path}", cfg.systemd_unit_path)
        absent(f"Remove {cfg.mongodb_jvm_args_path}", cfg.mongodb_jvm_args_path)
        secrets_dir = f"/etc/{cfg.service_name}-secrets"
        if str(PurePosixPath(cfg.mongodb_jvm_args_path).parent) == secrets_dir:
            absent(f"Remove {secrets_dir}", secrets_dir)
        systemd.daemon_reload(name="Reload systemd after the UniFi unit removal")
    if cfg.manage_traefik:
        absent(f"Remove {cfg.traefik_config_path}", cfg.traefik_config_path)
    # The role's condition: ansible_facts.os_family == "Debian", and ufw present.
    debian = cfg.manage_firewall and output("test -f /etc/debian_version && echo debian") == "debian"
    if debian and output("command -v ufw"):
        for rule in cfg.firewall_rules:
            server.shell(
                name=f"Remove the UniFi {rule.port}/{rule.proto} rule",
                commands=[f"ufw delete allow from any to any port {rule.port} proto {rule.proto}"],
                _ignore_errors=True,
            )
    if cfg.drop_mongodb_database and password:
        _mongo(cfg, "drop-database", password)
    if cfg.drop_mongodb_user and password:
        _mongo(cfg, "drop-user", password)
    if cfg.stop_mongod:
        service_absent(name="Stop and disable mongod", service="mongod", label="UniFi removal", _ignore_errors=True)
    if cfg.remove_packages:
        for kind, packages in (
            ("UniFi", cfg.unifi_packages),
            ("MongoDB", cfg.mongodb_packages),
            ("Java runtime", cfg.java_packages),
        ):
            _purge(name=f"Purge the {kind} packages", packages=packages)
    for path, enabled in (
        (cfg.cache_dir, cfg.delete_cache),
        (cfg.logs_dir, cfg.delete_logs),
        (cfg.backup_dir, cfg.delete_backup_dir),
        (cfg.data_dir, cfg.delete_data),
        (cfg.install_dir, cfg.delete_data),
        (cfg.home_dir, cfg.delete_home),
    ):
        if enabled:
            absent(f"Remove {path}", path)
    if cfg.remove_user:
        user_absent(name=f"Remove user {cfg.user}", user=cfg.user, remove_home=cfg.delete_home)
    if cfg.remove_group:
        server.group(name=f"Remove group {cfg.group}", group=cfg.group, present=False)
