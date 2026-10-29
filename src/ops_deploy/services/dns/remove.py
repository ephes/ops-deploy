"""The original confirmed DNS/DDNS removal and optional resolver restoration."""

from __future__ import annotations

import json
import re
import shlex
import stat
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Self, cast

from pydantic import Field, ValidationInfo, field_validator, model_validator
from pyinfra import logger
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server, systemd

from ops_deploy.base._common import RoleConfig, require_linux, require_systemd
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, stdin_arguments

SCRIPT = (Path(__file__).parent / "files/remove_state.py").read_text()
UNITS = (
    "unbound.service",
    "unbound-blocklist.timer",
    "unbound-blocklist.service",
    "ddns-update.timer",
    "ddns-status-endpoint.service",
    "ddns-update.service",
)
UNIT_FILES = tuple(
    "/etc/systemd/system/" + unit
    for unit in (
        "ddns-update.service",
        "ddns-update.timer",
        "ddns-status-endpoint.service",
        "pihole-FTL.service",
        "pihole-FTL-prestart.service",
        "pihole-FTL-poststop.service",
    )
)
LEFTOVERS = (
    "/var/cache/unbound",
    "/var/log/unbound",
    "/run/unbound",
    "/etc/.pihole",
    "/etc/bash_completion.d/pihole",
    "/etc/unbound",
    "/var/lib/unbound",
)
RESOLVED_FILE = "/lib/systemd/system/systemd-resolved.service"
FALLBACK = "# Fallback DNS configuration\nnameserver 1.1.1.1\nnameserver 1.0.0.1\nnameserver 8.8.8.8\n"


SpacedAbsolutePath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/ +\-]*$")]


class DnsRemoveConfig(RoleConfig):
    confirm: bool = False
    restore_systemd_resolved: bool = True
    unbound_config_dir: SpacedAbsolutePath = "/etc/unbound/unbound.conf.d"
    unbound_lib_dir: SpacedAbsolutePath = "/var/lib/unbound"
    ddns_script_path: SpacedAbsolutePath = "/usr/local/bin/ddns-update"
    ddns_config_dir: SpacedAbsolutePath = "/etc/ddns"
    ddns_log_dir: SpacedAbsolutePath = "/var/log/ddns"
    ddns_state_dir: SpacedAbsolutePath = "/var/lib/ddns"
    ddns_status_endpoint_server_path: SpacedAbsolutePath = "/usr/local/bin/ddns_status_httpd.py"
    ddns_status_endpoint_htpasswd_dir: SpacedAbsolutePath = "/etc/ddns-status-endpoint"

    @field_validator(
        "unbound_config_dir",
        "unbound_lib_dir",
        "ddns_script_path",
        "ddns_config_dir",
        "ddns_log_dir",
        "ddns_state_dir",
        "ddns_status_endpoint_server_path",
        "ddns_status_endpoint_htpasswd_dir",
    )
    @classmethod
    def canonical_path(cls, value: str, info: ValidationInfo) -> str:
        if ".." in PurePosixPath(value).parts:
            raise ValueError("DNS removal paths cannot contain parent traversal")
        # The original role applies its state-directory guard to the literal
        # variable. Stripping a trailing slash/dot could turn a skip into deletion.
        if info.field_name == "ddns_state_dir":
            return value
        return str(PurePosixPath(value))

    @model_validator(mode="after")
    def resource_paths(self) -> Self:
        protected = {"/", "/etc", "/var", "/usr", "/tmp", "/var/lib", "/var/log", "/usr/local", "/usr/local/bin"}
        for name, value in self.model_dump().items():
            if isinstance(value, str) and value in protected and name != "ddns_state_dir":
                raise ValueError(f"{name} must identify a declared DNS resource")
        return self


def selected_paths(cfg: DnsRemoveConfig) -> list[str]:
    paths = [
        cfg.unbound_config_dir,
        cfg.unbound_lib_dir,
        cfg.ddns_script_path,
        cfg.ddns_config_dir,
        cfg.ddns_log_dir,
        cfg.ddns_status_endpoint_server_path,
        cfg.ddns_status_endpoint_htpasswd_dir,
        "/usr/local/bin/ddns-update.sh",
        *UNIT_FILES,
        *LEFTOVERS,
    ]
    # Exact original role condition; a shared non-ddns state path is retained.
    if re.fullmatch(r"/.+/[^/]*ddns[^/]*", cfg.ddns_state_dir):
        paths.append(cfg.ddns_state_dir)
    return list(dict.fromkeys(paths))


def _command(action: str) -> str:
    return shlex.join(["python3", "-I", "-c", SCRIPT, action])


def _state(cfg: DnsRemoveConfig) -> dict[str, Any]:
    request = {
        "paths": [*selected_paths(cfg), RESOLVED_FILE, "/etc/resolv.conf"],
        "units": [*UNITS, "systemd-resolved.service"],
    }
    value = probe(_command("snapshot"), name="DNS removal selected metadata", stdin=json.dumps(request))
    try:
        state = json.loads(value) if value is not None else None
    except ValueError:
        state = None
    if not isinstance(state, dict) or set(state) != {"paths", "units", "account", "package", "ufw", "cron"}:
        raise DeployError("Cannot establish DNS removal state before mutation")
    if not isinstance(state["paths"], dict) or set(state["paths"]) != set(request["paths"]):
        raise DeployError("DNS removal metadata paths do not match the declared resources")
    if not isinstance(state["units"], dict) or set(state["units"]) != set(request["units"]):
        raise DeployError("DNS removal metadata units do not match the declared services")
    for details in state["paths"].values():
        if details is not None and (
            not isinstance(details, dict)
            or set(details) != {"mode", "uid", "gid"}
            or any(type(value) is not int or value < 0 for value in details.values())
        ):
            raise DeployError("DNS removal path metadata is malformed")
    for details in state["units"].values():
        if not isinstance(details, dict) or details.get("metadata_status") not in {"ok", "error"}:
            raise DeployError("DNS removal unit metadata is malformed")
        if details["metadata_status"] == "ok" and any(
            not isinstance(details.get(key), str) for key in ("LoadState", "ActiveState", "UnitFileState")
        ):
            raise DeployError("DNS removal unit metadata is incomplete")
    if state["account"] not in {"present", "absent", "unknown"} or state["package"] not in {
        "installed",
        "config-files",
        "not-installed",
        "unpacked",
        "half-installed",
        "half-configured",
        "triggers-awaited",
        "triggers-pending",
    }:
        raise DeployError("DNS removal account/package state is unknown")
    for key, admitted in (
        ("ufw", {"53/tcp", "53/udp", "4711/tcp", "5335/tcp", "5335/udp"}),
        ("cron", {"Pi-hole gravity update", "Pi-hole flush logs", "Unbound root hints update"}),
    ):
        details = state[key]
        if (
            not isinstance(details, dict)
            or set(details) != {"status", "selected"}
            or details["status"] not in {"ok", "error", "unavailable"}
            or not isinstance(details["selected"], list)
            or any(not isinstance(item, str) or item not in admitted for item in details["selected"])
        ):
            raise DeployError("DNS removal optional cleanup metadata is malformed")
    return cast("dict[str, Any]", state)


@deploy("Remove original DNS services")
def deploy_dns_remove(cfg: DnsRemoveConfig) -> None:
    if not cfg.confirm:
        raise DeployError("dns_remove: removal not confirmed; set confirm to remove DNS services")
    require_linux("dns_remove")
    require_systemd("dns_remove")
    state = _state(cfg)
    unknown_units = False
    for unit in UNITS:
        current = state["units"][unit]
        unknown = current.get("metadata_status") != "ok"
        unknown_units |= unknown
        commands = []
        if unknown or current.get("ActiveState") in {"active", "activating", "reloading", "deactivating"}:
            commands.append("timeout 30s systemctl stop " + shlex.quote(unit) + " || true")
            if unit == "unbound.service":
                commands.append(
                    "if systemctl is-active unbound >/dev/null 2>&1; then systemctl kill -s KILL unbound || true; fi"
                )
        if unknown or current.get("UnitFileState") in {"enabled", "enabled-runtime", "linked", "linked-runtime"}:
            commands.append("systemctl disable " + shlex.quote(unit) + " || true")
        if commands:
            server.shell(name=f"Original tolerant stop/disable {unit}", commands=commands)

    def remove_paths(paths: list[str] | tuple[str, ...], *, after_purge: bool = False) -> None:
        for path in dict.fromkeys(paths):
            if state["paths"][path] is not None or after_purge:
                server.shell(name=f"Remove declared DNS resource {path}", commands=["rm -rf -- " + shlex.quote(path)])

    ddns_paths = [
        *UNIT_FILES[:3],
        cfg.ddns_script_path,
        "/usr/local/bin/ddns-update.sh",
        cfg.ddns_status_endpoint_server_path,
        cfg.ddns_status_endpoint_htpasswd_dir,
        cfg.ddns_config_dir,
        cfg.ddns_log_dir,
    ]
    if re.fullmatch(r"/.+/[^/]*ddns[^/]*", cfg.ddns_state_dir):
        ddns_paths.append(cfg.ddns_state_dir)
    remove_paths(ddns_paths)
    if state["account"] != "absent":
        server.shell(
            name="Remove original ddns account/home with source error tolerance",
            commands=["userdel --remove ddns || true"],
        )
    changed_ddns_units = any(state["paths"][p] is not None for p in UNIT_FILES[:3])
    if changed_ddns_units:
        systemd.daemon_reload(name="Reload systemd after original removed DDNS units")
    remove_paths([cfg.unbound_config_dir, cfg.unbound_lib_dir])
    removing_package = state["package"] != "not-installed"
    if removing_package:
        server.shell(
            name="Purge original Unbound package including residual configuration",
            commands=["apt-get -y -q remove --purge unbound"],
        )
    # Package postrm may leave paths that were absent while planning. Keep that
    # possible first-run cleanup explicit; repeat has neither package nor paths.
    remove_paths(LEFTOVERS[:3], after_purge=removing_package)
    ufw = state["ufw"]
    if ufw["status"] != "unavailable":
        rules = ufw["selected"] if ufw["status"] == "ok" else ["53/tcp", "53/udp", "4711/tcp", "5335/tcp", "5335/udp"]
        for rule in rules:
            server.shell(
                name=f"Original tolerant removal of named DNS UFW allow {rule}",
                commands=["ufw delete allow " + shlex.quote(rule) + " || true"],
            )
    if cfg.restore_systemd_resolved:
        if state["paths"][RESOLVED_FILE] is not None:
            systemd.service(
                name="Restore original systemd-resolved enable/start policy",
                service="systemd-resolved",
                running=True,
                enabled=True,
            )
            # A TCP connect to the original local listener, never a DNS query.
            wait = """import socket,time
deadline=time.monotonic()+30
time.sleep(2)
while time.monotonic()<deadline:
    try:
        connection=socket.create_connection(('127.0.0.53',53),timeout=1)
        connection.close()
        break
    except OSError:
        time.sleep(1)
else:
    raise SystemExit(1)
"""
            mark_read_only(
                server.shell(
                    name="Original tolerated local resolved listener wait",
                    commands=[shlex.join(["python3", "-I", "-c", wait])],
                    _ignore_errors=True,
                )
            )
            files.link(
                name="Restore original resolved stub symlink",
                path="/etc/resolv.conf",
                target="/run/systemd/resolve/stub-resolv.conf",
                force=True,
                force_backup=False,
            )
        else:
            prior = state["paths"]["/etc/resolv.conf"]
            if prior is not None and stat.S_ISLNK(prior["mode"]):
                files.link(
                    name="Replace original resolver symlink for fallback", path="/etc/resolv.conf", present=False
                )
            files.put(
                name="Restore original fixed fallback resolver",
                src=StringIO(FALLBACK),
                dest="/etc/resolv.conf",
                mode="0644",
            )
    cron = state["cron"]
    if cron["status"] == "ok" and cron["selected"]:
        server.shell(
            name="Remove only the three original Ansible root cron entries",
            commands=[_command("clean-cron")],
            **stdin_arguments("{}"),
            _ignore_errors=True,
        )
    elif cron["status"] != "ok":
        logger.warning("Original optional DNS root cron cleanup unavailable; no absence is inferred")
    remove_paths([*UNIT_FILES[3:], *LEFTOVERS[3:]], after_purge=removing_package)
    # The original role retains stopped/disabled blocklist unit files. Their
    # loaded presence alone does not require a reload on an already-gone repeat.
    if unknown_units or removing_package or any(state["paths"][p] is not None for p in UNIT_FILES):
        systemd.daemon_reload(name="Final reload after original removed DNS units")
