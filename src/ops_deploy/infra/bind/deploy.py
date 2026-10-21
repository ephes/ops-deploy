"""Authoritative BIND (the ``bind_authoritative_deploy`` role).

Installs the packages, keeps ``named.conf``, ``named.conf.options``,
``named.conf.local`` and ``named.conf.keys`` byte-identical to the role's
templates, installs the static zone files from the controller, seeds dynamic
zone files once, keeps named enabled and running, reloads it after a change and
checks every authoritative zone with ``dig``.

All file changes go through one host-side transaction
(``files/bind_host.py apply``): new zone files pass ``named-checkzone`` first,
everything is renamed into place together, ``named-checkconf`` checks the
result, and a failure restores the previous files, so named is never reloaded
onto (or left with) a configuration that does not validate. A read-only probe
decides while planning whether that step is needed at all; a converged host
plans no mutating operation.

Dynamic zones (RFC 2136 ``UPDATE`` into a ``.jnl`` journal) are named's: their
file is only looked up, seeded when neither it nor its journal exists, and
never replaced, read or reset. The TSIG key file travels on stdin only and is
compared on the host; no secret, and no digest of one, is printed.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import SecretStr
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Which
from pyinfra.operations import apt, server, systemd

from ops_deploy.base._common import output, require_linux, require_systemd
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe
from ops_deploy.infra._common import directory
from ops_deploy.infra.bind.config import BindConfig, BindZone
from ops_deploy.infra.bind.render import (
    builtin_zones_file,
    keys_text,
    render_local,
    render_named_conf,
    render_options,
)
from ops_deploy.infra.postgres_install import missing_packages
from ops_deploy.ops.secret_file import secret_stdin

HOST_SCRIPT = (Path(__file__).parent / "files" / "bind_host.py").read_text()
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def host_command(action: str) -> str:
    """``files/bind_host.py <action>``, isolated from the host's Python setup (request on stdin)."""

    return shlex.join(["python3", "-I", "-c", HOST_SCRIPT, action])


def check_secrets(cfg: BindConfig, secrets: Mapping[str, SecretStr] | None) -> dict[str, SecretStr]:
    """Exactly one secret per configured key: base64, not empty, not a placeholder (never printed)."""

    given = dict(secrets or {})
    wanted = [key.name for key in cfg.tsig_keys]
    if sorted(given) != sorted(wanted):
        missing = sorted(set(wanted) - set(given))
        extra = sorted(set(given) - set(wanted))
        raise DeployError(f"bind: TSIG secrets must match the keys (missing: {missing}, unexpected: {extra})")
    for name, secret in given.items():
        value = secret.get_secret_value()
        if not value or value.upper() == "CHANGEME" or not _BASE64.fullmatch(value) or len(value) % 4:
            raise DeployError(
                f"bind: the secret of TSIG key {name} must be base64 key material from an encrypted source, "
                "not empty or a placeholder"
            )
    return given


def zone_sources(cfg: BindConfig) -> dict[str, bytes]:
    """Controller zone files by zone name (static and dynamic zones), as the role's validate.yml checks them."""

    base = Path(cfg.zone_files_dir)
    if not base.is_dir():
        raise DeployError(f"bind_zone_files_dir not found: {base}")
    wanted = [zone for zone in cfg.zones if not cfg.transfer_backed(zone)]
    missing = [zone.file for zone in wanted if not (base / zone.file).is_file()]
    if missing:
        raise DeployError(f"Missing zone files: {', '.join(missing)}")
    return {zone.name: (base / zone.file).read_bytes() for zone in wanted}


def distribution() -> tuple[str, int | None]:
    """Ansible's ``ansible_distribution`` (as the os-release ID) and major version."""

    text = output(
        '. /etc/os-release && printf "%s %s" "$ID" "${VERSION_ID:-$(cat /etc/debian_version 2>/dev/null)}"'
    ).strip()
    name, _, version = text.partition(" ")
    major = version.split(".", 1)[0]
    return ("Debian" if name == "debian" else name), (int(major) if major.isdigit() else None)


@dataclass(frozen=True)
class Candidate:
    path: str
    kind: str  # config | keys | zone | seed
    content: bytes
    user: str
    group: str
    mode: str
    zone: str | None = None


def candidates(
    cfg: BindConfig, builtin: str, secrets: Mapping[str, SecretStr], sources: Mapping[str, bytes]
) -> list[Candidate]:
    """The files in the role's order: keys, options, local, zones, seeds, named.conf."""

    owner = {"user": cfg.config_owner, "group": cfg.config_group}
    files: list[Candidate] = []
    if cfg.tsig_keys:
        keys = keys_text(cfg, secrets).encode()
        files.append(Candidate(cfg.keys_file, "keys", keys, mode=cfg.tsig_keys_mode, **owner))
    files.append(
        Candidate(
            f"{cfg.config_dir}/named.conf.options",
            "config",
            render_options(cfg).encode(),
            mode=cfg.config_mode,
            **owner,
        )
    )
    files.append(
        Candidate(
            f"{cfg.config_dir}/named.conf.local", "config", render_local(cfg).encode(), mode=cfg.config_mode, **owner
        )
    )
    seen: set[str] = set()
    for zone in cfg.static_zones():
        path = cfg.zone_path(zone)
        if path not in seen:  # zones sharing one file install it once
            seen.add(path)
            files.append(Candidate(path, "zone", sources[zone.name], mode=cfg.config_mode, zone=zone.name, **owner))
    for zone in cfg.dynamic_zones():
        files.append(
            Candidate(
                cfg.zone_path(zone),
                "seed",
                sources[zone.name],
                user=cfg.service_user,
                group=cfg.config_group,
                mode="0644",
                zone=zone.name,
            )
        )
    named_conf = render_named_conf(cfg, builtin).encode()
    files.append(Candidate(f"{cfg.config_dir}/named.conf", "config", named_conf, mode=cfg.config_mode, **owner))
    return files


def request(cfg: BindConfig, files: list[Candidate]) -> str:
    """The JSON both host commands read on stdin (it holds the key file: never log it)."""

    return json.dumps(
        {
            "files": [
                {
                    "path": item.path,
                    "kind": item.kind,
                    "zone": item.zone,
                    "user": item.user,
                    "group": item.group,
                    "mode": item.mode,
                    "data": base64.b64encode(item.content).decode("ascii"),
                }
                for item in files
            ],
            "remove": [] if cfg.tsig_keys else [cfg.keys_file],
            "named_conf": f"{cfg.config_dir}/named.conf",
            "keys_file": cfg.keys_file,
            "lock_dir": cfg.config_dir,
            "ufw": cfg.firewall_check_enabled,
        }
    )


def plan_changes(files: list[Candidate], state: Mapping[str, Any]) -> list[str]:
    """Paths the transaction will write or remove; refuses what it must not touch (before any change)."""

    if state["leftovers"]:
        raise DeployError(
            f"bind: {', '.join(state['leftovers'])} holds backups of an interrupted or unrestored run; check the "
            "configuration against them (named-checkconf), then remove the directory by hand"
        )
    found = state["files"]
    changes: list[str] = []
    for item in files:
        seen = found[item.path]
        if item.kind == "seed":
            if seen["state"] == "present":
                continue
            if seen["journal"]:
                raise DeployError(
                    f"bind: {item.path} is missing but its journal {item.path}.jnl exists; refusing to seed the "
                    "dynamic zone (named would refuse the out-of-sync journal). Restore the file or remove the "
                    "journal deliberately first."
                )
            changes.append(item.path)
            continue
        if seen["state"] == "other":
            raise DeployError(f"bind: {item.path} is not a regular file")
        if seen["state"] == "same" and seen["attrs"]:
            continue
        if item.kind == "zone" and seen["state"] != "same" and seen["journal"]:
            raise DeployError(f"bind: {item.path}.jnl exists; refusing to replace a zone file that has a journal")
        changes.append(item.path)
    for path, kind in state["remove"].items():
        if kind == "other":
            raise DeployError(f"bind: {path} is not a regular file")
        if kind == "file":
            changes.append(path)
    return changes


def _verify(cfg: BindConfig, zone: BindZone) -> None:
    dig = shlex.join(["dig", f"@{cfg.verify_server}", zone.name, "SOA", "+comments", "+norecurse"])
    message = shlex.quote(f"{zone.name}: no authoritative NOERROR answer from {cfg.verify_server}")
    script = (
        f"i=0; while [ $i -lt {cfg.verify_retries} ]; do i=$((i+1)); out=$({dig} 2>&1); "
        "if printf '%s\\n' \"$out\" | grep -q 'status: NOERROR' "
        "&& printf '%s\\n' \"$out\" | grep -Eq 'flags:[^;]* aa[ ;]'; then exit 0; fi; "
        f"[ $i -lt {cfg.verify_retries} ] && sleep {cfg.verify_delay}; done; echo {message} >&2; exit 1"
    )
    mark_read_only(server.shell(name=f"Verify authoritative answers for {zone.name}", commands=[script]))


def _firewall(state: Mapping[str, Any]) -> None:
    ufw = state.get("ufw")
    if ufw == "inactive":
        logger.warning(f"{host.print_prefix}WARNING: UFW is inactive; ensure TCP/UDP 53 is allowed by other firewalls.")
    elif ufw == "active-no-53":
        logger.warning(f"{host.print_prefix}WARNING: UFW is active but no explicit TCP/UDP 53 rule was found.")


@deploy("BIND authoritative")
def deploy_bind(cfg: BindConfig, tsig_secrets: Mapping[str, SecretStr] | None = None) -> None:
    """Deploy the role's configuration; see the module docstring."""

    if not cfg.enabled:
        return
    require_linux("bind")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("bind needs a Debian-family host")
    require_systemd("bind")
    secrets = check_secrets(cfg, tsig_secrets)
    sources = zone_sources(cfg)
    name, major = distribution()
    files = candidates(cfg, builtin_zones_file(cfg, name, major), secrets, sources)
    payload = request(cfg, files)

    found = probe(host_command("probe"), name="BIND files", stdin=payload)
    if found is None:
        raise DeployError("bind: the read-only file probe failed; nothing was changed")
    try:
        state = json.loads(found)
        changes = plan_changes(files, state)
    except (ValueError, KeyError, TypeError):
        raise DeployError("bind: the file probe printed something unexpected") from None

    missing = missing_packages(cfg.packages)
    if missing:
        apt.packages(name="Install BIND packages", packages=missing, update=True, cache_time=3600)
    directory(cfg.config_dir, user=cfg.config_owner, group=cfg.config_group, mode="0755")
    if cfg.needs_working_dir:
        directory(cfg.working_dir, user=cfg.service_user, group=cfg.config_group, mode="0775")
    if cfg.needs_dynamic_dir:
        directory(cfg.dynamic_zone_dir, user=cfg.service_user, group=cfg.config_group, mode="0775")

    install = None
    if changes:
        # The request holds the key file: secret_stdin keeps it off the command line and
        # out of the operation's arguments.
        install = secret_stdin(
            name="Install the BIND configuration (validated, restored on failure)",
            command=host_command("apply"),
            content=SecretContent(payload),
        )
    systemd.service(
        name=f"Ensure {cfg.service_name} is enabled and running",
        service=cfg.service_name,
        running=True,
        enabled=True,
    )
    if install is not None:
        server.shell(
            name=f"Reload {cfg.service_name}",
            commands=[shlex.join(["systemctl", "reload", cfg.service_name])],
            _if=install.did_change,
        )
    if cfg.verify_enabled:
        for zone in cfg.zones:
            if cfg.zone_type(zone) in cfg.verify_zone_types:
                _verify(cfg, zone)
    if cfg.firewall_check_enabled:
        _firewall(state)
