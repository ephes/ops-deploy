"""Authoritative BIND (the ``bind_authoritative_deploy`` role).

Does what the role does, in its order: installs the packages, ensures the
directories, keeps ``named.conf.keys``, ``named.conf.options``,
``named.conf.local``, the static zone files and ``named.conf`` equal to the
role's output, seeds dynamic zone files once, removes the key file when no
key is configured, keeps named enabled and running, reloads it after a change
and checks every authoritative zone with ``dig``. ``named.conf`` includes the
package's builtin zones as the host's release ships them
(``named.conf.root-hints`` on Debian 13 and Ubuntu 26.04 and later,
``named.conf.default-zones`` before), falling back to the one of the two that
exists when the release's file is missing (:func:`choose_builtin_zones_file`).

The files are compared and installed by one small host script
(``files/bind_config.sh``, standard tools only). It checks every candidate
before the first file is touched: ``named-checkzone`` for changed zone files
and ``named-checkconf -t`` on a copy of the configuration tree with the
candidates in place. Only then are the changed files renamed into place, so a
configuration named rejects leaves the installed files as they were and is
never reloaded. Differences from the role, all refusals: only the role's
default paths and ``db.*`` zone files of their own (:func:`check_layout`); a
changed static zone needs a greater serial; a dynamic zone file is not seeded
next to a leftover journal; a static zone file with a journal is not
replaced; managed paths must be regular files. There is no rollback: an I/O
error during the renames leaves the files installed so far (each one checked
as part of the whole set), as the role would, and the next run installs the
rest.

Dynamic zones (RFC 2136 ``UPDATE`` into a ``.jnl`` journal) are named's: an
existing file is never read, replaced or chmodded and its journal is never
touched. The TSIG key file travels on stdin only and is compared on the host;
no secret, and no digest of one, is printed. A reload a run never reached is
caught by the next run, which reloads when an installed file is newer than
named's last configuration load (``rndc status``).
"""

from __future__ import annotations

import base64
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

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
    DEFAULT_ZONES,
    ROOT_HINTS,
    builtin_zones_file,
    keys_text,
    render_local,
    render_named_conf,
    render_options,
)
from ops_deploy.ops.secret_file import secret_stdin

HOST_SCRIPT = (Path(__file__).parent / "files" / "bind_config.sh").read_text()
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
# The role's default paths: the only layout this deploy writes into.
DEFAULT_PATHS = {"config_dir": "/etc/bind", "working_dir": "/var/cache/bind", "dynamic_zone_dir": "/var/lib/bind"}
# "db." and dot-separated labels (Debian's naming): never a named.conf* file,
# rndc.key, bind.keys, zones.rfc1918 or a staged ".ops-deploy-new." file.
_ZONE_FILE = re.compile(r"db\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*")
# The zone files the bind9 package ships in /etc/bind up to Debian 12 and Ubuntu 24.04, which its
# named.conf.default-zones loads. Debian 13 and Ubuntu 26.04 ship none (a release upgrade may leave
# them behind); refused on every release, before the host is contacted, so a configuration stays
# valid across the upgrade.
PACKAGED_ZONE_FILES = ("db.0", "db.127", "db.255", "db.empty", "db.local")


def check_layout(cfg: BindConfig) -> None:
    """Refuse other paths than the role's defaults and zone files that are not ``db.*`` names of their own.

    Every file the deploy writes or removes is then one of the four
    ``named.conf`` files in ``/etc/bind``, a static zone file there, or a
    dynamic zone file it seeds (never replaces) in ``/var/lib/bind``. Each zone
    file name (all zone types) is used once, holds no ``.jnl`` and is not one
    of the package's zone files, so no two of these files are one file, and
    none of them is the builtin zones file, a staged file, a journal or a zone
    file of the package. Checked before the host is contacted.
    """

    moved = [name for name, path in DEFAULT_PATHS.items() if getattr(cfg, name) != path]
    if cfg.tsig_keys_file not in (None, f"{DEFAULT_PATHS['config_dir']}/named.conf.keys"):
        moved.append("tsig_keys_file")
    if cfg.builtin_zones_file is not None:
        moved.append("builtin_zones_file")
    if moved:
        raise DeployError(
            f"bind: only the role's default paths are supported, refusing the changed {', '.join(moved)} "
            "(deploy such a host with the role)"
        )
    files = [zone.file for zone in cfg.zones]
    refused = sorted(
        {
            name
            for name in files
            if not _ZONE_FILE.fullmatch(name) or name in PACKAGED_ZONE_FILES or ".jnl" in name or files.count(name) > 1
        }
    )
    if refused:
        raise DeployError(
            "bind: each zone needs a db.* file name of its own, without .jnl and none of "
            f"{', '.join(PACKAGED_ZONE_FILES)} (the package's zone files): {', '.join(refused)}"
        )


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


# dpkg states (second letter of db:Status-Abbrev) in which a package's files are all unpacked:
# installed, and the unpacked, half-configured and trigger states a release upgrade can leave.
_UNPACKED = frozenset("iUFWt")


def missing_packages(packages: tuple[str, ...]) -> list[str]:
    """``packages`` that are neither unpacked nor provided by an unpacked package (to install with apt).

    ``postgres_install.missing_packages`` with one difference: a package dpkg has
    unpacked but not configured (``iU``, ``iF``, ``iW``, ``it``) counts as there.
    A release upgrade leaves ``bind9`` half-configured while ``named.conf``
    still includes a file the new package removed; ``apt-get install`` would
    first re-run its failing configure script and stop before this deploy
    installs the configuration that lets it succeed. Hosts whose packages are
    all installed (``ii``) or absent get the same answer as before.
    """

    have: set[str] = set()
    query = "dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Provides}\\n'"
    for line in output(query).splitlines():
        status, _, rest = line.partition("|")
        if len(status) < 2 or status[0] != "i" or status[1] not in _UNPACKED:
            continue
        name, _, provides = rest.partition("|")
        have.add(name)
        have.update(item.split()[0] for item in provides.split(",") if item.strip())
    return [package for package in packages if package not in have]


def builtin_files_present(cfg: BindConfig) -> frozenset[str]:
    """Which of ``named.conf.default-zones`` and ``named.conf.root-hints`` exist in ``config_dir`` (read-only)."""

    names = (DEFAULT_ZONES, ROOT_HINTS)
    found = output(
        f"for name in {' '.join(names)}; do "
        f'if [ -f {shlex.quote(cfg.config_dir)}/"$name" ]; then echo "$name"; fi; done'
    )
    return frozenset(line for line in found.split() if line in names)


def choose_builtin_zones_file(cfg: BindConfig) -> str:
    """The builtin-zones include for this host: its release, or the packaged file present (see render)."""

    name, major = distribution()
    by_release = builtin_zones_file(cfg, name, major)
    chosen = builtin_zones_file(cfg, name, major, builtin_files_present(cfg))
    if chosen != by_release:
        logger.warning(
            f"{host.print_prefix}bind: {by_release} (the choice for {name} {major}) is missing; "
            f"including {chosen}, which exists"
        )
    return chosen


@dataclass(frozen=True)
class Entry:
    """One file for the host script: what it is, where, owner and mode, and its content."""

    kind: str  # config | keys | zone | seed | absent
    path: str
    content: bytes = b""
    user: str = "-"
    group: str = "-"
    mode: str = "-"
    zone: str = "-"


def entries(
    cfg: BindConfig, builtin: str, secrets: Mapping[str, SecretStr], sources: Mapping[str, bytes]
) -> list[Entry]:
    """The files in the role's order: keys, options, local, zones, seeds, named.conf, key file removal."""

    owner = {"user": cfg.config_owner, "group": cfg.config_group, "mode": cfg.config_mode}
    files: list[Entry] = []
    if cfg.tsig_keys:
        keys = keys_text(cfg, secrets).encode()
        files.append(
            Entry("keys", cfg.keys_file, keys, cfg.config_owner, cfg.config_group, cfg.tsig_keys_mode),
        )
    files.append(Entry("config", f"{cfg.config_dir}/named.conf.options", render_options(cfg).encode(), **owner))
    files.append(Entry("config", f"{cfg.config_dir}/named.conf.local", render_local(cfg).encode(), **owner))
    for zone in cfg.static_zones():
        files.append(Entry("zone", cfg.zone_path(zone), sources[zone.name], zone=zone.name, **owner))
    for zone in cfg.dynamic_zones():
        seed = sources[zone.name]
        files.append(Entry("seed", cfg.zone_path(zone), seed, cfg.service_user, cfg.config_group, "0644", zone.name))
    named_conf = render_named_conf(cfg, builtin).encode()
    files.append(Entry("config", f"{cfg.config_dir}/named.conf", named_conf, **owner))
    if not cfg.tsig_keys:
        files.append(Entry("absent", cfg.keys_file))
    return files


def host_command(cfg: BindConfig, mode: str, files: list[Entry]) -> str:
    """The host script's command line: paths, owners, modes and sizes only, never content."""

    args = [mode, cfg.config_dir, cfg.working_dir, cfg.service_name, cfg.keys_file]
    for item in files:
        size = "-" if item.kind == "absent" else str(len(item.content))
        args += [item.kind, item.path, item.zone, item.user, item.group, item.mode, size]
    return shlex.join(["bash", "-c", HOST_SCRIPT, "bind-config", *args])


def payload(files: list[Entry]) -> str:
    """The host script's stdin: one base64 line per file (it holds the key file: never log it)."""

    return "".join(base64.b64encode(item.content).decode("ascii") + "\n" for item in files if item.kind != "absent")


@dataclass(frozen=True)
class Plan:
    changes: tuple[str, ...]
    leftovers: tuple[str, ...]
    reload_pending: bool


def read_probe(found: str) -> Plan:
    """The probe's answer; refusals stop the deploy before any operation runs."""

    changes: list[str] = []
    leftovers: list[str] = []
    refusals: list[str] = []
    pending = False
    for line in found.splitlines():
        word, _, rest = line.partition(" ")
        if word == "change":
            changes.append(rest)
        elif word == "leftover":
            leftovers.append(rest)
        elif word == "refuse":
            refusals.append(rest)
        elif line == "reload-pending":
            pending = True
        elif line:
            raise DeployError("bind: the file probe printed something unexpected")
    if refusals:
        raise DeployError("bind: refusing to change anything:\n" + "\n".join(refusals))
    return Plan(tuple(changes), tuple(leftovers), pending)


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


def _firewall() -> None:
    status = output("if command -v ufw >/dev/null 2>&1; then ufw status verbose; fi")
    if "Status: inactive" in status:
        logger.warning(f"{host.print_prefix}WARNING: UFW is inactive; ensure TCP/UDP 53 is allowed by other firewalls.")
    elif "Status: active" in status and "53/tcp" not in status and "53/udp" not in status:
        logger.warning(f"{host.print_prefix}WARNING: UFW is active but no explicit TCP/UDP 53 rule was found.")


@deploy("BIND authoritative")
def deploy_bind(cfg: BindConfig, tsig_secrets: Mapping[str, SecretStr] | None = None) -> None:
    """Deploy the role's configuration; see the module docstring."""

    if not cfg.enabled:
        return
    check_layout(cfg)
    require_linux("bind")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("bind needs a Debian-family host")
    require_systemd("bind")
    secrets = check_secrets(cfg, tsig_secrets)
    sources = zone_sources(cfg)
    files = entries(cfg, choose_builtin_zones_file(cfg), secrets, sources)
    stdin = payload(files)

    found = probe(host_command(cfg, "probe", files), name="BIND files", stdin=stdin)
    if found is None:
        raise DeployError("bind: the read-only file probe failed; nothing was changed")
    plan = read_probe(found)

    missing = missing_packages(cfg.packages)
    if missing:
        apt.packages(name="Install BIND packages", packages=missing, update=True, cache_time=3600)
    directory(cfg.config_dir, user=cfg.config_owner, group=cfg.config_group, mode="0755")
    if cfg.needs_working_dir:
        directory(cfg.working_dir, user=cfg.service_user, group=cfg.config_group, mode="0775")
    if cfg.needs_dynamic_dir:
        directory(cfg.dynamic_zone_dir, user=cfg.service_user, group=cfg.config_group, mode="0775")

    if plan.changes or plan.leftovers:
        # The key file travels on stdin: secret_stdin keeps it off the command line
        # and out of the operation's arguments.
        secret_stdin(
            name="Install the BIND configuration (validated first)",
            command=host_command(cfg, "apply", files),
            content=SecretContent(stdin),
        )
    systemd.service(
        name=f"Ensure {cfg.service_name} is enabled and running",
        service=cfg.service_name,
        running=True,
        enabled=True,
    )
    if plan.changes or plan.reload_pending:
        # Under the host script's lock: named never loads the tree while another run renames files.
        reload = ["flock", "-w", "120", cfg.config_dir, "systemctl", "reload", cfg.service_name]
        server.shell(name=f"Reload {cfg.service_name}", commands=[shlex.join(reload)])
    if cfg.verify_enabled:
        for zone in cfg.zones:
            if cfg.zone_type(zone) in cfg.verify_zone_types:
                _verify(cfg, zone)
    if cfg.firewall_check_enabled:
        _firewall()
