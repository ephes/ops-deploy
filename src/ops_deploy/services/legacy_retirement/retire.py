"""Explicit retirement of unmanaged legacy accounts, units, paths and PostgreSQL databases.

Nothing here is a port of a role: it removes what predates the declared
deploys, after archiving it on the host. Never part of a normal deploy.

Order: archive everything that still exists, then remove. Each archive is
written to a ``.partial`` name, checked and renamed, mode ``0600`` in a
``0700`` root-owned directory; an existing archive is never replaced (it was
written before any removal, so it already holds whatever is still left).
Nothing that runs is stopped or killed: a listed account with processes, a
lingering user manager or a crontab, a listed unit that is not inactive, and a
listed database with connections fail the deploy while planning, before any
change, and the removal commands check processes and connections again.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from importlib.resources import files as resources
from pathlib import PurePosixPath
from typing import Annotated, Any, Self

from pydantic import Field, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux, require_systemd
from ops_deploy.core.config import UnixUser
from ops_deploy.helpers.probes import probe
from ops_deploy.services._lifecycle import remove_path

RESOURCE = resources("ops_deploy.services.legacy_retirement")
SYSTEM_UNITS = "/etc/systemd/system"
# Never retired, whatever a config lists.
ALWAYS_PROTECTED = frozenset({"root", "postgres", "nobody", "www-data", "daemon", "sshd"})
# System groups never removed, whatever a config lists.
PROTECTED_GROUPS = frozenset(
    {"adm", "sudo", "wheel", "staff", "users", "shadow", "systemd-journal", "docker", "ssh", "ssl-cert", "postgres"}
)
RESERVED_DATABASES = frozenset({"postgres", "template0", "template1"})
INACTIVE = frozenset({"inactive", "failed"})
UnitFile = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+\.(service|timer|socket|path)$")]
SqlName = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]{0,62}$")]


class RetiredDatabase(RoleConfig):
    """A PostgreSQL database and the role that owns it; both are dropped after a dump."""

    name: SqlName
    owner: SqlName

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if self.name in RESERVED_DATABASES or self.owner == "postgres":
            raise ValueError("legacy retirement refuses a reserved database or the postgres role")
        return self


class LegacyRetirementConfig(RoleConfig):
    archive_dir: AbsolutePath
    accounts: tuple[UnixUser, ...] = ()
    # Groups removed after the accounts; only while no remaining account has
    # one as its primary group or is a member.
    groups: tuple[UnixUser, ...] = ()
    units: tuple[UnitFile, ...] = ()
    paths: tuple[AbsolutePath, ...] = ()
    databases: tuple[RetiredDatabase, ...] = ()
    protected_accounts: tuple[UnixUser, ...] = ()
    # Lowest uid an account may have; system accounts are never retired here.
    min_uid: int = Field(default=1000, ge=1000)

    @model_validator(mode="after")
    def bounded(self) -> Self:
        root = PurePosixPath(self.archive_dir)
        if str(root) != self.archive_dir or ".." in root.parts or root.parent != PurePosixPath("/var/backups"):
            raise ValueError("archive_dir must be a directory directly below /var/backups")
        for name, items in (
            ("accounts", self.accounts),
            ("units", self.units),
            ("paths", self.paths),
            ("databases", tuple(item.name for item in self.databases)),
        ):
            if len(set(items)) != len(items):
                raise ValueError(f"legacy retirement {name} have duplicates")
        if set(self.accounts) & (ALWAYS_PROTECTED | set(self.protected_accounts)):
            raise ValueError("legacy retirement refuses a protected account")
        for path in self.paths:
            parts = PurePosixPath(path).parts
            # Three levels deep, or an application directory directly in /opt or /srv.
            deep_enough = len(parts) >= 4 or (len(parts) == 3 and parts[1] in ("opt", "srv"))
            if str(PurePosixPath(path)) != path or ".." in parts or not deep_enough:
                raise ValueError("paths must be canonical and three levels deep (two below /opt or /srv)")
            if parts[1] in ("home", "proc", "sys", "dev", "run") or PurePosixPath(path).is_relative_to(root):
                raise ValueError("paths may not lie below /home (accounts), a kernel filesystem or the archive")
            if PurePosixPath(path).is_relative_to(SYSTEM_UNITS):
                raise ValueError("unit files are retired through units, not paths")
        if len(set(self.groups)) != len(self.groups):
            raise ValueError("legacy retirement groups have duplicates")
        if set(self.groups) & (ALWAYS_PROTECTED | PROTECTED_GROUPS | set(self.protected_accounts)):
            raise ValueError("legacy retirement refuses a protected group")
        if not (self.accounts or self.units or self.paths or self.databases or self.groups):
            raise ValueError("legacy retirement lists nothing")
        return self

    def home_archive(self, user: str) -> str:
        return f"home-{user}.tar.gz"

    def dump_archive(self, database: str) -> str:
        return f"postgres-{database}.dump"

    def source_archive(self, path: str) -> str:
        """One archive per unit file, drop-in directory or path, so each removal checks its own."""

        digest = hashlib.sha256(path.encode()).hexdigest()[:12]
        return f"path-{PurePosixPath(path).name}-{digest}.tar.gz"

    def unit_sources(self, unit: str) -> list[str]:
        return [f"{SYSTEM_UNITS}/{unit}", f"{SYSTEM_UNITS}/{unit}.d"]

    def archives(self) -> list[str]:
        return [
            *(self.home_archive(user) for user in self.accounts),
            *(self.dump_archive(item.name) for item in self.databases),
            *(self.source_archive(path) for unit in self.units for path in self.unit_sources(unit)),
            *(self.source_archive(path) for path in self.paths),
        ]


def probe_command(cfg: LegacyRetirementConfig) -> str:
    source = base64.b64encode(RESOURCE.joinpath("files/legacy_retirement_probe.py").read_bytes()).decode()
    request = {
        "archive_dir": cfg.archive_dir,
        "accounts": list(cfg.accounts),
        "units": list(cfg.units),
        "groups": list(cfg.groups),
        "paths": list(cfg.paths),
        "archives": cfg.archives(),
        "databases": [item.model_dump() for item in cfg.databases],
    }
    code = f"import base64;exec(compile(base64.b64decode('{source}'),'<legacy-retirement-probe>','exec'))"
    return shlex.join(["python3", "-I", "-B", "-c", code, json.dumps(request, sort_keys=True)])


def host_state(cfg: LegacyRetirementConfig) -> dict[str, Any]:
    result = probe(probe_command(cfg), name="legacy retirement state")
    try:
        state = json.loads(result or "")
        if not isinstance(state, dict) or set(state) != {
            "accounts",
            "units",
            "groups",
            "paths",
            "archives",
            "postgres",
            "databases",
        }:
            raise ValueError
    except ValueError:
        raise DeployError("Cannot read the legacy retirement state; nothing was changed") from None
    return state


def refuse(cfg: LegacyRetirementConfig, state: dict[str, Any]) -> None:
    """Every reason to change nothing at all, found while planning."""

    for user, account in state["accounts"].items():
        if account["home_link"]:
            raise DeployError(f"/home/{user} is a symbolic link; nothing was changed")
        if not account["present"]:
            continue
        if account["uid"] < cfg.min_uid:
            raise DeployError(f"{user} has uid {account['uid']} below {cfg.min_uid}; nothing was changed")
        if account["home"] != f"/home/{user}":
            raise DeployError(f"{user}'s home is not /home/{user}; nothing was changed")
        if account["processes"]:
            raise DeployError(f"{user} has running processes; nothing was changed (nothing is killed)")
        if account["linger"] or account["crontab"]:
            raise DeployError(f"{user} has a lingering user manager or a crontab; nothing was changed")
    for name, unit in state["units"].items():
        if unit["LoadState"] == "not-found" and not (unit["file"] or unit["dropin_dir"]):
            continue
        if unit["ActiveState"] not in INACTIVE:
            raise DeployError(f"{name} is {unit['ActiveState']}; nothing was changed (nothing is stopped)")
        fragment = unit["FragmentPath"]
        # A linked unit (``systemctl link``): systemd may report the link's target.
        if fragment and fragment not in (f"{SYSTEM_UNITS}/{name}", unit.get("link_target") or None):
            raise DeployError(f"{name} is not a unit file in {SYSTEM_UNITS}; nothing was changed")
        for dropin in unit["DropInPaths"].split():
            if not dropin.startswith(f"{SYSTEM_UNITS}/{name}.d/"):
                raise DeployError(f"{name} has a drop-in outside {SYSTEM_UNITS}/{name}.d; nothing was changed")
    retired = set(cfg.accounts)
    for name, group in state["groups"].items():
        if not group["exists"]:
            continue
        if group["gid"] < cfg.min_uid:
            raise DeployError(f"group {name} has gid {group['gid']} below {cfg.min_uid}; nothing was changed")
        others = (set(group["members"]) | set(group["primary_of"])) - retired
        if others:
            raise DeployError(f"group {name} still has accounts {', '.join(sorted(others))}; nothing was changed")
    if cfg.databases and not state["postgres"]:
        raise DeployError("legacy retirement lists databases but the host has no PostgreSQL; nothing was changed")
    for item in cfg.databases:
        db = state["databases"][item.name]
        if db["exists"] and db["connections"]:
            raise DeployError(f"database {item.name} has open connections; nothing was changed")
        if db["owner_other_databases"]:
            raise DeployError(f"role {item.owner} owns other databases; nothing was changed")


def _publish(partial: str, final: str) -> str:
    """sh: make the checked ``partial`` ``0600`` and publish it as ``final``; never replaces ``final``.

    ``ln`` fails when ``final`` exists, so an archive that appeared meanwhile stays.
    """

    return f"chmod 0600 {partial} && ln -- {partial} {final} && rm -f -- {partial}"


def _archive(cfg: LegacyRetirementConfig, name: str, sources: list[str]) -> str:
    """sh: tar ``sources`` (absolute) to ``name`` in the archive directory, numeric owners, 0600."""

    final = shlex.quote(f"{cfg.archive_dir}/{name}")
    partial = shlex.quote(f"{cfg.archive_dir}/.{name}.partial")
    relative = " ".join(shlex.quote(source.lstrip("/")) for source in sources)
    return (
        f"umask 077 && test ! -e {final} && rm -f {partial} && "
        f"tar --numeric-owner --acls --xattrs -czpf {partial} -C / {relative} && "
        f"tar -tzf {partial} >/dev/null && {_publish(partial, final)}"
    )


def _no_processes(user: str) -> str:
    quoted = shlex.quote(user)
    message = shlex.quote(f"{user} has running processes, a lingering user manager or a crontab; not removed")
    return (
        f"if ps -u {quoted} -o pid= >/dev/null || test -e /var/lib/systemd/linger/{quoted} "
        f"|| test -e /var/spool/cron/crontabs/{quoted}; then echo {message} >&2; exit 1; fi"
    )


def _unit_inactive(unit: str) -> str:
    quoted = shlex.quote(unit)
    message = shlex.quote(f"{unit} is no longer inactive; not removed")
    return (
        f'case "$(systemctl show -p ActiveState --value -- {quoted})" in inactive|failed) ;; '
        f"*) echo {message} >&2; exit 1 ;; esac"
    )


def _psql(sql: str) -> str:
    return "cd / && " + shlex.join(
        ["runuser", "-u", "postgres", "--", "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", sql]
    )


@deploy("Retire legacy accounts and services")
def retire_legacy(cfg: LegacyRetirementConfig) -> None:
    require_linux("Legacy retirement")
    require_systemd("Legacy retirement")
    state = host_state(cfg)
    refuse(cfg, state)
    archived = state["archives"]
    accounts = state["accounts"]
    loaded = [name for name, unit in state["units"].items() if unit["LoadState"] != "not-found"]
    unit_paths = {
        path: name
        for name, unit in state["units"].items()
        for path, present in zip(cfg.unit_sources(name), (unit["file"], unit["dropin_dir"]), strict=True)
        if present
    }
    paths = [path for path, present in state["paths"].items() if present]
    databases = [item for item in cfg.databases if state["databases"][item.name]["exists"]]
    roles = [item.owner for item in cfg.databases if state["databases"][item.name]["owner_exists"]]
    homes = {user: account for user, account in accounts.items() if account["home_exists"] or account["mail"]}

    def check(name: str) -> str:
        return f"test -s {shlex.quote(cfg.archive_dir + '/' + name)}"

    if unit_paths or paths or databases or homes:
        files.directory(
            name=f"Root-only archive directory {cfg.archive_dir}",
            path=cfg.archive_dir,
            user="root",
            group="root",
            mode="0700",
        )
    # 1. Archives, before any removal; each source has its own.
    for path in [*unit_paths, *paths]:
        name = cfg.source_archive(path)
        if not archived[name]:
            server.shell(name=f"Archive {path} to {cfg.archive_dir}/{name}", commands=[_archive(cfg, name, [path])])
    for item in databases:
        name = cfg.dump_archive(item.name)
        if archived[name]:
            continue
        final = shlex.quote(f"{cfg.archive_dir}/{name}")
        partial = shlex.quote(f"{cfg.archive_dir}/.{name}.partial")
        dump = shlex.join(["runuser", "-u", "postgres", "--", "pg_dump", "-Fc", "--", item.name])
        server.shell(
            name=f"Dump PostgreSQL database {item.name} to {cfg.archive_dir}/{name}",
            commands=[
                f"cd / && umask 077 && test ! -e {final} && rm -f {partial} && {dump} > {partial} && "
                f"pg_restore -l {partial} >/dev/null && {_publish(partial, final)}"
            ],
        )
    for user, account in homes.items():
        name = cfg.home_archive(user)
        if archived[name]:
            continue
        sources = [
            path
            for path, present in ((account["home"], account["home_exists"]), (f"/var/mail/{user}", account["mail"]))
            if present
        ]
        server.shell(
            name=f"Archive {' and '.join(sources)} to {cfg.archive_dir}/{name}",
            commands=[_archive(cfg, name, sources)],
        )

    # 2. Units: disable, remove their files (each still inactive), reload.
    for name in loaded:
        if state["units"][name]["UnitFileState"] in ("enabled", "enabled-runtime", "linked", "linked-runtime"):
            server.shell(
                name=f"Disable {name}",
                commands=[_unit_inactive(name), f"systemctl disable -- {shlex.quote(name)}"],
            )
    for path, unit in unit_paths.items():
        server.shell(
            name=f"Remove {path}",
            commands=[
                _unit_inactive(unit),
                f"{check(cfg.source_archive(path))} && rm -rf -- {shlex.quote(path)}",
            ],
        )
    if unit_paths:
        systemd.daemon_reload(name="Reload systemd after the unit removal")
        for name in loaded:
            server.shell(
                name=f"Reset the failed state of {name}",
                commands=[f"systemctl reset-failed -- {shlex.quote(name)} || true"],
            )

    # 3. Other paths (a Traefik route only while no route transaction holds the lock).
    for path in paths:
        server.shell(name=f"Check the archive of {path}", commands=[check(cfg.source_archive(path))])
        remove_path(path)

    # 4. Databases, then their roles.
    for item in databases:
        busy = _psql(f"SELECT count(*) FROM pg_stat_activity WHERE datname = '{item.name}'")
        message = shlex.quote(f"database {item.name} has open connections; not dropped")
        server.shell(
            name=f"Drop PostgreSQL database {item.name}",
            commands=[
                f'{check(cfg.dump_archive(item.name))} && [ "$({busy})" = 0 ] || {{ echo {message} >&2; exit 1; }}',
                _psql(f"DROP DATABASE IF EXISTS {item.name}"),
            ],
        )
    for role in roles:
        server.shell(name=f"Drop PostgreSQL role {role}", commands=[_psql(f"DROP ROLE IF EXISTS {role}")])

    # 5. Accounts, their homes and mail spools, their groups (also what an interrupted run left).
    for user, account in accounts.items():
        quoted = shlex.quote(user)
        commands = []
        if account["present"]:
            gate = f"{check(cfg.home_archive(user))} && " if user in homes else ""
            commands += [_no_processes(user), f"{gate}userdel -- {quoted}"]
        if user in homes:
            leftovers = f"{shlex.quote(account['home'])} {shlex.quote('/var/mail/' + user)}"
            commands.append(f"{check(cfg.home_archive(user))} && rm -rf -- {leftovers}")
        if account["present"] or account["group"]:
            commands.append(f"if getent group {quoted} >/dev/null; then groupdel -- {quoted}; fi")
        if commands:
            server.shell(name=f"Remove user {user}, {account['home']} and its mail spool", commands=commands)
    for name, group in state["groups"].items():
        if group["exists"]:
            quoted = shlex.quote(name)
            server.shell(
                name=f"Remove group {name}",
                commands=[f"if getent group {quoted} >/dev/null; then groupdel -- {quoted}; fi"],
            )
