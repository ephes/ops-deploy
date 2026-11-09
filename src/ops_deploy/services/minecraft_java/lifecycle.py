"""Minecraft Java backup and restore (the ``minecraft_java_backup`` and ``minecraft_java_restore`` roles).

A backup is ``<root>/<prefix>-<UTC timestamp>.tar.gz`` (``root:root 0600`` in
a ``root:root 0700`` root) holding every world of the server (the configured
world and each other top-level directory with a ``level.dat``; hidden names
and pre-restore copies left out), ``server.properties`` and those of
``ops.json``, ``whitelist.json``, ``banned-ips.json`` and
``banned-players.json`` that exist, with paths relative to the server
directory, as the role's ``archive`` task packs them; either tool restores
the other's archives (the role restores the configured world of ours). While
the server runs the backup brackets the archive with RCON ``save-off``, a
verified ``save-all flush`` and, always, ``save-on``; a stopped server is
never started. The RCON password reaches the host only on stdin; a small RCON
client inside the host program uses it, so it is in no command line,
environment, file or log.

A restore picks ``latest`` (the newest ``*.tar.gz`` directly in the root by
mtime, the role's rule), a name in the root or an absolute path below it,
reads the whole archive (gzip and tar integrity, the configured world with
its ``level.dat``) and checks the unit as the role does. ``dry_run`` stops
there: it prints the plan and changes nothing (no work directory, no unit, no
data). A real restore needs ``confirm``; it stops a running unit, keeps each
live world of the archive as a pre-restore copy (ops-library's
``restore_preserve_internal/files/preserve.py``, shipped unchanged; a world
that does not exist yet, as on a fresh installation, has nothing to
snapshot), restores the worlds, ``server.properties`` and the player files
with the service account's ownership, and starts the unit again only when it
was running before. When replacing fails, the worlds come back from their
copies and the files from memory, and the unit stays stopped.

Deliberate deviations from the roles are listed in ``docs/services/minecraft_java.md``
(Backup and restore): every world instead of one; the world comes from the
caller (the playbook never set it, so the role archived its default
``world``) and must be the ``level-name`` of the live (and archived)
``server.properties``; running means the unit's state, not ``pgrep -f
server.jar`` (which misses Forge); a failed ``save-on`` fails the run;
``save-all flush`` must answer "Saved the game"; the role's retention (the 10
newest ``*.tar.gz``, whoever wrote them) and blanket ``chmod`` of other
archives are replaced by the recorded-snapshot retention of
:mod:`ops_deploy.services._lifecycle.local_backup`; the rollback; the restore
never enables the unit and starts it only when it ran before;
``server.properties`` is restored ``0640`` (the deploy's mode; the role wrote
``0644``); archive members that are links, special files or unsafe paths are
refused.
"""

from __future__ import annotations

import base64
import json
import shlex
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Self

from pydantic import Field, StrictBool, model_validator
from pyinfra import logger
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server

from ops_deploy.base._common import output
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, stdin_arguments, verify_probe
from ops_deploy.ops import secret_stdin
from ops_deploy.services._lifecycle.canonical import CanonicalPath, Prefix
from ops_deploy.services._lifecycle.local_backup import (
    MountGuard,
    SnapshotRetention,
    backup_preflight,
    mount_check,
    retention,
)
from ops_deploy.services._lifecycle.preserve import PRESERVE_PY
from ops_deploy.services.minecraft_java.deploy import Name, Port, validate_secrets

FILES = Path(__file__).parent / "files"
HOST_SCRIPT = "PRESERVE_SOURCE=" + repr(PRESERVE_PY) + "\n" + (FILES / "lifecycle_host.py").read_text()
PLAN_MARKER = "MINECRAFT_RESTORE_PLAN "
# ``latest``, an archive name in the root (as the existing hand-made names, ``=`` included) or an
# absolute canonical path below the root (checked by the config).
ArchiveName = Annotated[
    str, Field(pattern=r"^(latest|[A-Za-z0-9_+=-][A-Za-z0-9._+=-]*\.tar\.gz|/[A-Za-z0-9._/+=-]+\.tar\.gz)$")
]
# Directories a backup root, work directory or server directory must never be.
SHARED = frozenset(
    {"/", "/home", "/opt", "/opt/backups", "/root", "/srv", "/tmp", "/usr", "/var", "/var/lib", "/var/tmp", "/mnt"}
)


def _dedicated(**paths: str) -> None:
    for field, path in paths.items():
        if path in SHARED or len(PurePosixPath(path).parts) < 3:
            raise ValueError(f"{field} ({path}) must be a directory of its own, not a shared one")


def _overlap(first: str, second: str) -> bool:
    a, b = PurePosixPath(first), PurePosixPath(second)
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


class MinecraftJavaBackupConfig(SnapshotRetention):
    """``minecraft_java_backup`` with the role's defaults, except the world, which has none.

    ``world_name``: the directory below ``server_dir`` the server plays
    (ops-control passes the deploy's inventory world); the host refuses it
    unless it is the ``level-name`` of the live ``server.properties``.
    """

    prefix: Prefix = "manual"
    root: CanonicalPath = "/opt/backups/minecraft-java"
    server_dir: CanonicalPath = "/home/minecraft/server"
    world_name: Name
    service_name: ServiceName = "minecraft-java"
    port: Port = 25565
    rcon_port: Port = 25575
    # Seconds after ``save-all flush`` before archiving (the role's pause) and per RCON command (its timeout).
    save_wait: int = Field(default=2, ge=0, le=60)
    save_timeout: int = Field(default=30, ge=1, le=300)

    @model_validator(mode="after")
    def _paths(self) -> Self:
        _dedicated(root=self.root, server_dir=self.server_dir)
        if _overlap(self.root, self.server_dir):
            raise ValueError("root and server_dir must not overlap")
        if self.port == self.rcon_port:
            raise ValueError("game and RCON ports must differ")
        return self

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}


class MinecraftJavaRestoreConfig(MountGuard):
    """``minecraft_java_restore`` with the role's defaults, the world from the caller and the guards.

    ``staging_dir``: the work directory the selected members are unpacked into
    (the role used a ``/tmp`` temporary directory); emptied whether the
    restore succeeds or fails. ``start_timeout``: seconds the game port may
    take to open after a start (Forge needs minutes; the role waited 60).
    """

    archive: ArchiveName = "latest"
    root: CanonicalPath = "/opt/backups/minecraft-java"
    # ``<root>/.restore-work`` unless set.
    staging_dir: CanonicalPath = "/opt/backups/minecraft-java/.restore-work"
    server_dir: CanonicalPath = "/home/minecraft/server"
    world_name: Name
    service_name: ServiceName = "minecraft-java"
    user: UnixUser = "minecraft"
    group: UnixUser = "minecraft"
    port: Port = 25565
    start_timeout: int = Field(default=300, ge=1, le=1800)
    dry_run: StrictBool = False
    # The explicit authorization of a real restore (it replaces live world data).
    confirm: StrictBool = False

    @model_validator(mode="before")
    @classmethod
    def _staging_follows_root(cls, data: Any) -> Any:
        if isinstance(data, dict) and "root" in data and "staging_dir" not in data:
            return {**data, "staging_dir": f"{data['root']}/.restore-work"}
        return data

    @model_validator(mode="after")
    def _paths(self) -> Self:
        _dedicated(root=self.root, staging_dir=self.staging_dir, server_dir=self.server_dir)
        if _overlap(self.root, self.server_dir) or _overlap(self.staging_dir, self.server_dir):
            raise ValueError("root, staging_dir and server_dir must not overlap the server directory")
        if self.staging_dir == self.root or PurePosixPath(self.root).is_relative_to(self.staging_dir):
            raise ValueError("staging_dir must not be or contain the backup root")
        if self.archive.startswith("/"):
            path = PurePosixPath(self.archive)
            if ".." in path.parts or str(path) != self.archive or not path.is_relative_to(self.root):
                raise ValueError("an absolute archive must be a canonical path below root")
            if path.is_relative_to(self.staging_dir):
                raise ValueError("the archive must not lie in the restore work directory")
        if self.user in ("root", "0") or self.group in ("root", "0"):
            raise ValueError("the world must belong to the service account, not root")
        return self

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root, "staging_dir": self.staging_dir}


def _command(action: str) -> str:
    # Encoded packaged source (as the media lifecycle): a fish login shell
    # would otherwise alter backslash pairs in the nested Python source.
    encoded = base64.b64encode(HOST_SCRIPT.encode()).decode()
    loader = f"import base64;exec(compile(base64.b64decode({encoded!r}),'<minecraft-lifecycle>','exec'))"
    return shlex.join(["python3", "-I", "-c", loader, action])


def _stamp() -> str:
    # UTC in local_backup's STAMP_FORMAT (the role took the host's local time).
    stamp = output("date -u +%Y%m%dT%H%M%S").strip()
    if len(stamp) != len("YYYYmmddTHHMMSS"):
        raise DeployError("minecraft_java backup: cannot read the host's time")
    return stamp


@deploy("Minecraft Java backup")
def deploy_minecraft_java_backup(cfg: MinecraftJavaBackupConfig, secrets: SecretValues | None = None) -> None:
    """Check the mount and name, archive the world (saves coordinated while it runs), then prune recorded snapshots."""

    if secrets is None:
        raise DeployError("minecraft_java backup needs the rcon_password secret")
    try:
        validate_secrets(secrets)
    except (KeyError, ValueError) as error:
        raise DeployError(f"minecraft_java backup: {error}") from None
    stamp = _stamp()
    name = f"{cfg.prefix}-{stamp}"
    archive = f"{cfg.root}/{name}.tar.gz"
    preflight = backup_preflight(cfg, cfg.root, name)
    if preflight:
        server.shell(name="Check the backup mount and name", commands=[preflight], _shell_executable="bash")
    payload = {
        "root": cfg.root,
        "archive": archive,
        "server_dir": cfg.server_dir,
        "world": cfg.world_name,
        "unit": cfg.service_name,
        "port": cfg.port,
        "rcon_port": cfg.rcon_port,
        "save_wait": cfg.save_wait,
        "save_timeout": cfg.save_timeout,
        "rcon_password": secrets["rcon_password"],
    }
    secret_stdin(
        name=f"Back up the Minecraft worlds (playing {cfg.world_name}) into {archive}",
        command=_command("backup"),
        content=SecretContent(json.dumps(payload) + "\n"),
    )
    if cfg.retention:
        server.shell(
            name="Record the snapshot and prune recorded snapshots",
            commands=[retention(cfg, cfg.root, name, stamp)],
            _shell_executable="bash",
        )


def _report(plan: str | None) -> None:
    lines = [line for line in (plan or "").splitlines() if line.startswith(PLAN_MARKER)]
    if not lines:
        logger.warning("Minecraft restore check failed while planning; the check step below reports why")
        return
    found: dict[str, Any] = json.loads(lines[-1].removeprefix(PLAN_MARKER))
    worlds = ", ".join(
        f"{name} ({found['world_entries'][name]} entries, live copy: {name in found['live_worlds']})"
        for name in found["worlds"]
    )
    logger.info(
        f"Minecraft restore plan: archive {found['archive']} ({found['size_bytes']} bytes); worlds into "
        f"{found['server_dir']}: {worlds}; playing {found['world']}; server.properties: "
        f"{found['server_properties']}, player files: {', '.join(found['player_files']) or 'none'}, left out: "
        f"{', '.join(found['ignored_top_level']) or 'nothing'}; unit {found['unit']}, stop: {found['stop']}, "
        f"start afterwards: {found['start_after']}"
    )


@deploy("Minecraft Java restore")
def deploy_minecraft_java_restore(cfg: MinecraftJavaRestoreConfig) -> None:
    """Check the archive and the host; then (``dry_run``) stop there, or restore the world with a pre-restore copy."""

    if not cfg.dry_run and not cfg.confirm:
        raise DeployError(
            "minecraft_java restore replaces the live world of a protected service and was not confirmed; "
            "run the dry run first, then confirm"
        )
    payload = json.dumps(
        {
            "root": cfg.root,
            "archive": cfg.archive,
            "staging": cfg.staging_dir,
            "server_dir": cfg.server_dir,
            "world": cfg.world_name,
            "unit": cfg.service_name,
            "user": cfg.user,
            "group": cfg.group,
            "port": cfg.port,
            "start_timeout": cfg.start_timeout,
        }
    )
    if cfg.required_mount:
        guarded = [cfg.root] if cfg.dry_run else [cfg.root, cfg.staging_dir]
        meta = server.shell(
            name=f"Require {cfg.required_mount} below the restore paths",
            commands=[mount_check(cfg.required_mount, *guarded)],
            _shell_executable="bash",
        )
        if cfg.dry_run:
            mark_read_only(meta)
    check = _command("check")
    _report(probe(check, name="Minecraft restore check", stdin=payload))
    if cfg.dry_run:
        verify_probe(check, name="Minecraft restore check (dry run; nothing is changed)", stdin=payload)
        return
    server.shell(
        name=f"Restore the Minecraft worlds (playing {cfg.world_name}) from {cfg.archive}",
        commands=[_command("restore")],
        **stdin_arguments(payload + "\n"),
    )


__all__ = [
    "MinecraftJavaBackupConfig",
    "MinecraftJavaRestoreConfig",
    "deploy_minecraft_java_backup",
    "deploy_minecraft_java_restore",
]
