"""MeTube, Jellyfin and Navidrome backup and restore (the ``*_backup`` and ``*_restore`` roles).

A backup is ``<root>/<prefix>-<timestamp>/`` with the service's data
(``state/`` or ``data/``), config, unit, Traefik route and (Jellyfin,
Navidrome) logs and ``manifest.yml``, packed as ``<dir>.tar.gz`` with the
directory's contents below its name, as ``archive: format=gz`` packs it. The
directory stays next to the archive, as the roles leave it. Either tool
restores the other's archives.

Each backup and restore runs on the host as one Python program
(``files/media_lifecycle_host.py``) with its settings on stdin, so the
backups' ``block``/``always`` keeps its meaning (the service starts again only
when the backup stopped it). A restore keeps the replaced data (and Jellyfin's
config) directory as a pre-restore copy with ops-library's
``restore_preserve_internal/files/preserve.py``, shipped unchanged
(``files/preserve.py``); like the roles it stops where a step fails,
with the service stopped and the staging directory left for inspection.

The Navidrome restore exists only as ops-control's guarded recovery of a
Native (pyinfra) Navidrome (``playbooks/navidrome/restore.yml``): it needs
``confirm``, refuses non-canonical paths, Native pending/restart work and
unsafe recovery directories, keeps the current canonical config, unit and
route under a fresh ``/var/lib/ops-deploy/navidrome/restored/restore-<id>/``
and puts the archived ones there instead of their live locations.

``required_mount`` keeps the backup root on an external disk
(:mod:`ops_deploy.services._lifecycle.local_backup`); the roles' own
retention (``retain`` newest archives of the prefix by mtime) prunes after the
fetch, as the roles do.
"""

from __future__ import annotations

import base64
import json
import os
import shlex
import stat
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import BeforeValidator, Field, field_validator, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server

from ops_deploy.base._common import AbsolutePath, RoleConfig, output
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.helpers.probes import stdin_arguments
from ops_deploy.helpers.traefik import DYNAMIC_DIR, route_guard_command
from ops_deploy.services._lifecycle.local_backup import MountGuard, mount_check
from ops_deploy.services._lifecycle.preserve import PRESERVE_PY

FILES = Path(__file__).parent / "files"
HOST_SCRIPT = "PRESERVE_SOURCE=" + repr(PRESERVE_PY) + "\n" + (FILES / "media_lifecycle_host.py").read_text()
Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
Mode = Annotated[
    str,
    BeforeValidator(lambda value: format(value, "04o") if type(value) is int else value),
    Field(pattern=r"^0?[0-7]{3}$"),
]
# ``latest``, a name below the restore root or an absolute path.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|/?[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*)$")]
PROTECTED = frozenset(
    {
        "/",
        "/etc",
        "/etc/systemd",
        "/etc/systemd/system",
        "/etc/traefik",
        "/etc/traefik/dynamic",
        "/home",
        "/lib",
        "/lib/systemd",
        "/lib/systemd/system",
        "/mnt",
        "/opt",
        "/opt/backups",
        "/root",
        "/srv",
        "/tmp",
        "/usr",
        "/var",
        "/var/lib",
        "/var/log",
        "/var/tmp",
    }
)


def _dedicated(value: str) -> str:
    path = PurePosixPath(value)
    if ".." in path.parts or str(path) in PROTECTED:
        raise ValueError("media lifecycle paths must identify a dedicated resource")
    return value


class _MediaBackup(MountGuard):
    """The shared ``*_backup`` variables (``<service>_backup_*`` without the prefix)."""

    service_name: ServiceName
    prefix: Prefix = "manual"
    root: AbsolutePath
    archive_format: Literal["gz"] = "gz"
    archive_extension: Literal["tar.gz"] = "tar.gz"
    fetch_local: bool = True
    # None: ``~/backups/<service>`` on the controller.
    local_dir: Path | None = None
    dir_mode: Mode = "0700"
    file_mode: Mode = "0600"
    owner: UnixUser = "root"
    group: UnixUser = "root"
    create_archive: bool = True
    stop_service: bool = True
    include_config: bool = True
    include_systemd: bool = True
    include_traefik: bool = True
    use_delete: bool = True
    retain: int = Field(default=7, ge=0)
    generate_manifest: bool = True

    @field_validator("root")
    @classmethod
    def _root(cls, value: str) -> str:
        return _dedicated(value)

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}


class _MediaRestore(RoleConfig):
    """The shared ``*_restore`` variables."""

    root: AbsolutePath
    archive: ArchiveName = "latest"
    archive_extension: Literal["tar.gz"] = "tar.gz"
    staging_dir: AbsolutePath
    cleanup: bool = True
    restart: bool = True

    @field_validator("root", "staging_dir")
    @classmethod
    def _paths(cls, value: str) -> str:
        return _dedicated(value)

    @field_validator("archive")
    @classmethod
    def _archive(cls, value: str) -> str:
        if ".." in PurePosixPath(value).parts:
            raise ValueError("archive cannot contain parent traversal")
        return value


class MetubeBackupConfig(_MediaBackup):
    """``metube_backup`` with the ``metube_shared`` defaults."""

    root: AbsolutePath = "/opt/backups/metube"
    service_name: ServiceName = "metube"
    service_unit: AbsolutePath = "/etc/systemd/system/metube.service"
    state_dir: AbsolutePath = "/var/lib/metube"
    env_file: AbsolutePath = "/etc/metube/metube.env"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/metube.yml"
    venv_path: AbsolutePath = "/opt/metube/venv"
    include_state: bool = True


class JellyfinBackupConfig(_MediaBackup):
    """``jellyfin_backup`` with the ``jellyfin_shared`` defaults."""

    root: AbsolutePath = "/opt/backups/jellyfin"
    service_name: ServiceName = "jellyfin"
    service_unit: AbsolutePath = "/lib/systemd/system/jellyfin.service"
    data_dir: AbsolutePath = "/var/lib/jellyfin"
    config_dir: AbsolutePath = "/etc/jellyfin"
    log_dir: AbsolutePath = "/var/log/jellyfin"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/jellyfin.yml"
    include_data: bool = True
    include_logs: bool = True


class NavidromeBackupConfig(_MediaBackup):
    """``navidrome_backup`` with the ``navidrome_shared`` defaults."""

    root: AbsolutePath = "/opt/backups/navidrome"
    service_name: ServiceName = "navidrome"
    service_unit: AbsolutePath = "/etc/systemd/system/navidrome.service"
    data_dir: AbsolutePath = "/var/lib/navidrome"
    config_path: AbsolutePath = "/etc/navidrome.toml"
    log_dir: AbsolutePath = "/var/log/navidrome"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/navidrome.yml"
    bin_path: AbsolutePath = "/opt/navidrome/navidrome"
    include_data: bool = True
    include_logs: bool = True


class MetubeRestoreConfig(_MediaRestore):
    """``metube_restore`` with the ``metube_shared`` defaults."""

    root: AbsolutePath = "/opt/backups/metube"
    staging_dir: AbsolutePath = "/tmp/metube-restore"
    stop_service: bool = True
    user: UnixUser = "metube"
    group: UnixUser = "metube"
    service_name: ServiceName = "metube"
    service_enabled: bool = True
    service_unit: AbsolutePath = "/etc/systemd/system/metube.service"
    state_dir: AbsolutePath = "/var/lib/metube"
    env_dir: AbsolutePath = "/etc/metube"
    env_file: AbsolutePath = "/etc/metube/metube.env"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/metube.yml"

    @field_validator("state_dir", "env_dir")
    @classmethod
    def _live(cls, value: str) -> str:
        return _dedicated(value)


class JellyfinRestoreConfig(_MediaRestore):
    """``jellyfin_restore`` with the ``jellyfin_shared`` defaults."""

    root: AbsolutePath = "/opt/backups/jellyfin"
    staging_dir: AbsolutePath = "/tmp/jellyfin-restore"
    stop_service: bool = True
    user: UnixUser = "jellyfin"
    group: UnixUser = "jellyfin"
    service_name: ServiceName = "jellyfin"
    service_unit: AbsolutePath = "/lib/systemd/system/jellyfin.service"
    data_dir: AbsolutePath = "/var/lib/jellyfin"
    config_dir: AbsolutePath = "/etc/jellyfin"
    log_dir: AbsolutePath = "/var/log/jellyfin"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/jellyfin.yml"

    @field_validator("data_dir", "config_dir", "log_dir")
    @classmethod
    def _live(cls, value: str) -> str:
        return _dedicated(value)


# ops-control's quarantine asserts these canonical paths before the role runs.
NAVIDROME_CANONICAL = {
    "data_dir": "/var/lib/navidrome",
    "cache_dir": "/var/lib/navidrome/cache",
    "log_dir": "/var/log/navidrome",
    "service_name": "navidrome",
    "user": "navidrome",
    "group": "navidrome",
    "staging_dir": "/tmp/navidrome-restore",
    "config_path": "/etc/navidrome.toml",
    "service_unit": "/etc/systemd/system/navidrome.service",
    "traefik_config_path": "/etc/traefik/dynamic/navidrome.yml",
}


class NavidromeRestoreConfig(_MediaRestore):
    """``navidrome_restore`` behind ops-control's Native recovery quarantine.

    ``confirm`` is the explicit destructive-recovery authorization (the
    playbook's ``navidrome_ansible_rollback=true``). There is no dry run and
    no full rescan: the quarantine refuses both.
    """

    confirm: bool = False
    root: AbsolutePath = "/opt/backups/navidrome"
    staging_dir: AbsolutePath = NAVIDROME_CANONICAL["staging_dir"]
    user: UnixUser = NAVIDROME_CANONICAL["user"]
    group: UnixUser = NAVIDROME_CANONICAL["group"]
    service_name: ServiceName = NAVIDROME_CANONICAL["service_name"]
    data_dir: AbsolutePath = NAVIDROME_CANONICAL["data_dir"]
    cache_dir: AbsolutePath = NAVIDROME_CANONICAL["cache_dir"]
    log_dir: AbsolutePath = NAVIDROME_CANONICAL["log_dir"]
    config_path: AbsolutePath = NAVIDROME_CANONICAL["config_path"]
    service_unit: AbsolutePath = NAVIDROME_CANONICAL["service_unit"]
    traefik_config_path: AbsolutePath = NAVIDROME_CANONICAL["traefik_config_path"]
    # The Native deploy's state directory: its pending/restart markers and the recovery attempts.
    state_root: AbsolutePath = "/var/lib/ops-deploy/navidrome"

    @model_validator(mode="after")
    def _canonical(self) -> Self:
        for name, value in NAVIDROME_CANONICAL.items():
            if getattr(self, name) != value:
                raise ValueError(
                    "Native recovery keeps canonical data/service paths and cannot execute a full rescan "
                    f"using the quarantined archived config ({name} must be {value}). No restore role ran."
                )
        if self.state_root != "/var/lib/ops-deploy/navidrome":
            raise ValueError("Recovery output must be a fresh child of the trusted restored directory.")
        return self


def _command(action: str) -> str:
    # Encoded trusted packaged source, as the Certbot port: login shells
    # (fish) otherwise alter backslash pairs in nested Python reprs.
    encoded = base64.b64encode(HOST_SCRIPT.encode()).decode()
    loader = f"import base64;exec(compile(base64.b64decode({encoded!r}),'<media-lifecycle>','exec'))"
    return shlex.join(["python3", "-I", "-c", loader, action])


def _stamp(what: str) -> str:
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError(f"{what}: cannot read the host's time")
    return stamp


def _local_dir(path: str, mode: str) -> None:
    os.makedirs(path, mode=int(mode, 8), exist_ok=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(descriptor, int(mode, 8))
    finally:
        os.close(descriptor)


def _private_local_file(path: str) -> None:
    """Create ``path`` ``0600`` before the fetch, or restrict the existing regular file to ``0600``."""

    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise DeployError("media backup: local archive destination must be a regular, singly-linked file")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
    else:
        os.close(descriptor)


def _host(name: str, action: str, payload: dict[str, Any], *, route: str | None = None) -> None:
    """``action`` of the host program; a restore that writes ``route`` into Traefik's watched directory
    first checks that no transaction holds its lock, and checks again right before it writes the route."""

    command = _command(action)
    if route is not None:
        guard = PurePosixPath(route).is_relative_to(DYNAMIC_DIR)
        payload = {**payload, "route_guard": shlex.split(route_guard_command()) if guard else []}
        if guard:
            command = f"{route_guard_command()} && {command}"
    server.shell(name=name, commands=[command], **stdin_arguments(json.dumps(payload) + "\n"))


def _backup(cfg: _MediaBackup, label: str, payload: dict[str, Any], *, prune_dirs: bool = True) -> None:
    stamp = _stamp(f"{cfg.service_name}_backup")
    name = f"{cfg.prefix}-{stamp}"
    backup_dir = f"{cfg.root}/{name}"
    archive = f"{backup_dir}.{cfg.archive_extension}"
    if cfg.required_mount:
        server.shell(
            name=f"Require {cfg.required_mount} below {cfg.root}",
            commands=[mount_check(cfg.required_mount, cfg.root)],
            _shell_executable="bash",
        )
    common = {
        "service": cfg.service_name,
        "label": label,
        "root": cfg.root,
        "dir": backup_dir,
        "archive": archive,
        "owner": cfg.owner,
        "group": cfg.group,
        "dir_mode": cfg.dir_mode,
        "file_mode": cfg.file_mode,
        "stop": cfg.stop_service,
        "unit": cfg.service_name,
        "create_archive": cfg.create_archive,
    }
    payload["manifest"] = [["timestamp", stamp], ["archive", PurePosixPath(archive).name], *payload["manifest"]]
    _host(f"Back up {label} into {backup_dir}", "backup", {**common, **payload})
    if cfg.fetch_local and cfg.create_archive:
        local = str(cfg.local_dir or Path.home() / "backups" / cfg.service_name)
        python.call(name=f"Ensure {local} ({cfg.dir_mode})", function=_local_dir, path=local, mode=cfg.dir_mode)
        destination = f"{local}/{PurePosixPath(archive).name}"
        python.call(name="Prepare the private local archive", function=_private_local_file, path=destination)
        files.get(name=f"Fetch the {label} backup archive", src=archive, dest=destination)
        python.call(name="Restrict the local archive to 0600", function=_private_local_file, path=destination)
    if cfg.retain > 0:
        _host(
            f"Keep the newest {cfg.retain} {cfg.prefix} {label} backups",
            "retain",
            {
                "service": cfg.service_name,
                "root": cfg.root,
                "prefix": cfg.prefix,
                "extension": cfg.archive_extension,
                "retain": cfg.retain,
                "create_archive": cfg.create_archive,
                "prune_dirs": prune_dirs,
            },
        )


@deploy("MeTube backup")
def deploy_metube_backup(cfg: MetubeBackupConfig) -> None:
    """Stop MeTube, copy its state, env file, unit and route, start it, pack, fetch and prune."""

    checks = [
        [cfg.state_dir, True, "State directory"],
        [cfg.env_file, True, "Env file"],
        [cfg.service_unit, False, "Service unit"],
        [cfg.traefik_config_path, False, "Traefik config"],
    ]
    copies = [
        (cfg.include_state, 0, "tree", cfg.state_dir, "state", cfg.use_delete),
        (cfg.include_config, 1, "file", cfg.env_file, "config", False),
        (cfg.include_systemd, 2, "file", cfg.service_unit, "systemd", False),
        (cfg.include_traefik, 3, "file", cfg.traefik_config_path, "traefik", False),
    ]
    _backup(
        cfg,
        "MeTube",
        {
            "version": [
                f"{cfg.venv_path}/bin/python3",
                "-c",
                "import yt_dlp, sys; print(getattr(yt_dlp,'__version__','unknown'))",
            ],
            "subdirs": ["state", "config", "systemd", "traefik"],
            "checks": checks,
            "missing": "Required path missing for backup: {label} ({path})",
            "copies": _copies(copies),
            # The role writes its manifest unconditionally.
            "generate_manifest": True,
            "manifest": [
                ["state_dir", cfg.state_dir],
                ["env_file", cfg.env_file],
                ["service_unit", cfg.service_unit],
                ["traefik_config", cfg.traefik_config_path],
            ],
        },
    )


@deploy("Jellyfin backup")
def deploy_jellyfin_backup(cfg: JellyfinBackupConfig) -> None:
    """Stop Jellyfin, copy its data, config, unit, route and logs, start it, pack, fetch and prune."""

    checks = [
        [cfg.data_dir, True, "Data directory"],
        [cfg.config_dir, True, "Config directory"],
        [cfg.service_unit, False, "Service unit"],
        [cfg.traefik_config_path, False, "Traefik config"],
        [cfg.log_dir, False, "Log directory"],
    ]
    copies = [
        (cfg.include_data, 0, "tree", cfg.data_dir, "data", cfg.use_delete),
        (cfg.include_config, 1, "tree", cfg.config_dir, "config", cfg.use_delete),
        (cfg.include_systemd, 2, "file", cfg.service_unit, "systemd", False),
        (cfg.include_traefik, 3, "file", cfg.traefik_config_path, "traefik", False),
        (cfg.include_logs, 4, "tree", cfg.log_dir, "logs", False),
    ]
    _backup(
        cfg,
        "Jellyfin",
        {
            "version": ["dpkg-query", "-W", "-f=${Version}", "jellyfin"],
            "subdirs": ["data", "config", "systemd", "traefik", "logs"],
            "checks": checks,
            "missing": "Required Jellyfin path missing: {path}",
            "copies": _copies(copies),
            "generate_manifest": cfg.generate_manifest,
            "manifest": [
                ["data_dir", cfg.data_dir],
                ["config_dir", cfg.config_dir],
                ["service_unit", cfg.service_unit],
                ["traefik_config", cfg.traefik_config_path],
                ["log_dir", cfg.log_dir],
            ],
        },
    )


@deploy("Navidrome backup")
def deploy_navidrome_backup(cfg: NavidromeBackupConfig) -> None:
    """Stop Navidrome, copy its data, config, unit, route and logs, start it, pack, fetch and prune."""

    checks = [
        [cfg.data_dir, True, "Data directory"],
        [cfg.config_path, True, "Config file"],
        [cfg.service_unit, False, "Service unit"],
        [cfg.traefik_config_path, False, "Traefik config"],
        [cfg.log_dir, False, "Log directory"],
    ]
    copies = [
        (cfg.include_data, 0, "tree", cfg.data_dir, "data", cfg.use_delete),
        (cfg.include_config, 1, "file", cfg.config_path, "config", False),
        (cfg.include_systemd, 2, "file", cfg.service_unit, "systemd", False),
        (cfg.include_traefik, 3, "file", cfg.traefik_config_path, "traefik", False),
        (cfg.include_logs, 4, "tree", cfg.log_dir, "logs", False),
    ]
    _backup(
        cfg,
        "Navidrome",
        {
            "version": [cfg.bin_path, "--version"],
            "subdirs": ["data", "config", "systemd", "traefik", "logs"],
            "checks": checks,
            "missing": "Required Navidrome path missing: {path}",
            "copies": _copies(copies),
            # The role writes its manifest unconditionally.
            "generate_manifest": True,
            "manifest": [
                ["data_dir", cfg.data_dir],
                ["config", cfg.config_path],
                ["service_unit", cfg.service_unit],
                ["traefik_config", cfg.traefik_config_path],
                ["log_dir", cfg.log_dir],
            ],
        },
        # navidrome_backup prunes archives only.
        prune_dirs=False,
    )


def _copies(copies: list[tuple[bool, int, str, str, str, bool]]) -> list[list[Any]]:
    """The included copies as ``[kind, check index, source, destination below the backup dir, --delete]``."""

    return [
        [kind, index, source, subdir if kind == "tree" else f"{subdir}/{PurePosixPath(source).name}", delete]
        for include, index, kind, source, subdir, delete in copies
        if include
    ]


@deploy("MeTube restore")
def deploy_metube_restore(cfg: MetubeRestoreConfig) -> None:
    """Restore a MeTube backup over its state directory, env file, unit and route; restart MeTube."""

    payload = {
        "service": "metube",
        "label": "MeTube",
        "root": cfg.root,
        "archive": cfg.archive,
        "extension": cfg.archive_extension,
        "staging": cfg.staging_dir,
        "no_payload": f"Could not locate payload directory under {cfg.staging_dir}",
        "cleanup": cfg.cleanup,
        "restart": cfg.restart,
        "stop_service": cfg.stop_service,
        "unit": cfg.service_name,
        "enabled": cfg.service_enabled,
        "user": cfg.user,
        "group": cfg.group,
        "service_unit": cfg.service_unit,
        "state_dir": cfg.state_dir,
        "env_dir": cfg.env_dir,
        "env_file": cfg.env_file,
        "traefik_config_path": cfg.traefik_config_path,
    }
    _host("Restore MeTube", "restore-metube", payload, route=cfg.traefik_config_path)


@deploy("Jellyfin restore")
def deploy_jellyfin_restore(cfg: JellyfinRestoreConfig) -> None:
    """Restore a Jellyfin backup over its data, config and log directories, unit and route; restart Jellyfin."""

    payload = {
        "service": "jellyfin",
        "label": "Jellyfin",
        "root": cfg.root,
        "archive": cfg.archive,
        "extension": cfg.archive_extension,
        "staging": cfg.staging_dir,
        "no_payload": "Unable to locate payload directory inside restore archive",
        "cleanup": cfg.cleanup,
        "restart": cfg.restart,
        "stop_service": cfg.stop_service,
        "unit": cfg.service_name,
        "user": cfg.user,
        "group": cfg.group,
        "service_unit": cfg.service_unit,
        "data_dir": cfg.data_dir,
        "config_dir": cfg.config_dir,
        "log_dir": cfg.log_dir,
        "traefik_config_path": cfg.traefik_config_path,
    }
    _host("Restore Jellyfin", "restore-jellyfin", payload, route=cfg.traefik_config_path)


@deploy("Navidrome recovery restore")
def deploy_navidrome_restore(cfg: NavidromeRestoreConfig) -> None:
    """Quarantine the canonical files, then restore Navidrome's data and logs; archived system files stay aside."""

    if not cfg.confirm:
        raise DeployError(
            "navidrome_restore: destructive live data recovery not confirmed; it stops Navidrome and replaces "
            "its data from the archive. Review runbooks/navidrome.md, then set confirm."
        )
    payload = {
        "service": "navidrome",
        "label": "Navidrome",
        "root": cfg.root,
        "archive": cfg.archive,
        "extension": cfg.archive_extension,
        "staging": cfg.staging_dir,
        "no_payload": "Unable to locate payload directory inside restore archive",
        "cleanup": cfg.cleanup,
        "restart": cfg.restart,
        "unit": cfg.service_name,
        "user": cfg.user,
        "group": cfg.group,
        "data_dir": cfg.data_dir,
        "cache_dir": cfg.cache_dir,
        "log_dir": cfg.log_dir,
        "config_path": cfg.config_path,
        "service_unit": cfg.service_unit,
        "traefik_config_path": cfg.traefik_config_path,
        "state_root": cfg.state_root,
    }
    _host("Quarantine and restore Navidrome", "restore-navidrome", payload)


__all__ = [
    "JellyfinBackupConfig",
    "JellyfinRestoreConfig",
    "MetubeBackupConfig",
    "MetubeRestoreConfig",
    "NavidromeBackupConfig",
    "NavidromeRestoreConfig",
    "deploy_jellyfin_backup",
    "deploy_jellyfin_restore",
    "deploy_metube_backup",
    "deploy_metube_restore",
    "deploy_navidrome_backup",
    "deploy_navidrome_restore",
]
