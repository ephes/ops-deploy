"""nyxmon backup, restore and removal (the ``nyxmon_backup``, ``nyxmon_restore`` and ``nyxmon_remove`` roles).

A backup is ``<root>/<prefix>-<timestamp>`` with ``database/``, ``media/``,
``static/``, ``logs/``, ``config/``, ``systemd/``, ``traefik/``,
``metadata.yml`` and ``manifest.sha256``, packed as ``<dir>.tar.gz`` with the
directory as the archive's only top-level entry, exactly as the role writes
it. Either tool restores the other's archives.

Backup and restore run on the host as one bash script each (``files/``), so
the role's ``block``/``always``/``rescue`` structure keeps its meaning: the
services start again whatever the copy did, a failed restore puts the safety
snapshot back and starts them, and the staging directory always goes. Like the
roles, every backup and restore reports a change. Removal is planned from what
the host has, so a second run changes nothing.

``required_mount`` keeps the backup root and the restore's staging directory
on an external disk, and ``retain_count``/``retain_days`` limit the snapshots
a backup keeps (:mod:`ops_deploy.services._lifecycle.local_backup`).
"""

from __future__ import annotations

import shlex
from io import StringIO
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import Field
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.operations import apt, files, python, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, output
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.services._lifecycle import (
    exists,
    flag,
    kill_user_processes,
    private_local_dir,
    remove_account,
    remove_path,
    script,
    stop_disable,
)
from ops_deploy.services._lifecycle.local_backup import MountGuard, SnapshotRetention, retention

FILES = Path(__file__).parent / "files"
Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
# ``latest``, or an archive name below the search root (the role joins it to the root).
ArchiveName = Annotated[str, Field(pattern=r"^(latest|[A-Za-z0-9._+-]+\.tar\.gz)$")]
Hostname = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
Url = Annotated[str, Field(pattern=r"^https?://[A-Za-z0-9.:/_-]+$")]
UNITS = ("/etc/systemd/system/nyxmon.service", "/etc/systemd/system/nyxmon-monitor.service")
STOP_ORDER = ("nyxmon-monitor.service", "nyxmon.service")
START_ORDER = ("nyxmon.service", "nyxmon-monitor.service")
# ``use_sqlite_backup``: ``sqlite3 .timeout`` per attempt, attempts, seconds between them (``files/backup.sh``).
SQLITE_BACKUP_SETTINGS = {"SQLITE_TIMEOUT_MS": "30000", "SQLITE_ATTEMPTS": "3", "SQLITE_RETRY_DELAY": "5"}


class NyxmonBackupConfig(SnapshotRetention):
    # The metadata's ``host`` (Ansible's ``inventory_hostname``).
    host_name: Hostname
    root: AbsolutePath = "/opt/backups/nyxmon"
    prefix: Prefix = "manual"
    site_path: AbsolutePath = "/home/nyxmon/site"
    logs_path: AbsolutePath = "/home/nyxmon/logs"
    stop_services: bool = True
    # Off: the database file is copied (the role's default); on: ``sqlite3 .backup``
    # (waits for a writer's lock, three attempts, the copy must pass its integrity check).
    use_sqlite_backup: bool = False
    include_logs: bool = True
    include_cache: bool = False
    include_static: bool = True
    use_delete: bool = True
    generate_checksums: bool = True
    create_archive: bool = True
    fetch_local: bool = True
    # None: ``~/backups/nyxmon`` on the controller.
    local_dir: Path | None = None

    @property
    def python_bin(self) -> str:
        return f"{self.site_path}/.venv/bin/python"

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}


class NyxmonRestoreConfig(MountGuard):
    host_name: Hostname
    archive: ArchiveName = "latest"
    search_root: AbsolutePath = "/opt/backups/nyxmon"
    staging_dir: AbsolutePath = "/tmp/nyxmon-restore"
    validate_checksums: bool = True
    dry_run: bool = False
    check_disk_space: bool = True
    disk_space_multiplier: float = Field(default=2.0, gt=0)
    site_path: AbsolutePath = "/home/nyxmon/site"
    logs_path: AbsolutePath = "/home/nyxmon/logs"
    fix_ownership: bool = True
    site_owner: UnixUser = "nyxmon"
    site_group: UnixUser = "nyxmon"
    restore_system_files: bool = True
    verify_http: bool = True
    health_url: Url = "http://127.0.0.1:10017/admin/login/"
    health_retries: int = Field(default=5, ge=0)
    health_delay: int = Field(default=5, ge=0)
    health_expected_status: int = Field(default=200, ge=100, le=599)
    verify_sqlite: bool = True
    create_safety_backup: bool = True
    safety_backup_prefix: Prefix = "pre-restore"
    safety_rsync_delete: bool = True
    cleanup_safety_backup: bool = True

    def guarded_paths(self) -> dict[str, str]:
        return {"staging_dir": self.staging_dir}


class NyxmonRemoveConfig(RoleConfig):
    confirm: bool = False
    user: UnixUser = "nyxmon"
    group: UnixUser = "nyxmon"
    home: AbsolutePath = "/home/nyxmon"
    service_name: ServiceName = "nyxmon"
    monitor_service_name: ServiceName = "nyxmon-monitor"
    traefik_config_file: AbsolutePath = "/etc/traefik/dynamic/nyxmon.yml"


def backup_metadata(cfg: NyxmonBackupConfig, *, stamp: str, version: str) -> str:
    """``metadata.yml`` as the role's ``to_nice_yaml`` writes it."""

    data = {
        "timestamp": stamp,
        "host": cfg.host_name,
        "site_path": cfg.site_path,
        "database": f"{cfg.site_path}/db.sqlite3",
        "version": version,
        "stop_services": cfg.stop_services,
        "include_logs": cfg.include_logs,
        "include_cache": cfg.include_cache,
        "include_static": cfg.include_static,
        "services": list(STOP_ORDER),
    }
    return yaml.dump(data, indent=4, allow_unicode=True, default_flow_style=False, sort_keys=True)


@deploy("nyxmon backup")
def deploy_nyxmon_backup(cfg: NyxmonBackupConfig) -> None:
    """Stop nyxmon, copy its state into a backup directory, start it, pack and fetch the archive."""

    site = cfg.site_path
    required = {
        site: "Nyxmon site directory",
        f"{site}/.env": "Nyxmon .env",
        f"{site}/db.sqlite3": "Nyxmon SQLite database",
        **({f"{site}/staticfiles": "Nyxmon static files"} if cfg.include_static else {}),
        **({cfg.logs_path: "Nyxmon logs"} if cfg.include_logs else {}),
    }
    for path, what in required.items():
        if not exists(path):
            raise DeployError(f"nyxmon_backup: {what} not found: {path}")
    version = "unknown"
    if exists(cfg.python_bin):
        command = "import nyxmon, sys; sys.stdout.write(getattr(nyxmon, '__version__', 'unknown'))"
        version = output(f"{shlex.quote(cfg.python_bin)} -c {shlex.quote(command)}").strip()
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("nyxmon_backup: cannot read the host's time")
    name = f"{cfg.prefix}-{stamp}"
    backup_dir = f"{cfg.root}/{name}"

    apt.packages(name="Ensure sqlite3 is installed", packages=["sqlite3"])
    copies = [
        f"0600:{site}/.env:config/.env",
        f"0600:{site}/pyproject.toml:config/pyproject.toml",
        f"0600:{site}/uv.lock:config/uv.lock",
        *(f"0600:{unit}:systemd/{unit.rpartition('/')[2]}" for unit in UNITS),
        "0600:/etc/traefik/dynamic/nyxmon.yml:traefik/nyxmon.yml",
    ]
    server.shell(
        name="Copy nyxmon state",
        commands=[
            script(
                FILES / "backup.sh",
                {
                    "REQUIRED_MOUNT": cfg.required_mount or "",
                    "RECORD": flag(cfg.retention),
                    "ROOT": cfg.root,
                    "DIR": backup_dir,
                    "DB": f"{site}/db.sqlite3",
                    "STOP": flag(cfg.stop_services),
                    "SQLITE_BACKUP": flag(cfg.use_sqlite_backup),
                    **SQLITE_BACKUP_SETTINGS,
                    "DELETE": flag(cfg.use_delete),
                    "STOP_ORDER": STOP_ORDER,
                    "START_ORDER": START_ORDER,
                    "DIRS": (
                        f"1:{site}/media:media",
                        f"{flag(cfg.include_static)}:{site}/staticfiles:static",
                        f"{flag(cfg.include_cache)}:{site}/cache:cache",
                        f"{flag(cfg.include_logs)}:{cfg.logs_path}:logs",
                    ),
                    "COPIES": copies,
                },
            )
        ],
        _shell_executable="bash",
    )
    files.put(
        name="Write the backup metadata",
        src=StringIO(backup_metadata(cfg, stamp=stamp, version=version)),
        dest=f"{backup_dir}/metadata.yml",
        user="root",
        group="root",
        mode="0600",
    )
    if cfg.generate_checksums:
        server.shell(
            name="Generate the checksum manifest",
            commands=[
                f"cd {shlex.quote(backup_dir)} && find . -type f ! -name manifest.sha256 -print0 "
                "| sort -z | xargs -0 sha256sum > manifest.sha256"
            ],
            _shell_executable="bash",
        )
    archive = f"{backup_dir}.tar.gz"
    if cfg.create_archive:
        server.shell(
            name=f"Create {archive}",
            commands=[
                f"(umask 077; cd {shlex.quote(cfg.root)} && tar -C {shlex.quote(cfg.root)} -czf {name}.tar.gz {name})"
                f" && chmod 0600 {shlex.quote(archive)}"
            ],
        )
    if cfg.retention:
        server.shell(
            name="Prune local snapshots",
            commands=[retention(cfg, cfg.root, name, stamp)],
            _shell_executable="bash",
        )
    if cfg.create_archive and cfg.fetch_local:
        local_dir = str(cfg.local_dir or Path.home() / "backups" / "nyxmon")
        python.call(name=f"Ensure {local_dir} (0700)", function=private_local_dir, path=local_dir)
        files.get(name="Fetch the backup archive", src=archive, dest=f"{local_dir}/{name}.tar.gz")


@deploy("nyxmon restore")
def deploy_nyxmon_restore(cfg: NyxmonRestoreConfig) -> None:
    """Restore a backup archive over nyxmon, with a safety snapshot and rollback."""

    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("nyxmon_restore: cannot read the host's time")
    site, owner = cfg.site_path, cfg.site_owner
    server.shell(
        name="Restore nyxmon" + (" (dry run)" if cfg.dry_run else ""),
        commands=[
            script(
                FILES / "restore.sh",
                {
                    "REQUIRED_MOUNT": cfg.required_mount or "",
                    "HOST_NAME": cfg.host_name,
                    "STAMP": stamp,
                    "ARCHIVE": cfg.archive,
                    "SEARCH_ROOT": cfg.search_root,
                    "STAGING_BASE": cfg.staging_dir,
                    "STAGING_MODE": "0700",
                    "VALIDATE": flag(cfg.validate_checksums),
                    "CHECK_DISK": flag(cfg.check_disk_space),
                    "MULTIPLIER": str(cfg.disk_space_multiplier),
                    "DRY_RUN": flag(cfg.dry_run),
                    "SITE": site,
                    "LOGS": cfg.logs_path,
                    "DB": f"{site}/db.sqlite3",
                    "OWNER": owner,
                    "GROUP": cfg.site_group,
                    "SAFETY": flag(cfg.create_safety_backup),
                    "SAFETY_PREFIX": cfg.safety_backup_prefix,
                    "SAFETY_DELETE": flag(cfg.safety_rsync_delete),
                    "CLEANUP_SAFETY": flag(cfg.cleanup_safety_backup),
                    "REQUIRED_FIELDS": ("timestamp", "host", "site_path"),
                    "STOP_ORDER": STOP_ORDER,
                    "START_ORDER": START_ORDER,
                    "PRIMARY": "nyxmon.service",
                    "VERIFY_SQLITE": flag(cfg.verify_sqlite),
                    "DIRS": (
                        f"media:{site}/media",
                        f"static:{site}/staticfiles",
                        f"cache:{site}/cache",
                        f"logs:{cfg.logs_path}",
                    ),
                    "CONFIGS": (
                        f"0600:.env:{site}/.env",
                        f"0644:pyproject.toml:{site}/pyproject.toml",
                        f"0644:uv.lock:{site}/uv.lock",
                    ),
                    "SYSTEM_FILES": flag(cfg.restore_system_files),
                    "UNITS": UNITS,
                    "FIX_OWNERSHIP": flag(cfg.fix_ownership),
                    "MANAGE": f"{site}/src/django/manage.py",
                    "VERIFY_HTTP": flag(cfg.verify_http),
                    "HEALTH_URL": cfg.health_url,
                    # Production settings redirect plain HTTP; the probe sends
                    # what the reverse proxy sends (trusted from loopback).
                    "HEALTH_HEADERS": ("-H", "X-Forwarded-Proto: https"),
                    "HEALTH_STATUS": str(cfg.health_expected_status),
                    "HEALTH_RETRIES": str(cfg.health_retries),
                    "HEALTH_DELAY": str(cfg.health_delay),
                },
            )
        ],
        _shell_executable="bash",
    )


@deploy("Remove nyxmon")
def deploy_nyxmon_remove(cfg: NyxmonRemoveConfig) -> None:
    """Stop and remove nyxmon: units, route, user, home with the database, temp files."""

    if not cfg.confirm:
        raise DeployError(
            "nyxmon_remove: removal not confirmed; this deletes nyxmon, its user and all "
            "monitoring data (SQLite database included). Set confirm to proceed."
        )
    names = (cfg.service_name, cfg.monitor_service_name)
    stop_disable([f"{name}.service" for name in names])
    reload = False
    for name in names:
        reload = remove_path(f"/etc/systemd/system/{name}.service") or reload
        directory = f"/etc/systemd/system/{name}.service.d"
        reload = remove_path(f"{directory}/sqlite-privacy.conf") or reload
        if exists(directory) and not output(
            f"find {shlex.quote(directory)} -mindepth 1 -maxdepth 1 ! -name sqlite-privacy.conf -print -quit"
        ):
            # rmdir refuses a directory populated after the probe; never recursively remove operator drop-ins.
            server.shell(name=f"Remove empty {directory}", commands=[f"rmdir -- {shlex.quote(directory)}"])
            reload = True
    remove_path(cfg.traefik_config_file)
    databases = output(f"find {shlex.quote(cfg.home)} -name '*.sqlite3*'").split()
    if databases:
        host.noop(f"Database files to be removed: {', '.join(databases)}")
    kill_user_processes(cfg.user)
    remove_path(cfg.home)
    remove_account(cfg.user, cfg.group)
    # The role's ``rm -rf /tmp/*nyxmon*`` (non-hidden entries directly in /tmp).
    for path in output("find /tmp -mindepth 1 -maxdepth 1 -name '*nyxmon*' ! -name '.*'").splitlines():
        if path.startswith("/tmp/"):
            server.shell(name=f"Remove {path}", commands=[f"rm -rf {shlex.quote(path)}"])
    for name in names:
        reload = remove_path(f"/run/systemd/system/{name}.service.d") or reload
    if reload:
        systemd.daemon_reload(name="Reload systemd")


__all__ = [
    "NyxmonBackupConfig",
    "NyxmonRemoveConfig",
    "NyxmonRestoreConfig",
    "Prefix",
    "deploy_nyxmon_backup",
    "deploy_nyxmon_remove",
    "deploy_nyxmon_restore",
]
