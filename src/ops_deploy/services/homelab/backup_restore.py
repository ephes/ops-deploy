"""homelab backup and restore (the ``homelab_backup`` and ``homelab_restore`` roles).

A backup is ``<root>/<prefix>-<timestamp>`` with ``database/db.sqlite3``,
``static/``, ``media/``, ``cache/`` (empty unless included), ``env/.env``,
``configs/homelab.service``, ``configs/traefik.yml``, ``metadata.yml`` and
``manifest.sha256``, packed as ``<dir>.tar.gz`` with the directory as the
archive's only top-level entry, exactly as the role writes it. Either tool
restores the other's archives.

Backup and restore run on the host as one bash script each (``files/``), so
the role's ``block``/``always`` structure keeps its meaning: an offline
SQLite copy starts homelab again whatever the copy did, and the restore's
staging directory always goes. As with the role, a failed restore leaves the
pre-restore copy of the site (``<site>.pre-restore-<timestamp>``) in place and
does not roll back by itself.

Deliberate differences from the roles:

- ``archive`` is ``latest`` or a name directly below the search root, never
  an absolute path (ops-control's restore prelude uploads archives there).
- After the restored directories are copied, ``static``, ``media`` and
  ``cache`` get the modes the restore created them with again: ``rsync -a``
  copies the backup's ``0700`` directory mode onto them.
- Restoring the Traefik route waits for no Traefik transaction, like every
  route writer on the host.
- The controller copy of the archive is ``0600``, as the role leaves it.

``required_mount`` keeps the backup root and the restore's staging directory
on an external disk, and ``retain_count``/``retain_days`` limit the snapshots
a backup keeps (:mod:`ops_deploy.services._lifecycle.local_backup`).
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Literal

from pydantic import Field, StrictBool
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server

from ops_deploy.base._common import output
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services._lifecycle import exists, flag, private_local_dir, script
from ops_deploy.services._lifecycle.canonical import (
    ArchiveName,
    CanonicalPath,
    FileMode,
    Hostname,
    LibraryVersion,
    Prefix,
    Url,
)
from ops_deploy.services._lifecycle.local_backup import MountGuard, SnapshotRetention, retention

FILES = Path(__file__).parent / "files"
SLUG = "homelab"


class _Site(MountGuard):
    """``homelab_shared``'s paths and identity."""

    user: UnixUser = "homelab"
    group: UnixUser = "homelab"
    service_name: ServiceName = "homelab"
    site_path: CanonicalPath = "/home/homelab/site"
    # None: below ``site_path``, as the shared defaults derive them.
    database_path: CanonicalPath | None = None
    static_root: CanonicalPath | None = None
    media_root: CanonicalPath | None = None
    cache_dir: CanonicalPath | None = None
    env_file: CanonicalPath | None = None
    systemd_unit_path: CanonicalPath = "/etc/systemd/system/homelab.service"
    traefik_config_path: CanonicalPath = "/etc/traefik/dynamic/homelab.yml"

    @property
    def database(self) -> str:
        return self.database_path or f"{self.site_path}/db.sqlite3"

    @property
    def static(self) -> str:
        return self.static_root or f"{self.site_path}/staticfiles"

    @property
    def media(self) -> str:
        return self.media_root or f"{self.site_path}/media"

    @property
    def cache(self) -> str:
        return self.cache_dir or f"{self.site_path}/cache"

    @property
    def env(self) -> str:
        return self.env_file or f"{self.site_path}/.env"


class HomelabBackupConfig(_Site, SnapshotRetention):
    # The metadata's ``host`` (Ansible's ``inventory_hostname``).
    host_name: Hostname
    ops_library_version: LibraryVersion = "unknown"
    root: CanonicalPath = "/opt/backups/homelab"
    prefix: Prefix = "manual"
    include_static: StrictBool = True
    include_media: StrictBool = True
    include_cache: StrictBool = False
    include_env: StrictBool = True
    include_systemd: StrictBool = True
    include_traefik: StrictBool = True
    rsync_use_delete: StrictBool = True
    git_check_enabled: StrictBool = True
    # True: stop homelab and copy the file; otherwise ``sqlite3 .backup``
    # (falling back to the offline copy when every attempt fails).
    force_stop: StrictBool = False
    sqlite_retries: int = Field(default=3, ge=0)
    manifest_enabled: StrictBool = True
    archive_format: Literal["tar.gz"] = "tar.gz"
    create_archive: StrictBool = True
    fetch_local: StrictBool = True
    # None: ``~/backups/homelab`` on the controller.
    local_dir: Path | None = None
    owner: UnixUser = "root"
    group: UnixUser = "root"
    dir_mode: FileMode = "0700"
    file_mode: FileMode = "0600"

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}


class HomelabRestoreConfig(_Site):
    host_name: Hostname
    ops_library_version: LibraryVersion = "unknown"
    archive: ArchiveName = "latest"
    search_root: CanonicalPath = "/opt/backups/homelab"
    staging_dir: CanonicalPath = "/tmp/homelab-restore"
    staging_mode: FileMode = "0700"
    dry_run: StrictBool = False
    validate_checksums: StrictBool = True
    cleanup: StrictBool = True
    allow_version_mismatch: StrictBool = False
    restore_env: StrictBool = True
    rebuild_static: StrictBool = False
    use_rsync_delete: StrictBool = True
    safe_snapshot_prefix: Prefix = "pre-restore"
    # True deletes the pre-restore copy after a successful restore.
    safe_snapshot_delete: StrictBool = False
    create_safe_snapshot: StrictBool = True
    reload_traefik: StrictBool = True
    reload_systemd: StrictBool = True
    traefik_service_name: ServiceName = "traefik"
    venv_bin: CanonicalPath | None = None
    django_settings_module: str = Field(default="config.settings.production", pattern=r"^[A-Za-z0-9_.]+$")
    verify_http: StrictBool = True
    # None: the role's ``http://127.0.0.1:10010/admin/``.
    healthcheck_url: Url | None = None
    healthcheck_retries: int = Field(default=5, ge=0)
    healthcheck_delay: int = Field(default=3, ge=0)
    expected_content: str = Field(default="", pattern=r"^[^\n\r]*$")
    fix_permissions: StrictBool = True
    env_mode: FileMode = "0600"
    media_mode: FileMode = "0755"
    required_fields: tuple[str, ...] = ("slug", "timestamp", "host")

    def guarded_paths(self) -> dict[str, str]:
        return {"staging_dir": self.staging_dir}


def backup_metadata(cfg: HomelabBackupConfig, *, stamp: str, commit: str, sqlite_mode: str) -> str:
    """``metadata.yml`` exactly as the role's template renders it."""

    def text(value: str) -> str:
        return f'"{value}"'

    lines = {
        "slug": text(SLUG),
        "timestamp": text(stamp),
        "host": text(cfg.host_name),
        "ops_library_version": text(cfg.ops_library_version),
        "source_commit": text(commit),
        "sqlite_mode": text(sqlite_mode),
        **{
            f"include_{part}": str(getattr(cfg, f"include_{part}"))
            for part in ("static", "media", "cache", "env", "systemd", "traefik")
        },
        "site_path": text(cfg.site_path),
        "database_path": text(cfg.database),
        "static_root": text(cfg.static),
        "media_root": text(cfg.media),
        "cache_dir": text(cfg.cache),
        "env_file": text(cfg.env),
    }
    return "".join(f"{key}: {value}\n" for key, value in lines.items())


def _restrict_local(path: str) -> None:
    # ``fetch`` writes the copy with the controller's umask; the archive holds the .env.
    if os.path.exists(path):
        os.chmod(path, 0o600)


def _stamp(role: str) -> str:
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError(f"{role}: cannot read the host's time")
    return stamp


@deploy("homelab backup")
def deploy_homelab_backup(cfg: HomelabBackupConfig) -> None:
    """Copy homelab's database, directories and config into a backup directory, pack and fetch it."""

    if not exists(cfg.site_path):
        raise DeployError(f"homelab_backup: homelab_site_path ({cfg.site_path}) must exist on the target host")
    commit = "unknown"
    if cfg.git_check_enabled and exists(f"{cfg.site_path}/.git"):
        found = output(f"git -C {shlex.quote(cfg.site_path)} rev-parse HEAD 2>/dev/null || true").strip()
        commit = found or "unknown"
    stamp = _stamp("homelab_backup")
    name = f"{cfg.prefix}-{stamp}"
    backup_dir = f"{cfg.root}/{name}"
    server.shell(
        name="Back up homelab",
        commands=[
            script(
                FILES / "backup.sh",
                {
                    "REQUIRED_MOUNT": cfg.required_mount or "",
                    "RECORD": flag(cfg.retention),
                    "ROOT": cfg.root,
                    "DIR": backup_dir,
                    "OWNER": cfg.owner,
                    "GROUP": cfg.group,
                    "DIR_MODE": cfg.dir_mode,
                    "FILE_MODE": cfg.file_mode,
                    "DB": cfg.database,
                    "SERVICE": f"{cfg.service_name}",
                    "FORCE_STOP": flag(cfg.force_stop),
                    # Ansible's ``retries`` with ``until``: the first try plus the retries.
                    "SQLITE_ATTEMPTS": str(cfg.sqlite_retries + 1),
                    "DELETE": flag(cfg.rsync_use_delete),
                    "DIRS": (
                        f"{flag(cfg.include_static)}:{cfg.static}:static",
                        f"{flag(cfg.include_media)}:{cfg.media}:media",
                        f"{flag(cfg.include_cache)}:{cfg.cache}:cache",
                    ),
                    "COPIES": (
                        f"{flag(cfg.include_env)}:{cfg.env}:env/.env",
                        f"{flag(cfg.include_systemd)}:{cfg.systemd_unit_path}:configs/homelab.service",
                        f"{flag(cfg.include_traefik)}:{cfg.traefik_config_path}:configs/traefik.yml",
                    ),
                    "METADATA": backup_metadata(cfg, stamp=stamp, commit=commit, sqlite_mode="@SQLITE_MODE@"),
                    "MANIFEST": flag(cfg.manifest_enabled),
                    "ARCHIVE": flag(cfg.create_archive),
                },
            )
        ],
        _shell_executable="bash",
    )
    if cfg.retention:
        server.shell(
            name="Prune local snapshots",
            commands=[retention(cfg, cfg.root, name, stamp)],
            _shell_executable="bash",
        )
    if cfg.create_archive and cfg.fetch_local:
        local_dir = str(cfg.local_dir or Path.home() / "backups" / SLUG)
        local = f"{local_dir}/{name}.tar.gz"
        python.call(name=f"Ensure {local_dir} (0700)", function=private_local_dir, path=local_dir)
        files.get(name="Fetch the backup archive", src=f"{backup_dir}.tar.gz", dest=local)
        python.call(name="Restrict the local archive copy (0600)", function=_restrict_local, path=local)


@deploy("homelab restore")
def deploy_homelab_restore(cfg: HomelabRestoreConfig) -> None:
    """Restore a backup archive over homelab, keeping a pre-restore copy of the site."""

    stamp = _stamp("homelab_restore")
    server.shell(
        name="Restore homelab" + (" (dry run)" if cfg.dry_run else ""),
        commands=[
            script(
                FILES / "restore.sh",
                {
                    "REQUIRED_MOUNT": cfg.required_mount or "",
                    "STAMP": stamp,
                    "SLUG": SLUG,
                    "LIBRARY_VERSION": cfg.ops_library_version,
                    "ALLOW_MISMATCH": flag(cfg.allow_version_mismatch),
                    "ARCHIVE": cfg.archive,
                    "SEARCH_ROOT": cfg.search_root,
                    "STAGING": cfg.staging_dir,
                    "STAGING_MODE": cfg.staging_mode,
                    "REQUIRED_FIELDS": cfg.required_fields,
                    "VALIDATE": flag(cfg.validate_checksums),
                    "DRY_RUN": flag(cfg.dry_run),
                    "CLEANUP": flag(cfg.cleanup),
                    "SITE": cfg.site_path,
                    "USER_NAME": cfg.user,
                    "GROUP_NAME": cfg.group,
                    "SERVICE": cfg.service_name,
                    "DB": cfg.database,
                    "STATIC": cfg.static,
                    "MEDIA": cfg.media,
                    "CACHE": cfg.cache,
                    "ENV_FILE": cfg.env,
                    "UNIT": cfg.systemd_unit_path,
                    "TRAEFIK": cfg.traefik_config_path,
                    "TRAEFIK_SERVICE": cfg.traefik_service_name,
                    "ROUTE_GUARD": shlex.split(route_guard_command()),
                    "SAFETY": flag(cfg.create_safe_snapshot),
                    "SAFETY_PREFIX": cfg.safe_snapshot_prefix,
                    "SAFETY_DELETE": flag(cfg.safe_snapshot_delete),
                    "MEDIA_MODE": cfg.media_mode,
                    "ENV_MODE": cfg.env_mode,
                    "RSYNC_DELETE": flag(cfg.use_rsync_delete),
                    "RESTORE_ENV": flag(cfg.restore_env),
                    "REBUILD_STATIC": flag(cfg.rebuild_static),
                    "FIX_PERMISSIONS": flag(cfg.fix_permissions),
                    "RELOAD_SYSTEMD": flag(cfg.reload_systemd),
                    "RELOAD_TRAEFIK": flag(cfg.reload_traefik),
                    "VENV_BIN": cfg.venv_bin or f"{cfg.site_path}/.venv/bin",
                    "SETTINGS": cfg.django_settings_module,
                    "VERIFY_HTTP": flag(cfg.verify_http),
                    "HEALTH_URL": cfg.healthcheck_url or "http://127.0.0.1:10010/admin/",
                    "HEALTH_RETRIES": str(cfg.healthcheck_retries),
                    "HEALTH_DELAY": str(cfg.healthcheck_delay),
                    "EXPECTED": cfg.expected_content,
                },
            )
        ],
        _shell_executable="bash",
    )


__all__ = [
    "HomelabBackupConfig",
    "HomelabRestoreConfig",
    "backup_metadata",
    "deploy_homelab_backup",
    "deploy_homelab_restore",
]
