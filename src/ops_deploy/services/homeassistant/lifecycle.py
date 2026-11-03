"""Home Assistant backup and restore (the ``homeassistant_backup`` and ``homeassistant_restore`` roles).

A backup is ``<root>/<prefix>-<timestamp>`` with ``config/`` (the recorder
database as a ``sqlite3 .backup`` copy), ``data/``, ``logs/``, the included
Thread/Matter state directories, ``homeassistant.service``,
``homeassistant.traefik.yml``, ``metadata.yml`` and ``manifest.sha256``,
packed as ``<dir>.tar.gz`` with the directory as the archive's only
top-level entry, as the role writes it. Home Assistant keeps running during
a backup, as with the role. Either tool restores the other's archives.

Backup and restore run on the host as one bash script each (``files/``), so
the role's ``block``/``always``/``rescue`` structure keeps its meaning: the
staging directory always goes, and a failed restore puts the pre-restore
safety snapshot of the site directory back and starts Home Assistant again.

Deliberate differences from the roles:

- ``metadata.yml`` is valid YAML. The role renders its ``extra_paths`` list
  onto the key's line, which no YAML parser reads; restore therefore checks
  the required fields and the host line by line, so the role's archives
  restore too.
- The role rolls back only after a failed verification; here a failure while
  the files are copied rolls back as well, and the rollback also starts the
  Thread and Matter services the restore stopped.
- The role sets an existing ``homeassistant`` account's shell to
  ``/usr/sbin/nologin`` (the deploy sets ``/bin/bash`` again); here the
  restore creates the account only when it is missing. A dry run changes no
  account.
- A missing archive is not uploaded from the controller's cache; copy it to
  the search root first (ops-control's restore prelude does).
- Restoring the Traefik route waits for no Traefik transaction, like every
  route writer on the host.

``required_mount`` keeps the backup root and the restore's staging directory
on an external disk, and ``retain_count``/``retain_days`` limit the snapshots
a backup keeps (:mod:`ops_deploy.services._lifecycle.local_backup`).
"""

from __future__ import annotations

import shlex
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated

import yaml
from pydantic import Field, StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server

from ops_deploy.base._common import AbsolutePath, output
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services._lifecycle import exists, flag, private_local_dir, script
from ops_deploy.services._lifecycle.local_backup import MountGuard, SnapshotRetention, retention

FILES = Path(__file__).parent / "files"
Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
# ``latest``, or an archive name below the search root.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|[A-Za-z0-9._+-]+\.tar\.gz)$")]
Hostname = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
Url = Annotated[str, Field(pattern=r"^https?://[A-Za-z0-9.:/_-]+$")]
HeaderName = Annotated[str, Field(pattern=r"^[A-Za-z0-9-]+$")]
FileMode = Annotated[str, Field(pattern=r"^0?[0-7]{3}$")]
REQUIRED_FIELDS = ("timestamp", "host", "config_path", "data_path")


def _inside(path: str, parent: str) -> bool:
    return path == parent or PurePosixPath(path).is_relative_to(parent)


class _Paths(MountGuard):
    config_path: AbsolutePath = "/home/homeassistant/site/config"
    data_path: AbsolutePath = "/home/homeassistant/site/data"
    logs_path: AbsolutePath = "/home/homeassistant/site/logs"
    # None: ``<data_path>/matter-server``, the role default.
    matter_server_storage_path: AbsolutePath | None = None
    # The role's ``homeassistant_matter_server_chip_factory_dir``; "" turns it off.
    matter_server_chip_factory_dir: str = "/data"
    otbr_state_path: AbsolutePath = "/var/lib/thread"
    service_unit_path: AbsolutePath = "/etc/systemd/system/homeassistant.service"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/homeassistant.yml"

    @model_validator(mode="after")
    def _canonical_paths(self) -> _Paths:
        # The scripts create, chown and remove below these paths: no "/./",
        # "/../", "//" or trailing "/" spellings that resolve elsewhere.
        for name, value in self.model_dump().items():
            if isinstance(value, str) and value.startswith("/"):
                path = PurePosixPath(value)
                if value != str(path) or ".." in path.parts or path == PurePosixPath("/"):
                    raise ValueError(f"{name} must be a canonical absolute path other than /")
        return self

    @property
    def matter_storage(self) -> str:
        return self.matter_server_storage_path or f"{self.data_path}/matter-server"

    def matter_storage_separate(self) -> bool:
        """The role's include rule: Matter storage outside the data directory."""
        return not _inside(self.matter_storage, self.data_path)

    def chip_factory_separate(self) -> bool:
        factory = self.matter_server_chip_factory_dir
        return bool(factory) and factory != "/data" and not factory.startswith(self.data_path + "/")


class HomeAssistantBackupConfig(_Paths, SnapshotRetention):
    # The metadata's ``host`` (Ansible's ``inventory_hostname``) and ``ansible_user``.
    host_name: Hostname
    ansible_user: str = ""
    root: AbsolutePath = "/opt/backups/homeassistant"
    prefix: Prefix = "manual"
    # None: ``<config_path>/home-assistant_v2.db``.
    sqlite_path: AbsolutePath | None = None
    use_sqlite_backup: StrictBool = True
    include_thread: StrictBool = True
    include_logs: StrictBool = True
    use_delete: StrictBool = True
    generate_checksums: StrictBool = True
    create_archive: StrictBool = True
    fetch_local: StrictBool = True
    # None: ``~/backups/homeassistant`` on the controller.
    local_dir: Path | None = None
    owner: UnixUser = "root"
    group: UnixUser = "root"
    file_mode: FileMode = "0644"
    dir_mode: FileMode = "0700"

    @property
    def database(self) -> str:
        return self.sqlite_path or f"{self.config_path}/home-assistant_v2.db"

    def extra_dirs(self) -> list[tuple[str, str]]:
        """The role's default ``homeassistant_backup_extra_dirs`` that it includes: (name, source)."""
        candidates = [
            ("thread", self.otbr_state_path, self.include_thread),
            ("matter-server", self.matter_storage, self.matter_storage_separate()),
            ("matter-chip-factory", self.matter_server_chip_factory_dir, self.chip_factory_separate()),
        ]
        return [(name, src) for name, src, include in candidates if include]

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}


class HomeAssistantRestoreConfig(_Paths):
    host_name: Hostname
    archive: ArchiveName = "latest"
    search_root: AbsolutePath = "/opt/backups/homeassistant"
    # Named in the missing-archive message only (the role's local cache).
    local_cache: str = "~/backups/homeassistant"
    staging_dir: AbsolutePath = "/tmp/homeassistant-restore"
    validate_checksums: StrictBool = True
    enforce_host_match: StrictBool = True
    dry_run: StrictBool = False
    check_disk_space: StrictBool = True
    disk_space_multiplier: float = Field(default=2.0, gt=0)
    site_root: AbsolutePath = "/home/homeassistant/site"
    service_name: ServiceName = "homeassistant"
    # The inventory's ``homeassistant_manage_matter_server`` (role default false).
    manage_matter_server: StrictBool = False
    matter_service_name: ServiceName = "matter-server"
    manage_otbr_state: StrictBool = True
    otbr_service_name: ServiceName = "otbr-agent"
    start_timeout: int = Field(default=60, ge=0)
    start_poll_interval: int = Field(default=3, ge=1)
    verify_http: StrictBool = False
    health_url: Url = "http://localhost:10020/auth/providers"
    health_retries: int = Field(default=5, ge=0)
    health_delay: int = Field(default=5, ge=0)
    health_expected_status: int = Field(default=200, ge=100, le=599)
    # None: the host's default IPv4 address (Ansible's ``ansible_default_ipv4``); "" sends no header.
    health_forwarded_for: str | None = Field(default=None, pattern=r"^[0-9A-Fa-f.:]*$")
    health_forwarded_proto: str = Field(default="http", pattern=r"^[a-z]*$")
    health_headers: dict[HeaderName, str] = Field(default_factory=dict)
    restore_system_files: StrictBool = False
    fix_ownership: StrictBool = True
    site_owner: UnixUser = "homeassistant"
    site_group: UnixUser = "homeassistant"
    create_safety_backup: StrictBool = True
    safety_backup_prefix: Prefix = "pre-restore"
    safety_rsync_delete: StrictBool = True
    cleanup_safety_backup: StrictBool = True
    cleanup_after_rollback: StrictBool = False
    rollback_on_failure: StrictBool = True

    def extra_dirs(self) -> list[tuple[str, str, str, str, str]]:
        """The role's default ``homeassistant_restore_extra_dirs`` that it includes."""
        owner, group = self.site_owner, self.site_group
        candidates = [
            ("thread", self.otbr_state_path, "root", "root", self.manage_otbr_state),
            ("matter-server", self.matter_storage, owner, group,
             self.manage_matter_server and self.matter_storage_separate()),
            ("matter-chip-factory", self.matter_server_chip_factory_dir, owner, group,
             self.manage_matter_server and self.chip_factory_separate()),
        ]  # fmt: skip
        return [(name, dest, o, g, "0750") for name, dest, o, g, include in candidates if include]

    def guarded_paths(self) -> dict[str, str]:
        return {"staging_dir": self.staging_dir}


def backup_metadata(cfg: HomeAssistantBackupConfig, *, stamp: str) -> str:
    """``metadata.yml`` with the role's keys, quoting and ``True``/``False``, as valid YAML."""

    def quoted(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    lines = [
        f"timestamp: {quoted(stamp)}",
        f"host: {quoted(cfg.host_name)}",
        f"config_path: {quoted(cfg.config_path)}",
        f"data_path: {quoted(cfg.data_path)}",
        f"logs_included: {cfg.include_logs}",
        f"traefik_config: {quoted(cfg.traefik_config_path)}",
        f"service_unit: {quoted(cfg.service_unit_path)}",
    ]
    extras = cfg.extra_dirs()
    if not extras:
        lines.append("extra_paths: []")
    else:
        lines.append("extra_paths:")
        for name, src in extras:
            lines += [f"  - name: {quoted(name)}", f"    path: {quoted(src)}"]
    lines.append(f"ansible_user: {quoted(cfg.ansible_user)}")
    text = "\n".join(lines) + "\n"
    yaml.safe_load(text)  # never write what the restore cannot read
    return text


@deploy("Home Assistant backup")
def deploy_homeassistant_backup(cfg: HomeAssistantBackupConfig) -> None:
    """Snapshot Home Assistant's state into a backup directory, pack it and fetch the archive."""

    if not exists(cfg.config_path):
        raise DeployError(f"homeassistant_backup: Home Assistant config directory not found: {cfg.config_path}")
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("homeassistant_backup: cannot read the host's time")
    name = f"{cfg.prefix}-{stamp}"
    backup_dir = f"{cfg.root}/{name}"
    server.shell(
        name="Copy Home Assistant state",
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
                    "CONFIG": cfg.config_path,
                    "DATA": cfg.data_path,
                    "LOGS": cfg.logs_path,
                    "INCLUDE_LOGS": flag(cfg.include_logs),
                    "DB": cfg.database,
                    "SQLITE_BACKUP": flag(cfg.use_sqlite_backup),
                    "DELETE": flag(cfg.use_delete),
                    "EXTRAS": [f"{extra}:{src}" for extra, src in cfg.extra_dirs()],
                    "COPIES": [
                        f"{cfg.service_unit_path}:homeassistant.service",
                        f"{cfg.traefik_config_path}:homeassistant.traefik.yml",
                    ],
                },
            )
        ],
        _shell_executable="bash",
    )
    files.put(
        name="Write the backup metadata",
        src=StringIO(backup_metadata(cfg, stamp=stamp)),
        dest=f"{backup_dir}/metadata.yml",
        user=cfg.owner,
        group=cfg.group,
        mode=cfg.file_mode,
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
        local_dir = str(cfg.local_dir or Path.home() / "backups" / "homeassistant")
        python.call(name=f"Ensure {local_dir} (0700)", function=private_local_dir, path=local_dir)
        files.get(name="Fetch the backup archive", src=archive, dest=f"{local_dir}/{name}.tar.gz")


@deploy("Home Assistant restore")
def deploy_homeassistant_restore(cfg: HomeAssistantRestoreConfig) -> None:
    """Restore a backup archive over Home Assistant, with a safety snapshot and rollback."""

    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("homeassistant_restore: cannot read the host's time")
    headers: list[str] = []
    for header, value in cfg.health_headers.items():
        headers += ["-H", f"{header}: {value}"]
    forwarded = "@default-ipv4" if cfg.health_forwarded_for is None else cfg.health_forwarded_for
    server.shell(
        name="Restore Home Assistant" + (" (dry run)" if cfg.dry_run else ""),
        commands=[
            script(
                FILES / "restore.sh",
                {
                    "REQUIRED_MOUNT": cfg.required_mount or "",
                    "HOST_NAME": cfg.host_name,
                    "STAMP": stamp,
                    "ARCHIVE": cfg.archive,
                    "SEARCH_ROOT": cfg.search_root,
                    "LOCAL_CACHE": cfg.local_cache,
                    "STAGING_BASE": cfg.staging_dir,
                    "STAGING_MODE": "0700",
                    "VALIDATE": flag(cfg.validate_checksums),
                    "ENFORCE_HOST": flag(cfg.enforce_host_match),
                    "REQUIRED_FIELDS": REQUIRED_FIELDS,
                    "CHECK_DISK": flag(cfg.check_disk_space),
                    "MULTIPLIER": str(cfg.disk_space_multiplier),
                    "DRY_RUN": flag(cfg.dry_run),
                    "SITE": cfg.site_root,
                    "OWNER": cfg.site_owner,
                    "GROUP": cfg.site_group,
                    "SAFETY": flag(cfg.create_safety_backup),
                    "SAFETY_PREFIX": cfg.safety_backup_prefix,
                    "SAFETY_DELETE": flag(cfg.safety_rsync_delete),
                    "CLEANUP_SAFETY": flag(cfg.cleanup_safety_backup),
                    "CLEANUP_AFTER_ROLLBACK": flag(cfg.cleanup_after_rollback),
                    "ROLLBACK": flag(cfg.rollback_on_failure),
                    "SERVICE": cfg.service_name,
                    "UNIT_PATH": cfg.service_unit_path,
                    "TRAEFIK_PATH": cfg.traefik_config_path,
                    "ROUTE_GUARD": shlex.split(route_guard_command()),
                    "MANAGE_MATTER": flag(cfg.manage_matter_server),
                    "MATTER_SERVICE": cfg.matter_service_name,
                    "MANAGE_OTBR": flag(cfg.manage_otbr_state),
                    "OTBR_SERVICE": cfg.otbr_service_name,
                    "DIRS": (
                        f"config:{cfg.config_path}:0",
                        f"data:{cfg.data_path}:0",
                        f"logs:{cfg.logs_path}:1",
                    ),
                    "EXTRAS": [":".join(extra) for extra in cfg.extra_dirs()],
                    "SYSTEM_FILES": flag(cfg.restore_system_files),
                    "FIX_OWNERSHIP": flag(cfg.fix_ownership),
                    "START_RETRIES": str(max(cfg.start_timeout // cfg.start_poll_interval, 1)),
                    "START_POLL": str(cfg.start_poll_interval),
                    "VERIFY_HTTP": flag(cfg.verify_http),
                    "HEALTH_URL": cfg.health_url,
                    "HEALTH_HEADERS": headers,
                    "FORWARDED_FOR": forwarded,
                    "FORWARDED_PROTO": cfg.health_forwarded_proto,
                    "HEALTH_STATUS": str(cfg.health_expected_status),
                    "HEALTH_RETRIES": str(cfg.health_retries),
                    "HEALTH_DELAY": str(cfg.health_delay),
                },
            )
        ],
        _shell_executable="bash",
    )


__all__ = [
    "HomeAssistantBackupConfig",
    "HomeAssistantRestoreConfig",
    "backup_metadata",
    "deploy_homeassistant_backup",
    "deploy_homeassistant_restore",
]
