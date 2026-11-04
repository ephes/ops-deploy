"""Paperless-ngx backup and restore (the ``paperless_backup`` and ``paperless_restore`` roles).

A backup is ``<root>/<prefix>-<timestamp>/`` with ``database/<db>.sql``
(``pg_dump``), ``exporter/`` (``document_exporter``), ``media/``, ``data/``
(and ``logs``/``consume``/``export`` when included), ``config/``,
``systemd/``, ``traefik/``, ``ssh/``, ``metadata.yml`` and
``manifest.sha256``, packed as ``<dir>.tar.gz`` (or ``.tar.zst``) with the
directory as the archive's only top-level entry, exactly as the role writes
it. Either tool restores the other's archives.

The restore follows the role's phases in one host script (``files/``):
validate, prepare (disk check and the pre-restore safety snapshot, written by
``files/backup.sh`` with the role's overrides), restore (stop the services,
drop and create the database, ``document_importer`` or the SQL dump plus the
raw directories, config and system files) and verify (start the services,
PostgreSQL and HTTP checks). A failed verification restores the safety
snapshot raw and fails; a failure before verification leaves the services
stopped and the safety snapshot in place, as with the role.

Secrets (the exporter/importer passphrase and PostgreSQL passwords) reach the
host on the script's stdin only; passwords reach ``pg_dump``/``psql`` as a
passfile in a private directory owned by the PostgreSQL account, as the role
renders it.

Deliberate differences from the roles:

- ``archive`` is ``latest`` or an archive name directly below the search root,
  never an absolute path or an extracted directory, and a missing archive is
  not uploaded from the controller cache (ops-control's restore prelude does
  that before the restore runs).
- ``metadata.yml`` is read line by line (the role's and this port's layout),
  not as general YAML.
- The archive is fetched with pyinfra's ``files.get`` (the role's default
  method is ``synchronize``; ``fetch_method`` and ``report_size`` are not
  ported); the local copy ends ``0600`` either way.
- A route that differs from the live one is written only while no Traefik
  transaction holds its lock: a lock held before the services stop refuses
  the restore; a lock taken later leaves the route, the restore finishes and
  then fails (keeping the safety snapshot and the staging directory).
- The PostgreSQL account writes its passfiles itself; they live below one
  private directory per run that is always removed. The snapshot's dump is
  read as the owner of its directory (as root when that account cannot reach
  it) and staged by root for psql (the role chowns the snapshot's dump
  first); validation refuses a dump that is not a regular file.
- The role's safety-snapshot overrides win over the inventory's backup
  settings (the role applies ``safety_backup_vars`` after them); the snapshot
  always records the restore's host.
- The backup directory stays root's while root writes into it (the exporter
  and the dump account write only their own subdirectories); the role's
  owners and modes are applied at the end. The restore's safety snapshot
  stays root's: a rollback installs its unit files.
- The restore refuses a staging root that is not root's directory and
  creates its staging directory fresh.
- ``metadata.yml`` and ``manifest.sha256`` are fixed names (the role's
  ``metadata_file``/``manifest_file`` defaults).
- The safety snapshot's metadata records ``postgres.port`` 5432 (the role
  writes an empty value); the rollback plans its storage from the safety
  snapshot's own metadata, and the HTTP check does not follow redirects.

``required_mount`` keeps the backup root and the restore's staging directory on
an external disk, and ``retain_count``/``retain_days`` limit the snapshots a
backup keeps (:mod:`ops_deploy.services._lifecycle.local_backup`).
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server

from ops_deploy.base._common import output
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.helpers.probes import stdin_arguments
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services._lifecycle import flag, private_local_dir, script
from ops_deploy.services._lifecycle.canonical import CanonicalPath, FileMode, Hostname, Prefix, Url
from ops_deploy.services._lifecycle.local_backup import MountGuard, SnapshotRetention, retention

FILES = Path(__file__).parent / "files"
Identifier = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]*$")]
ArchiveName = Annotated[str, Field(pattern=r"^(latest|[A-Za-z0-9._+-]+\.tar\.(gz|zst))$")]
# Relative paths inside a backup directory (no "..", no leading "/").
Relative = Annotated[str, Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*$")]
Flags = Annotated[str, Field(pattern=r"^[A-Za-z0-9 =_.-]*$")]
Password = Annotated[SecretStr, Field()]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CopySpec(_Frozen):
    src: CanonicalPath
    dest: Relative


class RestoreFile(_Frozen):
    src: Relative
    dest: CanonicalPath
    owner: UnixUser = "paperless"
    group: UnixUser = "paperless"
    mode: FileMode = "0640"
    required: StrictBool = False


class StorageDir(_Frozen):
    name: Relative
    dest: CanonicalPath
    required: StrictBool = False
    metadata_flag: Annotated[str, Field(pattern=r"^[a-z_]*$")] = ""


class Placement(_Frozen):
    src: Relative
    dest: CanonicalPath


def _no_line_breaks(values: Mapping[str, SecretStr]) -> None:
    for name, value in values.items():
        text = value.get_secret_value()
        if "\n" in text or "\r" in text:
            raise ValueError(f"{name}: PostgreSQL passfile passwords and passphrases cannot contain line breaks.")


class PaperlessBackupConfig(SnapshotRetention):
    # The metadata's ``host`` (Ansible's ``inventory_hostname``).
    host_name: Hostname
    root: CanonicalPath = "/opt/backups/paperless"
    prefix: Prefix = "manual"
    owner: UnixUser = "root"
    group: UnixUser = "root"
    dir_mode: FileMode = "0750"
    file_mode: FileMode = "0640"
    archive_mode: FileMode = "0600"
    root_mode: FileMode = "0755"
    # None: ``owner`` / ``group``.
    dir_owner: UnixUser | None = None
    dir_group: UnixUser | None = None
    # None: ``postgres_become_user``.
    database_dir_owner: UnixUser | None = None
    database_dir_group: UnixUser | None = None
    create_archive: StrictBool = True
    archive_format: Literal["tar.gz", "tar.zst"] = "tar.gz"
    fetch_local: StrictBool = True
    # None: ``~/backups/paperless`` on the controller.
    local_dir: Path | None = None
    generate_checksums: StrictBool = True
    disk_check_enabled: StrictBool = True
    disk_overhead_ratio: float = Field(default=1.15, gt=0)
    site_root: CanonicalPath = "/home/paperless/site"
    manage_dir: CanonicalPath | None = None
    virtualenv: CanonicalPath | None = None
    env_file: CanonicalPath | None = None
    user: UnixUser = "paperless"
    group_runtime: UnixUser = "paperless"
    external_root: CanonicalPath = "/mnt/cryptdata/paperless"
    media_path: CanonicalPath | None = None
    data_path: CanonicalPath | None = None
    consume_path: CanonicalPath | None = None
    export_path: CanonicalPath | None = None
    logs_path: CanonicalPath | None = None
    include_consume: StrictBool = False
    include_export: StrictBool = False
    include_logs: StrictBool = False
    rsync_binary: CanonicalPath | Literal["rsync"] = "rsync"
    rsync_delete: StrictBool = False
    exporter_enabled: StrictBool = True
    # "": ``<backup dir>/exporter``.
    exporter_target: CanonicalPath | Literal[""] = ""
    exporter_flags: Flags = "-z --delete"
    exporter_passphrase: Password = SecretStr("")
    exporter_clean_target: StrictBool = True
    postgres_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.:-]*$")] = ""
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_user: Identifier = "paperless"
    postgres_password: Password = SecretStr("")
    postgres_become_user: UnixUser = "paperless"
    postgres_database: Identifier = "paperless"
    postgres_dump_binary: CanonicalPath | Literal["pg_dump"] = "pg_dump"
    postgres_dump_options: Flags = "--clean --if-exists --no-owner"
    # None: ``.env`` and ``gunicorn.conf.py`` below ``site_root``.
    config_files: tuple[CopySpec, ...] | None = None
    systemd_units: tuple[CanonicalPath, ...] = (
        "/etc/systemd/system/paperless.service",
        "/etc/systemd/system/paperless-worker.service",
        "/etc/systemd/system/paperless-scheduler.service",
        "/etc/systemd/system/paperless-consumer.service",
    )
    traefik_config_path: CanonicalPath | Literal[""] = "/etc/traefik/dynamic/paperless.yml"
    ssh_config_path: CanonicalPath | Literal[""] = "/etc/ssh/sshd_config.d/sftp-scanner.conf"
    extra_files: tuple[CopySpec, ...] = ()
    # Rendered as JSON (flow YAML) under ``extra``, as the role's ``to_json``.
    metadata_extra: Mapping[str, str | bool | int] = Field(default_factory=dict)

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}

    @model_validator(mode="after")
    def _secrets_one_line(self) -> Self:
        _no_line_breaks({"exporter_passphrase": self.exporter_passphrase, "postgres_password": self.postgres_password})
        return self

    def path(self, name: str) -> str:
        site, ext = self.site_root, self.external_root
        defaults = {
            "manage_dir": f"{site}/paperless-ngx/src",
            "virtualenv": f"{site}/.venv",
            "env_file": f"{site}/.env",
            "media_path": f"{ext}/media",
            "data_path": f"{ext}/data",
            "consume_path": f"{ext}/consume",
            "export_path": f"{ext}/export",
            "logs_path": f"{site}/logs",
        }
        value: str | None = getattr(self, name)
        return value or defaults[name]

    @property
    def configs(self) -> tuple[CopySpec, ...]:
        if self.config_files is not None:
            return self.config_files
        return (
            CopySpec(src=self.path("env_file"), dest="config/paperless.env"),
            CopySpec(src=f"{self.site_root}/gunicorn.conf.py", dest="config/gunicorn.conf.py"),
        )


def backup_metadata(cfg: PaperlessBackupConfig, *, stamp: str, backup_dir: str, exporter_target: str) -> str:
    """``metadata.yml`` as the role's template renders it; ``@VERSION@`` is filled on the host."""

    import json

    def b(value: bool) -> str:
        return str(value)

    return (
        f'timestamp: "{stamp}"\n'
        'timestamp_source: "ansible_date_time.iso8601_basic_short (play start)"\n'
        f'host: "{cfg.host_name}"\n'
        f'backup_dir: "{backup_dir}"\n'
        'paperless_version: "@VERSION@"\n'
        "exporter:\n"
        f"  enabled: {b(cfg.exporter_enabled)}\n"
        f'  target: "{exporter_target if cfg.exporter_enabled else ""}"\n'
        f"  flags: {json.dumps(cfg.exporter_flags)}\n"
        f"  passphrase_set: {b(bool(cfg.exporter_passphrase.get_secret_value()))}\n"
        "postgres:\n"
        f'  database: "{cfg.postgres_database}"\n'
        f'  host: "{cfg.postgres_host}"\n'
        f"  port: {cfg.postgres_port}\n"
        f"  options: {json.dumps(cfg.postgres_dump_options)}\n"
        "storage:\n"
        f'  media_path: "{cfg.path("media_path")}"\n'
        f'  data_path: "{cfg.path("data_path")}"\n'
        f'  consume_path: "{cfg.path("consume_path")}"\n'
        f'  export_path: "{cfg.path("export_path")}"\n'
        f'  logs_path: "{cfg.path("logs_path")}"\n'
        f"  include_consume: {b(cfg.include_consume)}\n"
        f"  include_export: {b(cfg.include_export)}\n"
        f"  include_logs: {b(cfg.include_logs)}\n"
        "archive:\n"
        f"  create: {b(cfg.create_archive)}\n"
        f'  format: "{cfg.archive_format}"\n'
        f"extra: {json.dumps(dict(cfg.metadata_extra))}\n"
    )


def backup_settings(
    cfg: PaperlessBackupConfig, *, stamp: str, handover: bool = True
) -> tuple[dict[str, str | tuple[str, ...]], str]:
    """The host script's settings and the backup directory.

    ``handover``: apply the role's owners and modes to the snapshot at the end;
    the restore's safety snapshot stays root's (its units are installed back
    by a rollback).
    """

    backup_dir = f"{cfg.root}/{cfg.prefix}-{stamp}"
    exporter_target = cfg.exporter_target or f"{backup_dir}/exporter"
    required = [
        f"{cfg.path('manage_dir')}:Paperless manage.py directory",
        f"{cfg.path('virtualenv')}:Paperless virtualenv",
        f"{cfg.path('env_file')}:Paperless .env",
        f"{cfg.path('media_path')}:Media directory",
        f"{cfg.path('data_path')}:Data directory",
    ]
    for include, name, description in (
        (cfg.include_logs, "logs_path", "Logs directory"),
        (cfg.include_consume, "consume_path", "Consume directory"),
        (cfg.include_export, "export_path", "Export directory"),
    ):
        if include:
            required.append(f"{cfg.path(name)}:{description}")
    copies = [f"{spec.src}:{spec.dest}" for spec in cfg.configs]
    copies += [f"{unit}:systemd/{PurePosixPath(unit).name}" for unit in cfg.systemd_units]
    if cfg.traefik_config_path:
        copies.append(f"{cfg.traefik_config_path}:traefik/{PurePosixPath(cfg.traefik_config_path).name}")
    if cfg.ssh_config_path:
        copies.append(f"{cfg.ssh_config_path}:ssh/{PurePosixPath(cfg.ssh_config_path).name}")
    settings: dict[str, str | tuple[str, ...]] = {
        "REQUIRED_MOUNT": cfg.required_mount or "",
        "RECORD": flag(cfg.retention),
        "ROOT": cfg.root,
        "DIR": backup_dir,
        "OWNER": cfg.owner,
        "GROUP": cfg.group,
        "ROOT_MODE": cfg.root_mode,
        "DIR_OWNER": cfg.dir_owner or cfg.owner,
        "DIR_GROUP": cfg.dir_group or cfg.group,
        "DIR_MODE": cfg.dir_mode,
        "DB_DIR_OWNER": cfg.database_dir_owner or cfg.postgres_become_user,
        "DB_DIR_GROUP": cfg.database_dir_group or cfg.postgres_become_user,
        "FILE_MODE": cfg.file_mode,
        "ARCHIVE_MODE": cfg.archive_mode,
        "REQUIRED": tuple(required),
        "DISK_CHECK": flag(cfg.disk_check_enabled),
        "OVERHEAD": str(cfg.disk_overhead_ratio),
        "MANAGE_DIR": cfg.path("manage_dir"),
        "ENV_FILE": cfg.path("env_file"),
        "PYTHON": f"{cfg.path('virtualenv')}/bin/python",
        "APP_USER": cfg.user,
        "APP_GROUP": cfg.group_runtime,
        "EXPORTER": flag(cfg.exporter_enabled),
        "EXPORTER_TARGET": exporter_target,
        "EXPORTER_FLAGS": tuple(shlex.split(cfg.exporter_flags)),
        "EXPORTER_CLEAN": flag(cfg.exporter_clean_target),
        "PG_HOST": cfg.postgres_host,
        "PG_PORT": str(cfg.postgres_port),
        "PG_USER": cfg.postgres_user,
        "PG_BECOME": cfg.postgres_become_user,
        "PG_DB": cfg.postgres_database,
        "PG_DUMP": cfg.postgres_dump_binary,
        "PG_DUMP_OPTIONS": tuple(shlex.split(cfg.postgres_dump_options)),
        "RSYNC": cfg.rsync_binary,
        "RSYNC_DELETE": flag(cfg.rsync_delete),
        "DIRS": (
            f"1:{cfg.path('media_path')}:media",
            f"1:{cfg.path('data_path')}:data",
            f"{flag(cfg.include_logs)}:{cfg.path('logs_path')}:logs",
            f"{flag(cfg.include_consume)}:{cfg.path('consume_path')}:consume",
            f"{flag(cfg.include_export)}:{cfg.path('export_path')}:export",
        ),
        "COPIES": tuple(copies),
        "EXTRA_FILES": tuple(f"{spec.src}:{spec.dest}" for spec in cfg.extra_files),
        "METADATA": backup_metadata(cfg, stamp=stamp, backup_dir=backup_dir, exporter_target=exporter_target),
        "CHECKSUMS": flag(cfg.generate_checksums),
        "ARCHIVE": flag(cfg.create_archive),
        "FORMAT": cfg.archive_format,
        "HANDOVER": flag(handover),
    }
    return settings, backup_dir


def _stamp(role: str) -> str:
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError(f"{role}: cannot read the host's time")
    return stamp


def _restrict_local(path: str) -> None:
    # The archive holds every document, the database dump and the service secrets.
    if os.path.exists(path):
        os.chmod(path, 0o600)


def _stdin(*values: SecretStr) -> dict[str, Any]:
    return stdin_arguments("".join(value.get_secret_value() + "\n" for value in values))


@deploy("Paperless backup")
def deploy_paperless_backup(cfg: PaperlessBackupConfig) -> None:
    """Dump, export and copy Paperless into a backup directory, pack it and fetch the archive."""

    stamp = _stamp("paperless_backup")
    settings, backup_dir = backup_settings(cfg, stamp=stamp)
    server.shell(
        name="Back up Paperless",
        commands=[script(FILES / "backup.sh", settings)],
        _shell_executable="bash",
        **_stdin(cfg.exporter_passphrase, cfg.postgres_password),
    )
    name = PurePosixPath(backup_dir).name
    if cfg.retention:
        server.shell(
            name="Prune local snapshots",
            commands=[retention(cfg, cfg.root, name, stamp)],
            _shell_executable="bash",
        )
    if cfg.create_archive and cfg.fetch_local:
        local_dir = str(cfg.local_dir or Path.home() / "backups" / "paperless")
        local = f"{local_dir}/{name}.{cfg.archive_format}"
        python.call(name=f"Ensure {local_dir} (0700)", function=private_local_dir, path=local_dir)
        files.get(name="Fetch the backup archive", src=f"{backup_dir}.{cfg.archive_format}", dest=local)
        python.call(name="Restrict the local archive copy (0600)", function=_restrict_local, path=local)


class PaperlessRestoreConfig(MountGuard):
    host_name: Hostname
    archive: ArchiveName = "latest"
    search_root: CanonicalPath = "/opt/backups/paperless"
    staging_dir: CanonicalPath = "/tmp/paperless-restore"
    staging_mode: FileMode = "0750"
    staging_owner: UnixUser = "root"
    # None: ``postgres_become_user``.
    staging_group: UnixUser | None = None
    validate_checksums: StrictBool = True
    validate_metadata: StrictBool = True
    enforce_host_match: StrictBool = True
    dry_run: StrictBool = False
    check_disk_space: StrictBool = True
    disk_space_multiplier: float = Field(default=1.5, gt=0)
    # None: ``site_root``.
    disk_space_path: CanonicalPath | None = None
    site_root: CanonicalPath = "/home/paperless/site"
    site_owner: UnixUser = "paperless"
    site_group: UnixUser = "paperless"
    manage_dir: CanonicalPath | None = None
    virtualenv: CanonicalPath | None = None
    env_file: CanonicalPath | None = None
    logs_path: CanonicalPath | None = None
    external_root: CanonicalPath = "/mnt/cryptdata/paperless"
    media_path: CanonicalPath | None = None
    data_path: CanonicalPath | None = None
    consume_path: CanonicalPath | None = None
    export_path: CanonicalPath | None = None
    database_dump: Relative = "database/paperless.sql"
    exporter_dir: Relative = "exporter"
    metadata_required_fields: tuple[Annotated[str, Field(pattern=r"^[a-z_]+$")], ...] = (
        "timestamp",
        "host",
        "paperless_version",
        "storage",
        "postgres",
    )
    # None: the role's map (media, data required; consume/export/logs by metadata flag).
    storage_dirs: tuple[StorageDir, ...] | None = None
    config_files: tuple[RestoreFile, ...] | None = None
    systemd_units: tuple[Placement, ...] = tuple(
        Placement(src=f"systemd/{name}.service", dest=f"/etc/systemd/system/{name}.service")
        for name in ("paperless", "paperless-worker", "paperless-scheduler", "paperless-consumer")
    )
    system_files: StrictBool = True
    traefik_file: Placement = Placement(src="traefik/paperless.yml", dest="/etc/traefik/dynamic/paperless.yml")
    ssh_file: Placement = Placement(src="ssh/sftp-scanner.conf", dest="/etc/ssh/sshd_config.d/sftp-scanner.conf")
    stop_services: tuple[ServiceName, ...] = (
        "paperless-consumer",
        "paperless-scheduler",
        "paperless-worker",
        "paperless",
    )
    start_services: tuple[ServiceName, ...] = (
        "paperless",
        "paperless-worker",
        "paperless-scheduler",
        "paperless-consumer",
    )
    service_start_retries: int = Field(default=10, ge=0)
    service_start_delay: int = Field(default=3, ge=0)
    service_start_pause: int = Field(default=2, ge=0)
    http_timeout: int = Field(default=10, ge=1)
    restart_daemon_after_system_files: StrictBool = True
    fix_permissions: StrictBool = False
    # None: ``(site_root,)``.
    fix_paths: tuple[CanonicalPath, ...] | None = None
    postgres_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.:-]+$")] = "localhost"
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_user: Identifier = "paperless"
    postgres_password: Password = SecretStr("")
    postgres_database: Identifier = "paperless"
    postgres_become_user: UnixUser = "postgres"
    postgres_admin_user: Identifier = "postgres"
    postgres_admin_password: Password = SecretStr("")
    postgres_admin_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.:-]*$")] = ""
    postgres_admin_port: Annotated[str, Field(pattern=r"^[0-9]*$")] = ""
    safety_backup_postgres_user: Identifier = "paperless"
    safety_backup_postgres_become_user: UnixUser = "paperless"
    postgres_owner: Identifier = "paperless"
    psql_binary: CanonicalPath | Literal["psql"] = "psql"
    drop_database: StrictBool = True
    create_database: StrictBool = True
    postgres_test_query: Annotated[str, Field(pattern=r"^[A-Za-z0-9 ;*(),_.]+$")] = "SELECT 1;"
    postgres_check_retries: int = Field(default=3, ge=0)
    postgres_check_delay: int = Field(default=5, ge=0)
    use_importer: StrictBool = True
    importer_flags: Flags = ""
    importer_passphrase: Password = SecretStr("")
    importer_require_artifact: StrictBool = True
    importer_source: CanonicalPath | Literal[""] = ""
    importer_timeout: int = Field(default=0, ge=0)
    rsync_binary: CanonicalPath | Literal["rsync"] = "rsync"
    rsync_delete: StrictBool = True
    verify_http: StrictBool = True
    health_url: Url = "http://localhost:10030/api/"
    health_expected_status: int = Field(default=200, ge=100, le=599)
    health_retries: int = Field(default=10, ge=0)
    health_delay: int = Field(default=6, ge=0)
    postgres_check_enabled: StrictBool = True
    create_safety_backup: StrictBool = True
    safety_backup_prefix: Prefix = "pre-restore"
    safety_backup_cleanup: StrictBool = True
    rollback_on_failure: StrictBool = True
    cleanup_after_rollback: StrictBool = False
    # The safety snapshot: paperless_backup with these settings (inventory
    # values) and the role's overrides (prefix, no archive/fetch/exporter,
    # checksums, peer authentication as the safety PostgreSQL account).
    safety_backup: PaperlessBackupConfig | None = None

    def guarded_paths(self) -> dict[str, str]:
        return {"staging_dir": self.staging_dir}

    @model_validator(mode="after")
    def _checks(self) -> Self:
        _no_line_breaks(
            {
                "importer_passphrase": self.importer_passphrase,
                "postgres_password": self.postgres_password,
                "postgres_admin_password": self.postgres_admin_password,
            }
        )
        staging = PurePosixPath(self.staging_dir)
        for name in ("search_root", "site_root", "external_root"):
            other = PurePosixPath(getattr(self, name))
            # Never over these; inside the search root is fine (ops-control's work directory).
            if other.is_relative_to(staging) or (staging.is_relative_to(other) and name != "search_root"):
                raise ValueError(f"staging_dir ({staging}) must lie apart from {name} ({other})")
        return self

    def path(self, name: str) -> str:
        site, ext = self.site_root, self.external_root
        defaults = {
            "manage_dir": f"{site}/paperless-ngx/src",
            "virtualenv": f"{site}/.venv",
            "env_file": f"{site}/.env",
            "logs_path": f"{site}/logs",
            "media_path": f"{ext}/media",
            "data_path": f"{ext}/data",
            "consume_path": f"{ext}/consume",
            "export_path": f"{ext}/export",
        }
        value: str | None = getattr(self, name)
        return value or defaults[name]

    @property
    def storage(self) -> tuple[StorageDir, ...]:
        if self.storage_dirs is not None:
            return self.storage_dirs
        return (
            StorageDir(name="media", dest=self.path("media_path"), required=True),
            StorageDir(name="data", dest=self.path("data_path"), required=True),
            StorageDir(name="consume", dest=self.path("consume_path"), metadata_flag="include_consume"),
            StorageDir(name="export", dest=self.path("export_path"), metadata_flag="include_export"),
            StorageDir(name="logs", dest=self.path("logs_path"), metadata_flag="include_logs"),
        )

    @property
    def configs(self) -> tuple[RestoreFile, ...]:
        if self.config_files is not None:
            return self.config_files
        owner, group = self.site_owner, self.site_group
        return (
            RestoreFile(
                src="config/paperless.env",
                dest=self.path("env_file"),
                owner=owner,
                group=group,
                mode="0640",
                required=True,
            ),
            RestoreFile(
                src="config/gunicorn.conf.py",
                dest=f"{self.site_root}/gunicorn.conf.py",
                owner=owner,
                group=group,
                mode="0644",
                required=True,
            ),
        )


RECONCILE_SQL = """DO $$
DECLARE
  _owner text := '@OWNER@';
  r record;
BEGIN
  EXECUTE format('ALTER SCHEMA public OWNER TO %I', _owner);
  FOR r IN SELECT schemaname, tablename FROM pg_tables WHERE schemaname='public' LOOP
    EXECUTE format('ALTER TABLE %I.%I OWNER TO %I', r.schemaname, r.tablename, _owner);
  END LOOP;
  FOR r IN SELECT schemaname, viewname FROM pg_views WHERE schemaname='public' LOOP
    EXECUTE format('ALTER VIEW %I.%I OWNER TO %I', r.schemaname, r.viewname, _owner);
  END LOOP;
  FOR r IN SELECT schemaname, matviewname FROM pg_matviews WHERE schemaname='public' LOOP
    EXECUTE format('ALTER MATERIALIZED VIEW %I.%I OWNER TO %I', r.schemaname, r.matviewname, _owner);
  END LOOP;
  FOR r IN SELECT sequence_schema, sequence_name FROM information_schema.sequences WHERE sequence_schema='public' LOOP
    EXECUTE format('ALTER SEQUENCE %I.%I OWNER TO %I', r.sequence_schema, r.sequence_name, _owner);
  END LOOP;
  EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', _owner);
  EXECUTE format(
    'GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public TO %I',
    _owner);
  EXECUTE format('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO %I', _owner);
  EXECUTE format(
    'ALTER DEFAULT PRIVILEGES FOR USER postgres IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, '
    'REFERENCES, TRIGGER ON TABLES TO %I', _owner);
  EXECUTE format(
    'ALTER DEFAULT PRIVILEGES FOR USER postgres IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO %I',
    _owner);
END $$;
"""


def _assignments(values: Mapping[str, str | tuple[str, ...]]) -> str:
    """bash assignments (lists as arrays), quoted as :func:`script` quotes them."""

    lines = []
    for name, value in values.items():
        if isinstance(value, str):
            lines.append(f"{name}={shlex.quote(value)}")
        else:
            lines.append(f"{name}=({' '.join(shlex.quote(item) for item in value)})")
    return "\n".join(lines) + "\n"


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def safety_config(cfg: PaperlessRestoreConfig, stamp: str = "") -> PaperlessBackupConfig:
    """The role's pre-restore snapshot: the backup settings with the restore's overrides."""

    base = cfg.safety_backup or PaperlessBackupConfig(host_name=cfg.host_name)
    become = cfg.safety_backup_postgres_become_user
    return base.model_copy(
        update={
            # The rollback's host check compares the snapshot with the restore's host.
            "host_name": cfg.host_name,
            "prefix": cfg.safety_backup_prefix,
            "create_archive": False,
            "fetch_local": False,
            "generate_checksums": True,
            "exporter_enabled": False,
            "postgres_user": cfg.safety_backup_postgres_user,
            "postgres_password": SecretStr(""),
            "postgres_host": "",
            "postgres_become_user": become,
            "database_dir_owner": become,
            "database_dir_group": become,
            # Not under retention: snapshot records are for the normal backups.
            "retain_count": 0,
            "retain_days": 0,
            "metadata_extra": {
                "safety_snapshot": True,
                "source_role": "paperless_restore",
                "source_timestamp": stamp,
                **base.metadata_extra,
            },
        }
    )


@deploy("Paperless restore")
def deploy_paperless_restore(cfg: PaperlessRestoreConfig) -> None:
    """Restore a Paperless archive with a pre-restore safety snapshot and rollback after a failed verification."""

    stamp = _stamp("paperless_restore")
    safety = safety_config(cfg, stamp)
    safety_settings, safety_dir = backup_settings(safety, stamp=stamp, handover=False)
    reconcile = RECONCILE_SQL.replace("@OWNER@", cfg.postgres_owner.replace("'", "''"))
    settings: dict[str, str | tuple[str, ...]] = {
        "REQUIRED_MOUNT": cfg.required_mount or "",
        "HOST_NAME": cfg.host_name,
        "STAMP": stamp,
        "ARCHIVE": cfg.archive,
        "SEARCH_ROOT": cfg.search_root,
        "STAGING": cfg.staging_dir,
        "STAGING_OWNER": cfg.staging_owner,
        "STAGING_GROUP": cfg.staging_group or cfg.postgres_become_user,
        "STAGING_MODE": cfg.staging_mode,
        "VALIDATE_CHECKSUMS": flag(cfg.validate_checksums),
        "VALIDATE_METADATA": flag(cfg.validate_metadata),
        "ENFORCE_HOST": flag(cfg.enforce_host_match),
        "REQUIRED_FIELDS": cfg.metadata_required_fields,
        "DRY_RUN": flag(cfg.dry_run),
        "CHECK_DISK": flag(cfg.check_disk_space),
        "MULTIPLIER": str(cfg.disk_space_multiplier),
        "DISK_PATH": cfg.disk_space_path or cfg.site_root,
        "SITE_OWNER": cfg.site_owner,
        "SITE_GROUP": cfg.site_group,
        "MANAGE_DIR": cfg.path("manage_dir"),
        "ENV_FILE": cfg.path("env_file"),
        "PYTHON": f"{cfg.path('virtualenv')}/bin/python",
        "EXTERNAL_ROOT": cfg.external_root,
        "DB_DUMP": cfg.database_dump,
        "EXPORTER_DIR": cfg.exporter_dir,
        "STORAGE": tuple(f"{d.name}:{d.dest}:{flag(d.required)}:{d.metadata_flag}" for d in cfg.storage),
        "CONFIGS": tuple(f"{c.src}:{c.dest}:{c.owner}:{c.group}:{c.mode}:{flag(c.required)}" for c in cfg.configs),
        "UNITS": tuple(f"{u.src}:{u.dest}" for u in cfg.systemd_units),
        "SYSTEM_FILES": flag(cfg.system_files),
        "TRAEFIK_FILE": f"{cfg.traefik_file.src}:{cfg.traefik_file.dest}",
        "SSH_FILE": f"{cfg.ssh_file.src}:{cfg.ssh_file.dest}",
        "ROUTE_GUARD": tuple(shlex.split(route_guard_command())),
        "STOP_SERVICES": cfg.stop_services,
        "START_SERVICES": cfg.start_services,
        "START_RETRIES": str(cfg.service_start_retries),
        "START_DELAY": str(cfg.service_start_delay),
        "START_PAUSE": str(cfg.service_start_pause),
        "HTTP_TIMEOUT": str(cfg.http_timeout),
        "RELOAD_AFTER_SYSTEM_FILES": flag(cfg.restart_daemon_after_system_files),
        "FIX_PERMISSIONS": flag(cfg.fix_permissions),
        "FIX_PATHS": cfg.fix_paths or (cfg.site_root,),
        "PG_HOST": cfg.postgres_host,
        "PG_PORT": str(cfg.postgres_port),
        "PG_USER": cfg.postgres_user,
        "PG_DB": cfg.postgres_database,
        "PG_DB_IDENT": _ident(cfg.postgres_database),
        "PG_OWNER_IDENT": _ident(cfg.postgres_owner),
        "PG_BECOME": cfg.postgres_become_user,
        "PG_ADMIN_USER": cfg.postgres_admin_user,
        "PG_ADMIN_HOST": cfg.postgres_admin_host,
        "PG_ADMIN_PORT": cfg.postgres_admin_port,
        "PSQL": cfg.psql_binary,
        "DROP_DATABASE": flag(cfg.drop_database),
        "CREATE_DATABASE": flag(cfg.create_database),
        "RECONCILE_SQL": reconcile,
        "PG_TEST_QUERY": cfg.postgres_test_query,
        "PG_RETRIES": str(cfg.postgres_check_retries),
        "PG_DELAY": str(cfg.postgres_check_delay),
        "PG_CHECK": flag(cfg.postgres_check_enabled),
        "USE_IMPORTER": flag(cfg.use_importer),
        "IMPORTER_FLAGS": tuple(shlex.split(cfg.importer_flags)),
        "IMPORTER_REQUIRE": flag(cfg.importer_require_artifact),
        "IMPORTER_SOURCE": cfg.importer_source,
        "IMPORTER_TIMEOUT": str(cfg.importer_timeout),
        "RSYNC": cfg.rsync_binary,
        "RSYNC_DELETE": flag(cfg.rsync_delete),
        "VERIFY_HTTP": flag(cfg.verify_http),
        "HEALTH_URL": cfg.health_url,
        "HEALTH_STATUS": str(cfg.health_expected_status),
        "HEALTH_RETRIES": str(cfg.health_retries),
        "HEALTH_DELAY": str(cfg.health_delay),
        "CREATE_SAFETY": flag(cfg.create_safety_backup),
        # backup.sh and its settings, run in a subshell of the restore.
        "SAFETY_SETTINGS": _assignments(safety_settings),
        "BACKUP_BODY": (FILES / "backup.sh").read_text(),
        "SAFETY_DIR": safety_dir,
        "SAFETY_CLEANUP": flag(cfg.safety_backup_cleanup),
        "ROLLBACK": flag(cfg.rollback_on_failure),
        "CLEANUP_AFTER_ROLLBACK": flag(cfg.cleanup_after_rollback),
    }
    server.shell(
        name="Restore Paperless" + (" (dry run)" if cfg.dry_run else ""),
        commands=[script(FILES / "restore.sh", settings)],
        _shell_executable="bash",
        **_stdin(cfg.importer_passphrase, cfg.postgres_password, cfg.postgres_admin_password),
    )


__all__ = [
    "PaperlessBackupConfig",
    "PaperlessRestoreConfig",
    "backup_metadata",
    "deploy_paperless_backup",
    "deploy_paperless_restore",
    "safety_config",
]
