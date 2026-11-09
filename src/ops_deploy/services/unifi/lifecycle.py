"""UniFi backup and restore (the ``unifi_backup`` and ``unifi_restore`` roles).

A backup is ``<root>/<prefix>-<timestamp>/`` with ``database/`` (the
``mongodump`` of the UniFi database, taken while the controller runs),
``data/`` (the data directory without ``db/*``), ``autobackups/`` (``.unf``
files younger than seven days), ``logs/`` (empty unless included),
``config/`` (``system.properties``, keystore), ``systemd/`` (unit, MongoDB
JVM argument file), ``traefik/`` (route), ``metadata.yml`` and
``manifest.sha256``, packed as ``<dir>.tar.gz`` with the directory as its only
top-level entry. Directories are ``root 0700``, files and the archive
``0600``. The layout and the metadata are the role's, so either tool restores
the other's archives and snapshot directories.

Each backup and restore runs on the host as one Python program
(``files/lifecycle_host.py``) with its settings on stdin; the MongoDB
credentials travel there too and never reach a command line, an environment
or a log (see the program). The service is stopped only around the file copy
and started again, whatever the copy did, when it was running.

A restore needs ``confirm`` unless it is a ``dry_run``. The dry run resolves
the artifact, unpacks an archive into a scratch directory below
``work_dir``, validates checksums, metadata and the major version, prints the
plan and removes the scratch directory: UniFi, MongoDB, the data directory,
unit and route stay untouched. A real restore takes a safety backup first
(``pre-restore-<timestamp>``, without archive; on a fresh installation a
missing database or data directory is reported as nothing to snapshot),
stops UniFi, replaces the database and data, restores unit, JVM argument file
and route, starts and verifies it, and rolls back from the safety backup when
restoring or verifying fails. The safety backup is removed after a successful
restore and kept after a failed one.

Deliberate differences from the roles are listed in the service page
(``docs/services/unifi.md``, Backup and restore). ``required_mount`` keeps
the backup root and the restore's work directory on an external disk, and
``retain_count``/``retain_days`` prune the snapshots this port wrote
(:mod:`ops_deploy.services._lifecycle.local_backup`).
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Self

from pydantic import Field, StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server

from ops_deploy.base._common import output
from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.traefik import DYNAMIC_DIR, route_guard_command
from ops_deploy.ops import secret_stdin
from ops_deploy.services._lifecycle import private_local_dir
from ops_deploy.services._lifecycle.canonical import CanonicalPath, Hostname, Prefix
from ops_deploy.services._lifecycle.local_backup import (
    MountGuard,
    SnapshotRetention,
    backup_preflight,
    mount_check,
    retention,
)
from ops_deploy.services._lifecycle.media_lifecycle import PROTECTED

HOST_SCRIPT = (Path(__file__).parent / "files" / "lifecycle_host.py").read_text()
EXTENSION = "tar.gz"
UnitName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,31}\.service$")]
MongoHost = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")]
Url = Annotated[str, Field(pattern=r"^https?://[A-Za-z0-9.:/_-]+$")]
# ``latest``, a name directly below the root (an archive, with or without
# ``.tar.gz``, or a snapshot directory) or an absolute path below the root.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|[A-Za-z0-9_+-][A-Za-z0-9._+-]*|/[A-Za-z0-9._+/-]+)$")]
# Database and authentication database names (argv, paths); MongoDB user names.
MONGO_NAME = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
MONGO_USER = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")
SECRET_DEFAULTS = {"mongodb_username": "unifi", "mongodb_auth_db": "admin", "mongodb_database": "unifi"}
# The roles' waits: start ``until`` active (12 retries, 5 s; restore 10 s),
# mongorestore (3 retries, 5 s), the verification dump (6, 5 s) and the web
# check (6, 10 s). ``attempts`` counts the first try too.
TIMING = {
    "start_attempts": 13,
    "start_delay": 5,
    "active_attempts": 13,
    "active_delay": 10,
    "mongorestore_attempts": 4,
    "mongorestore_delay": 5,
    "dump_attempts": 7,
    "dump_delay": 5,
    "http_attempts": 7,
    "http_delay": 10,
}


def _dedicated(name: str, value: str) -> None:
    if value in PROTECTED:
        raise ValueError(f"{name} ({value}) must be a dedicated directory, not a shared system path")


class _Unifi(MountGuard):
    """``unifi_backup``/``unifi_restore`` defaults shared by both roles."""

    # The metadata's ``host`` (Ansible's ``inventory_hostname``).
    host_name: Hostname
    root: CanonicalPath = "/opt/backups/unifi"
    service_name: UnitName = "unifi.service"
    data_path: CanonicalPath = "/usr/lib/unifi/data"
    systemd_unit_path: CanonicalPath = "/etc/systemd/system/unifi.service"
    # Java @argfile with the MongoDB URI (password) written by the deploy.
    jvm_args_path: CanonicalPath = "/etc/unifi-secrets/mongodb.jvmargs"
    traefik_config_path: CanonicalPath = "/etc/traefik/dynamic/unifi.yml"
    mongodb_host: MongoHost = "127.0.0.1"
    mongodb_port: int = Field(default=27017, ge=1, le=65535)
    # Parent of the private 0700 directory with the tools' credential file
    # (a tmpfs on the hosts: the file never reaches a disk).
    credentials_dir: CanonicalPath = "/run"
    # The roles' pause after stopping UniFi.
    stop_pause: int = Field(default=10, ge=0, le=300)

    @model_validator(mode="after")
    def _paths_apart(self) -> Self:
        _dedicated("root", self.root)
        root, data = PurePosixPath(self.root), PurePosixPath(self.data_path)
        if root.is_relative_to(data) or data.is_relative_to(root):
            raise ValueError(f"root ({root}) and data_path ({data}) must not contain each other")
        return self


class UnifiBackupConfig(_Unifi, SnapshotRetention):
    """``unifi_backup`` with its defaults (the archive always ``tar.gz``, root ``0700``, files ``0600``)."""

    prefix: Prefix = "manual"
    # None: below ``data_path``, as the role derives them.
    db_path: CanonicalPath | None = None
    autobackup_path: CanonicalPath | None = None
    system_properties_path: CanonicalPath | None = None
    keystore_path: CanonicalPath | None = None
    logs_path: CanonicalPath = "/usr/lib/unifi/logs"
    env_file: CanonicalPath = "/etc/default/unifi"
    stop_service: StrictBool = True
    mongodb_backup: StrictBool = True
    include_logs: StrictBool = False
    include_autobackups: StrictBool = True
    include_traefik: StrictBool = True
    include_system_properties: StrictBool = True
    include_keystore: StrictBool = True
    include_env: StrictBool = False
    use_delete: StrictBool = True
    disk_check: StrictBool = True
    disk_overhead_ratio: float = Field(default=1.5, gt=0, le=100)
    generate_checksums: StrictBool = True
    create_archive: StrictBool = True
    fetch_local: StrictBool = True
    # None: ``~/backups/unifi`` on the controller.
    local_dir: Path | None = None

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}


class UnifiRestoreConfig(_Unifi):
    """``unifi_restore`` with its defaults and the automated method (MongoDB plus data directory).

    ``confirm`` authorizes the destructive restore of the live controller; a
    ``dry_run`` needs none and changes nothing of UniFi.
    """

    confirm: StrictBool = False
    dry_run: StrictBool = False
    archive: ArchiveName = "latest"
    # The scratch directories of unpacked archives (one per run, removed afterwards).
    work_dir: CanonicalPath = "/tmp/unifi-restore"
    validate_checksums: StrictBool = True
    check_version_compatibility: StrictBool = True
    create_safety_backup: StrictBool = True
    safety_backup_prefix: Prefix = "pre-restore"
    cleanup_safety_backup: StrictBool = True
    include_mongodb: StrictBool = True
    drop_database: StrictBool = True
    mongorestore_drop: StrictBool = False
    verify_mongodb: StrictBool = True
    verify_http: StrictBool = True
    health_url: Url = "https://127.0.0.1:8443/"
    rollback_on_failure: StrictBool = True
    unifi_user: UnixUser = "unifi"
    unifi_group: UnixUser = "unifi"
    jvm_args_group: UnixUser = "unifi"

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root, "work_dir": self.work_dir}

    @model_validator(mode="after")
    def _restore_paths(self) -> Self:
        _dedicated("work_dir", self.work_dir)
        work, root = PurePosixPath(self.work_dir), PurePosixPath(self.root)
        if work == root or root.is_relative_to(work):
            raise ValueError(f"work_dir ({work}) must not contain root ({root})")
        if work.is_relative_to(self.data_path) or PurePosixPath(self.data_path).is_relative_to(work):
            raise ValueError(f"work_dir ({work}) and data_path must not contain each other")
        archive = PurePosixPath(self.archive)
        if ".." in archive.parts:
            raise ValueError("archive cannot contain parent traversal")
        if archive.is_absolute() and (archive == root or not archive.is_relative_to(root)):
            raise ValueError(f"an absolute archive must lie below root ({root})")
        if self.rollback_on_failure and not self.create_safety_backup:
            raise ValueError("rollback_on_failure needs create_safety_backup")
        return self


def _secrets(secrets: SecretValues | None, *, password: bool) -> tuple[dict[str, str], dict[str, str] | None]:
    """The database name (not secret) and, with ``password``, the credentials for the host program."""

    given = secrets if secrets is not None else {}
    # The playbooks' ``| default(...)`` for a missing (or empty) key.
    values = {key: given.get(key) or default for key, default in SECRET_DEFAULTS.items()}
    for key in ("mongodb_database", "mongodb_auth_db"):
        if not MONGO_NAME.match(values[key]):
            raise DeployError(f"unifi lifecycle: {key} must be a plain MongoDB database name")
    if not MONGO_USER.match(values["mongodb_username"]):
        raise DeployError("unifi lifecycle: mongodb_username must be a plain MongoDB user name")
    if not password:
        return {"database": values["mongodb_database"]}, None
    secret = given.get("mongodb_password", "")
    if not secret:
        raise DeployError("unifi lifecycle: mongodb_password is required (the playbooks' service secret)")
    if "\n" in secret or "\r" in secret:
        raise DeployError("unifi lifecycle: mongodb_password cannot contain line breaks")
    credentials = {"username": values["mongodb_username"], "password": secret, "auth_db": values["mongodb_auth_db"]}
    return {"database": values["mongodb_database"]}, credentials


def _stamp(what: str) -> str:
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError(f"{what}: cannot read the host's time")
    return stamp


def _command(action: str) -> str:
    # Encoded trusted packaged source, as the media port: login shells (fish)
    # otherwise alter backslash pairs in nested Python source.
    encoded = base64.b64encode(HOST_SCRIPT.encode()).decode()
    loader = f"import base64;exec(compile(base64.b64decode({encoded!r}),'<unifi-lifecycle>','exec'))"
    return shlex.join(["python3", "-I", "-c", loader, action])


def _restrict_local(path: str) -> None:
    # ``fetch`` writes the copy with the controller's umask; the archive holds credentials.
    if os.path.exists(path):
        os.chmod(path, 0o600)


def backup_payload(
    cfg: UnifiBackupConfig, mongo: dict[str, str], name: str, stamp: str, *, safety: bool
) -> dict[str, Any]:
    """The host program's backup settings for ``<root>/<name>``."""

    data = cfg.data_path
    return {
        "safety": safety,
        "unit": cfg.service_name,
        "host": cfg.host_name,
        "root": cfg.root,
        "name": name,
        "dir": f"{cfg.root}/{name}",
        "stamp": stamp,
        "database": mongo["database"],
        "mongodb_port": cfg.mongodb_port,
        "paths": {
            "data": data,
            "db": cfg.db_path or f"{data}/db",
            "autobackup": cfg.autobackup_path or f"{data}/backup/autobackup",
            "logs": cfg.logs_path,
            "system_properties": cfg.system_properties_path or f"{data}/system.properties",
            "keystore": cfg.keystore_path or f"{data}/keystore",
            "env_file": cfg.env_file,
            "unit_file": cfg.systemd_unit_path,
            "jvm_args": cfg.jvm_args_path,
            "traefik": cfg.traefik_config_path,
        },
        "include": {
            "logs": cfg.include_logs,
            "autobackups": cfg.include_autobackups,
            "traefik": cfg.include_traefik,
            "system_properties": cfg.include_system_properties,
            "keystore": cfg.include_keystore,
            "env": cfg.include_env,
        },
        "stop_service": cfg.stop_service,
        "stop_pause": cfg.stop_pause,
        "mongodb_backup": cfg.mongodb_backup,
        "use_delete": cfg.use_delete,
        "disk_check": cfg.disk_check,
        "disk_overhead_ratio": cfg.disk_overhead_ratio,
        "generate_checksums": cfg.generate_checksums,
        "create_archive": cfg.create_archive,
        "timing": TIMING,
    }


def _run(name: str, action: str, payload: dict[str, Any], *, guard: bool = False) -> None:
    command = _command(action)
    if guard:
        command = f"{route_guard_command()} && {command}"
    secret_stdin(name=name, command=command, content=SecretContent(json.dumps(payload) + "\n"))


@deploy("UniFi backup")
def deploy_unifi_backup(cfg: UnifiBackupConfig, secrets: SecretValues | None = None) -> None:
    """Dump the database while UniFi runs, stop it for the file copy, start it, pack, fetch and prune."""

    mongo, credentials = _secrets(secrets, password=True)
    stamp = _stamp("unifi_backup")
    name = f"{cfg.prefix}-{stamp}"
    directory = f"{cfg.root}/{name}"
    preflight = backup_preflight(cfg, cfg.root, name)
    if preflight is not None:
        server.shell(name=f"Check {cfg.root} before the backup", commands=[preflight], _shell_executable="bash")
    payload = {
        "backup": backup_payload(cfg, mongo, name, stamp, safety=False),
        "mongodb": {"host": cfg.mongodb_host, "port": cfg.mongodb_port, **mongo},
        "credentials": credentials,
        "credentials_dir": cfg.credentials_dir,
    }
    _run(f"Back up UniFi into {directory}", "backup", payload)
    if cfg.create_archive and cfg.fetch_local:
        local_dir = str(cfg.local_dir or Path.home() / "backups" / "unifi")
        local = f"{local_dir}/{name}.{EXTENSION}"
        python.call(name=f"Ensure {local_dir} (0700)", function=private_local_dir, path=local_dir)
        files.get(name="Fetch the UniFi backup archive", src=f"{directory}.{EXTENSION}", dest=local)
        python.call(name="Restrict the local archive copy (0600)", function=_restrict_local, path=local)
    if cfg.retention:
        server.shell(
            name=f"Prune recorded {cfg.prefix} UniFi snapshots",
            commands=[retention(cfg, cfg.root, name, stamp)],
            _shell_executable="bash",
        )


@deploy("UniFi restore")
def deploy_unifi_restore(cfg: UnifiRestoreConfig, secrets: SecretValues | None = None) -> None:
    """Validate a UniFi backup (``dry_run``) or restore it over the live controller, with safety backup and rollback."""

    if not cfg.dry_run and not cfg.confirm:
        raise DeployError(
            "unifi_restore: restoring replaces the live controller's database, data, unit and route "
            "(a protected service). Validate the archive with a dry run first, then confirm the restore."
        )
    mongo, credentials = _secrets(secrets, password=not cfg.dry_run)
    stamp = _stamp("unifi_restore")
    if cfg.required_mount:
        server.shell(
            name=f"Require {cfg.required_mount} below {cfg.root} and {cfg.work_dir}",
            commands=[mount_check(cfg.required_mount, cfg.root, cfg.work_dir)],
            _shell_executable="bash",
        )
    safety = None
    if cfg.create_safety_backup:
        safety_cfg = UnifiBackupConfig(
            host_name=cfg.host_name,
            prefix=cfg.safety_backup_prefix,
            root=cfg.root,
            required_mount=cfg.required_mount,
            service_name=cfg.service_name,
            data_path=cfg.data_path,
            systemd_unit_path=cfg.systemd_unit_path,
            jvm_args_path=cfg.jvm_args_path,
            traefik_config_path=cfg.traefik_config_path,
            mongodb_host=cfg.mongodb_host,
            mongodb_port=cfg.mongodb_port,
            credentials_dir=cfg.credentials_dir,
            stop_pause=cfg.stop_pause,
            create_archive=False,
            fetch_local=False,
        )
        safety = backup_payload(safety_cfg, mongo, f"{cfg.safety_backup_prefix}-{stamp}", stamp, safety=True)
    # The route goes into Traefik's watched directory only while no transaction holds its lock.
    guard = not cfg.dry_run and PurePosixPath(cfg.traefik_config_path).is_relative_to(DYNAMIC_DIR)
    payload = {
        "dry_run": cfg.dry_run,
        "root": cfg.root,
        "archive": cfg.archive,
        "work_dir": cfg.work_dir,
        "validate_checksums": cfg.validate_checksums,
        "check_version": cfg.check_version_compatibility,
        "unit": cfg.service_name,
        "paths": {
            "data": cfg.data_path,
            "unit_file": cfg.systemd_unit_path,
            "jvm_args": cfg.jvm_args_path,
            "traefik": cfg.traefik_config_path,
        },
        "include_mongodb": cfg.include_mongodb,
        "drop_database": cfg.drop_database,
        "mongorestore_drop": cfg.mongorestore_drop,
        "verify_mongodb": cfg.verify_mongodb,
        "verify_http": cfg.verify_http,
        "health_url": cfg.health_url,
        "rollback_on_failure": cfg.rollback_on_failure,
        "cleanup_safety_backup": cfg.cleanup_safety_backup,
        "unifi_user": cfg.unifi_user,
        "unifi_group": cfg.unifi_group,
        "jvm_args_group": cfg.jvm_args_group,
        # The role creates the credentials directory only for its default location.
        "manage_jvm_args_dir": str(PurePosixPath(cfg.jvm_args_path).parent) == "/etc/unifi-secrets",
        "route_guard": shlex.split(route_guard_command()) if guard else [],
        "stop_pause": cfg.stop_pause,
        "safety": safety,
        "timing": TIMING,
        "mongodb": {"host": cfg.mongodb_host, "port": cfg.mongodb_port, **mongo},
        "credentials": credentials,
        "credentials_dir": cfg.credentials_dir,
    }
    label = "Validate the UniFi restore (dry run)" if cfg.dry_run else "Restore UniFi"
    _run(label, "restore", payload, guard=guard)


__all__ = [
    "UnifiBackupConfig",
    "UnifiRestoreConfig",
    "backup_payload",
    "deploy_unifi_backup",
    "deploy_unifi_restore",
]
