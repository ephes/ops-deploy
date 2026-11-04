"""Wagtail backup and restore (the ``wagtail_backup`` and ``wagtail_restore`` roles).

A backup is ``<root>/<prefix>-<timestamp>/`` with ``database/<db>.sql.gz``
(``pg_dump`` piped through ``pigz``/``gzip`` as the become user, as
``postgresql_db: state=dump`` runs it) and ``manifest.yml``, packed as
``<dir>.tar.gz`` with the directory's contents below its name, as
``archive: format=gz`` packs it. Either tool restores the other's archives.

Both run on the host as one Python program (``files/wagtail_host.py``) with
the settings and the database passwords on stdin, so the restore's
``block``/``rescue``/``always`` keeps its meaning: a failure after the
database was touched leaves the units stopped and, before the SQL
replacement committed, brings back the verified safety dump; the passfile
directory always goes. The site directory is kept as a pre-restore copy by
ops-library's ``restore_preserve_internal/files/preserve.py``, shipped
unchanged (``files/preserve.py``).

``required_mount`` keeps the backup root on an external disk
(:mod:`ops_deploy.services._lifecycle.local_backup`); the role's own
retention (``retain`` newest archives and directories by mtime) prunes, after
the fetch, as the role does.
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
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.probes import stdin_arguments
from ops_deploy.ops import secret_stdin
from ops_deploy.services._lifecycle.local_backup import MountGuard, mount_check
from ops_deploy.services._lifecycle.preserve import PRESERVE_PY

FILES = Path(__file__).parent / "files"
HOST_SCRIPT = "PRESERVE_SOURCE=" + repr(PRESERVE_PY) + "\n" + (FILES / "wagtail_host.py").read_text()
Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
Identifier = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]{0,62}$")]
Mode = Annotated[
    str,
    BeforeValidator(lambda value: format(value, "04o") if type(value) is int else value),
    Field(pattern=r"^0?[0-7]{3}$"),
]
Port = int | Literal[""]
Host = Annotated[str, Field(pattern=r"^[A-Za-z0-9.:_-]*$")]
# ``latest``, a name below the restore root or an absolute path; an archive or a backup directory.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|/?[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*)$")]
Settings = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]*$")]
PROTECTED = frozenset(
    {"/", "/tmp", "/var", "/var/tmp", "/opt", "/home", "/root", "/etc", "/usr", "/srv", "/mnt", "/var/lib"}
)


def _no_traversal(value: str) -> str:
    if ".." in PurePosixPath(value).parts:
        raise ValueError("paths cannot contain parent traversal")
    return value


def _fill(values: Any, defaults: list[tuple[str, Any]]) -> Any:
    if not isinstance(values, dict):
        return values
    filled = dict(values)
    for name, default in defaults:
        if filled.get(name) is None:
            filled[name] = default(filled) if callable(default) else default
    return filled


class WagtailBackupConfig(MountGuard):
    """``wagtail_backup``'s variables without the prefix; derived defaults follow ``service_name``."""

    service_name: ServiceName
    prefix: Prefix = "manual"
    root: AbsolutePath = ""
    dir_mode: Mode = "0700"
    file_mode: Mode = "0600"
    owner: UnixUser = "root"
    group: UnixUser = "root"
    create_archive: bool = True
    archive_format: Literal["gz"] = "gz"
    archive_extension: Literal["tar.gz"] = "tar.gz"
    fetch_local: bool = True
    # None: ``~/backups/<service_name>`` on the controller.
    local_dir: Path | None = None
    local_dir_mode: Mode = "0700"
    retain: int = Field(default=7, ge=0)
    stop_service: bool = False
    systemd_unit_name: ServiceName = ""
    postgres_database: Identifier = ""
    postgres_user: Identifier = ""
    postgres_host: Host = "localhost"
    postgres_port: Port = 5432
    postgres_become_user: UnixUser = "postgres"
    # Extra ``pg_dump`` options, split like the module's shell command line.
    postgres_target_opts: Annotated[str, Field(pattern=r"^( *-[A-Za-z0-9=_-]+)* *$")] = ""
    generate_manifest: bool = True

    @model_validator(mode="before")
    @classmethod
    def _derived(cls, values: Any) -> Any:
        return _fill(
            values,
            [
                ("root", lambda v: f"/opt/backups/{v.get('service_name', '')}"),
                ("systemd_unit_name", lambda v: v.get("service_name", "")),
                ("postgres_database", lambda v: v.get("service_name", "")),
                ("postgres_user", lambda v: v.get("service_name", "")),
            ],
        )

    @field_validator("root")
    @classmethod
    def _root(cls, value: str) -> str:
        return _no_traversal(value)

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}


class WagtailRestoreConfig(RoleConfig):
    """``wagtail_restore``'s variables without the prefix; derived defaults follow ``service_name``."""

    service_name: ServiceName
    root: AbsolutePath = ""
    archive: ArchiveName = "latest"
    archive_extension: Literal["tar.gz"] = "tar.gz"
    cleanup: bool = True
    restart: bool = True
    stop_service: bool = True
    dry_run: bool = False
    staging_dir: AbsolutePath = ""
    user: UnixUser = ""
    group: UnixUser = ""
    home: AbsolutePath = ""
    site_path: AbsolutePath = ""
    env_path: AbsolutePath = ""
    manage_py: AbsolutePath = ""
    venv_bin: AbsolutePath = ""
    python: AbsolutePath = ""
    django_settings_module: Settings = "config.settings.production"
    run_migrations: bool = True
    collectstatic: bool = True
    update_index: bool = False
    systemd_unit_name: ServiceName = ""
    db_worker_enabled: bool = False
    db_worker_unit_name: ServiceName = ""
    # None: the db worker when ``db_worker_enabled``, else none.
    extra_systemd_units: tuple[ServiceName, ...] | None = None
    postgres_database: Identifier = ""
    postgres_user: Identifier = ""
    postgres_host: Host = "localhost"
    postgres_port: Port = 5432
    postgres_admin_user: Identifier = ""
    postgres_become_user: UnixUser = "postgres"
    postgres_target_opts: str = ""

    @model_validator(mode="before")
    @classmethod
    def _derived(cls, values: Any) -> Any:
        return _fill(
            values,
            [
                ("root", lambda v: f"/opt/backups/{v.get('service_name', '')}"),
                ("staging_dir", lambda v: f"/tmp/wagtail-restore-{v.get('service_name', '')}"),
                ("user", lambda v: v.get("service_name", "")),
                ("group", lambda v: v["user"]),
                ("home", lambda v: f"/home/{v.get('service_name', '')}"),
                ("site_path", lambda v: f"{v['home']}/site"),
                ("env_path", lambda v: f"{v['site_path']}/.env"),
                ("manage_py", lambda v: f"{v['site_path']}/manage.py"),
                ("venv_bin", lambda v: f"{v['site_path']}/.venv/bin"),
                ("python", lambda v: f"{v['venv_bin']}/python"),
                ("systemd_unit_name", lambda v: v.get("service_name", "")),
                ("db_worker_unit_name", lambda v: f"{v.get('service_name', '')}-db-worker"),
                ("postgres_database", lambda v: v.get("service_name", "")),
                ("postgres_user", lambda v: v.get("service_name", "")),
                ("postgres_admin_user", lambda v: v["postgres_user"]),
            ],
        )

    @field_validator("root", "site_path", "staging_dir", "env_path", "manage_py", "python", "home", "venv_bin")
    @classmethod
    def _paths(cls, value: str) -> str:
        return _no_traversal(value)

    @field_validator("archive")
    @classmethod
    def _archive(cls, value: str) -> str:
        return _no_traversal(value)

    @field_validator("postgres_target_opts")
    @classmethod
    def _no_target_opts(cls, value: str) -> str:
        # The role's "Refuse legacy PostgreSQL target options".
        if value:
            raise ValueError(
                "wagtail_restore_postgres_target_opts must be empty; transactional restore owns these options."
            )
        return value

    @model_validator(mode="after")
    def _staging_and_site(self) -> Self:
        # The staging directory is reset with ``rm -rf``; never a system directory.
        for name in ("staging_dir", "site_path"):
            if str(PurePosixPath(getattr(self, name))) in PROTECTED:
                raise ValueError(f"{name} must identify a dedicated directory")
        return self

    @property
    def extra_units(self) -> tuple[str, ...]:
        if self.extra_systemd_units is not None:
            return self.extra_systemd_units
        return (self.db_worker_unit_name,) if self.db_worker_enabled else ()


def _command(action: str) -> str:
    # Encoded trusted packaged source, as the Certbot port: login shells
    # (fish) otherwise alter backslash pairs in nested Python reprs.
    encoded = base64.b64encode(HOST_SCRIPT.encode()).decode()
    loader = f"import base64;exec(compile(base64.b64decode({encoded!r}),'<wagtail-lifecycle>','exec'))"
    return shlex.join(["python3", "-I", "-c", loader, action])


def _passwords(secrets: SecretValues | None, what: str) -> tuple[str, str]:
    """``postgres_password`` (required, as the roles assert) and ``postgres_admin_password`` (default: the same)."""

    password = secrets.get("postgres_password", "") if secrets is not None else ""
    if not password or password == "CHANGEME":
        raise DeployError(f"Missing required Wagtail {what} variables or secrets.")
    admin = (secrets.get("postgres_admin_password", "") if secrets is not None else "") or password
    # The restore's passfile holds ``postgres_password``; the role checks that one only.
    if what == "restore" and ("\n" in password or "\r" in password):
        raise DeployError("PostgreSQL passfile passwords cannot contain line breaks.")
    return password, admin


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
                raise DeployError("wagtail_backup: local archive destination must be a regular, singly-linked file")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
    else:
        os.close(descriptor)


def _port(value: int | str) -> str:
    return str(value)


@deploy("Wagtail backup")
def deploy_wagtail_backup(cfg: WagtailBackupConfig, secrets: SecretValues | None = None) -> None:
    """Dump the database into a backup directory, pack it, fetch the archive and prune old backups."""

    password, _admin = _passwords(secrets, "backup")
    stamp = _stamp("wagtail_backup")
    name = f"{cfg.prefix}-{stamp}"
    backup_dir = f"{cfg.root}/{name}"
    archive = f"{backup_dir}.{cfg.archive_extension}"
    if cfg.required_mount:
        server.shell(
            name=f"Require {cfg.required_mount} below {cfg.root}",
            commands=[mount_check(cfg.required_mount, cfg.root)],
            _shell_executable="bash",
        )
    payload = {
        "service": cfg.service_name,
        "timestamp": stamp,
        "root": cfg.root,
        "dir": backup_dir,
        "archive": archive,
        "dump": f"{backup_dir}/database/{cfg.postgres_database}.sql.gz",
        "owner": cfg.owner,
        "group": cfg.group,
        "dir_mode": cfg.dir_mode,
        "file_mode": cfg.file_mode,
        "stop_service": cfg.stop_service,
        "unit": cfg.systemd_unit_name,
        "database": cfg.postgres_database,
        "user": cfg.postgres_user,
        "host": cfg.postgres_host,
        "port": _port(cfg.postgres_port),
        "become_user": cfg.postgres_become_user,
        "target_opts": shlex.split(cfg.postgres_target_opts),
        "generate_manifest": cfg.generate_manifest,
        "create_archive": cfg.create_archive,
        "password": password,
    }
    secret_stdin(
        name=f"Back up {cfg.service_name} into {backup_dir}",
        command=_command("backup"),
        content=SecretContent(json.dumps(payload) + "\n"),
    )
    if cfg.fetch_local and cfg.create_archive:
        local = str(cfg.local_dir or Path.home() / "backups" / cfg.service_name)
        python.call(
            name=f"Ensure {local} ({cfg.local_dir_mode})", function=_local_dir, path=local, mode=cfg.local_dir_mode
        )
        destination = f"{local}/{PurePosixPath(archive).name}"
        python.call(name="Prepare the private local archive", function=_private_local_file, path=destination)
        files.get(name="Fetch the backup archive", src=archive, dest=destination)
        python.call(name="Restrict the local archive to 0600", function=_private_local_file, path=destination)
    if cfg.retain > 0:
        retention = {
            "root": cfg.root,
            "prefix": cfg.prefix,
            "extension": cfg.archive_extension,
            "retain": cfg.retain,
            "create_archive": cfg.create_archive,
        }
        server.shell(
            name=f"Keep the newest {cfg.retain} {cfg.prefix} backups",
            commands=[_command("retain")],
            **stdin_arguments(json.dumps(retention) + "\n"),
        )


@deploy("Wagtail restore")
def deploy_wagtail_restore(cfg: WagtailRestoreConfig, secrets: SecretValues | None = None) -> None:
    """Restore a backup over the Wagtail database, with a pre-restore copy and safety dump recovery."""

    password, admin = _passwords(secrets, "restore")
    payload = {
        "root": cfg.root,
        "archive": cfg.archive,
        "extension": cfg.archive_extension,
        "cleanup": cfg.cleanup,
        "restart": cfg.restart,
        "stop_service": cfg.stop_service,
        "dry_run": cfg.dry_run,
        "staging": cfg.staging_dir,
        "site_user": cfg.user,
        "site_path": cfg.site_path,
        "env_path": cfg.env_path,
        "manage_py": cfg.manage_py,
        "python": cfg.python,
        "settings": cfg.django_settings_module,
        "run_migrations": cfg.run_migrations,
        "collectstatic": cfg.collectstatic,
        "update_index": cfg.update_index,
        "unit": cfg.systemd_unit_name,
        "extra_units": list(cfg.extra_units),
        "database": cfg.postgres_database,
        "user": cfg.postgres_user,
        "host": cfg.postgres_host,
        "port": _port(cfg.postgres_port),
        "admin_user": cfg.postgres_admin_user,
        "become_user": cfg.postgres_become_user,
        "password": password,
        "admin_password": admin,
    }
    label = " (dry run: validation only)" if cfg.dry_run else ""
    secret_stdin(
        name=f"Restore {cfg.service_name}{label}",
        command=_command("restore"),
        content=SecretContent(json.dumps(payload) + "\n"),
    )


__all__ = ["WagtailBackupConfig", "WagtailRestoreConfig", "deploy_wagtail_backup", "deploy_wagtail_restore"]
