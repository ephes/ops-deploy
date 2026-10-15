"""FastDeploy backup, restore and removal.

Ports of the ``fastdeploy_backup``, ``fastdeploy_restore`` and ``fastdeploy_remove`` roles.

A backup is ``<root>/<prefix>-<timestamp>`` (``root:postgres 0750``) with a
``pg_dump`` of the database, the registered services, the deploy runners
(without the SOPS key), the env file, unit, Traefik route and sudoers rules,
``metadata.yml`` and ``manifest.sha256``, packed as ``<dir>.tar.gz`` (or
``.tar.zst``) as the role packs it. Either tool restores the other's archives
and snapshot directories.

Backup and restore run on the host as one bash script (``files/lifecycle.sh``),
which keeps the roles' structure: a restore takes a safety backup first, and
when restoring or verifying fails it restores that safety backup, verifies it
and still fails; the extracted archive is always removed. The database
password reaches the script on stdin only. Removal is planned from what the
host has, so a second run changes nothing.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, output
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.probes import probe
from ops_deploy.ops import secret_stdin
from ops_deploy.services._lifecycle import (
    flag,
    kill_user_processes,
    private_local_dir,
    remove_account,
    remove_path,
    script,
    stop_disable,
)

LIFECYCLE = Path(__file__).parent / "files" / "lifecycle.sh"
Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
Hostname = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
Identifier = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]{0,62}$")]
Option = Annotated[str, Field(pattern=r"^-[A-Za-z0-9=_-]+$")]
Glob = Annotated[str, Field(pattern=r"^[A-Za-z0-9._*?-]+$")]
Url = Annotated[str, Field(pattern=r"^https?://[A-Za-z0-9.:/_-]+$")]
# ``latest``, a name below the search root (``.tar.gz``/``.tar.zst`` may be left
# out) or an absolute path; an archive or a snapshot directory.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|/?[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*)$")]


class FastdeployBackupConfig(RoleConfig):
    # The metadata's ``host`` (Ansible's ``inventory_hostname``).
    host_name: Hostname
    prefix: Prefix = "manual"
    user: UnixUser = "fastdeploy"
    site_path: AbsolutePath = "/home/fastdeploy/site"
    deploy_home: AbsolutePath = "/home/deploy"
    include_workspace: bool = False
    require_runner_root: bool = False
    root: AbsolutePath = "/opt/backups/fastdeploy"
    postgres_database: Identifier = "fastdeploy"
    # pg_dump's ``--username``; the dump runs as ``postgres_admin``.
    postgres_user: Identifier = "postgres"
    postgres_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.:-]*$")] = ""
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_admin: UnixUser = "postgres"
    dump_options: tuple[Option, ...] = ("--clean", "--if-exists", "--no-owner")
    units: tuple[AbsolutePath, ...] = ("/etc/systemd/system/fastdeploy.service",)
    # Empty: no route is backed up.
    traefik_config_path: Annotated[str, Field(pattern=r"^(/[A-Za-z0-9._/+-]*)?$")] = (
        "/etc/traefik/dynamic/fastdeploy.yml"
    )
    sudoers_dir: AbsolutePath = "/etc/sudoers.d"
    sudoers_pattern: Glob = "fastdeploy_*"
    create_archive: bool = True
    archive_format: Literal["tar.gz", "tar.zst"] = "tar.gz"
    fetch_local: bool = True
    # None: ``~/backups/fastdeploy`` on the controller.
    local_dir: Path | None = None
    disk_check: bool = True
    disk_overhead_ratio: float = Field(default=1.5, gt=0)
    report_size: bool = True
    generate_checksums: bool = True
    # journald export of the unit into ``logs_output`` below the backup.
    include_logs: bool = False
    logs_output: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")] = "logs/fastdeploy.journal"
    metadata_extra: dict[str, Any] = Field(default_factory=dict)
    file_mode: Annotated[str, Field(pattern=r"^0[0-7]{3}$")] = "0640"
    rsync_delete: bool = True
    runner_excludes: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9._/*-]+$")], ...] = (".config/sops/age/keys.txt",)


class FastdeployRestoreConfig(RoleConfig):
    host_name: Hostname
    archive: ArchiveName = "latest"
    search_root: AbsolutePath = "/opt/backups/fastdeploy"
    temp_dir: AbsolutePath = "/tmp/fastdeploy-restore"
    validate_checksums: bool = True
    dry_run: bool = False
    create_safety_backup: bool = True
    # ``latest`` passes over safety backups (``<prefix>-`` in the path) while other archives exist.
    safety_backup_prefix: Prefix = "pre-restore"
    user: UnixUser = "fastdeploy"
    group: UnixUser = "fastdeploy"
    site_path: AbsolutePath = "/home/fastdeploy/site"
    deploy_user: UnixUser = "deploy"
    deploy_group: UnixUser = "deploy"
    require_sops_key: bool = False
    traefik_config_path: Annotated[str, Field(pattern=r"^(/[A-Za-z0-9._/+-]*)?$")] = (
        "/etc/traefik/dynamic/fastdeploy.yml"
    )
    postgres_database: Identifier = "fastdeploy"
    # The restored database's owner; the dump is replayed as this role.
    postgres_user: Identifier = "fastdeploy"
    postgres_admin: UnixUser = "postgres"
    service_name: ServiceName = "fastdeploy"
    http_check: bool = True
    health_url: Url = "http://127.0.0.1:9999/docs"
    http_check_retries: int = Field(default=5, ge=0)
    http_check_delay: int = Field(default=2, ge=0)
    service_count_check: bool = True
    psql_binary: Annotated[str, Field(pattern=r"^[A-Za-z0-9._/-]+$")] = "psql"

    @field_validator("archive")
    @classmethod
    def _no_parent_parts(cls, value: str) -> str:
        if ".." in value.split("/"):
            raise ValueError("archive must not contain '..'")
        return value

    @property
    def deploy_home(self) -> str:
        return f"/home/{self.deploy_user}"


class FastdeployRemoveConfig(RoleConfig):
    confirm: bool = False
    service_name: ServiceName = "fastdeploy"
    user: UnixUser = "fastdeploy"
    group: UnixUser = "fastdeploy"
    home: AbsolutePath = "/home/fastdeploy"
    deploy_user: UnixUser = "deploy"
    deploy_group: UnixUser = "deploy"
    deploy_home: AbsolutePath = "/home/deploy"
    postgres_database: Identifier = "fastdeploy"
    postgres_user: Identifier = "fastdeploy"
    traefik_config_file: AbsolutePath = "/etc/traefik/dynamic/fastdeploy.yml"
    sudoers_dir: AbsolutePath = "/etc/sudoers.d"
    sudoers_pattern: Glob = "fastdeploy_*"


def _password(secrets: SecretValues | None) -> str:
    """``postgres_password`` (the playbooks pass the service's), else empty."""

    password = secrets.get("postgres_password", "") if secrets is not None else ""
    if "\n" in password or "\r" in password:
        raise DeployError("PostgreSQL passfile passwords cannot contain line breaks.")
    return password


def _stamp(what: str) -> str:
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError(f"{what}: cannot read the host's time")
    return stamp


def backup_values(cfg: FastdeployBackupConfig, backup_dir: str) -> dict[str, str | tuple[str, ...]]:
    """The ``B_*`` settings of ``fd_backup`` in ``files/lifecycle.sh``."""

    return {
        "PG_ADMIN": cfg.postgres_admin,
        "B_HOST": cfg.host_name,
        "B_ROOT": cfg.root,
        "B_DIR": backup_dir,
        "B_USER": cfg.user,
        "B_SITE": cfg.site_path,
        "B_ENV": f"{cfg.site_path}/.env",
        "B_SERVICES": f"{cfg.site_path}/services",
        "B_PYTHON": f"{cfg.site_path}/.venv/bin/python",
        "B_RUNNERS": f"{cfg.deploy_home}/runners",
        "B_WORKSPACE": f"{cfg.deploy_home}/_workspace",
        "B_INCLUDE_WORKSPACE": flag(cfg.include_workspace),
        "B_REQUIRE_RUNNERS": flag(cfg.require_runner_root),
        "B_PG_DATABASE": cfg.postgres_database,
        "B_PG_USER": cfg.postgres_user,
        "B_PG_HOST": cfg.postgres_host,
        "B_PG_PORT": str(cfg.postgres_port),
        "B_DUMP_BINARY": "pg_dump",
        "B_DUMP_OPTIONS": cfg.dump_options,
        "B_DUMP_OPTIONS_JSON": json.dumps(" ".join(cfg.dump_options)),
        "B_UNITS": cfg.units,
        "B_TRAEFIK": cfg.traefik_config_path,
        "B_SUDOERS_DIR": cfg.sudoers_dir,
        "B_SUDOERS_PATTERN": cfg.sudoers_pattern,
        "B_CREATE_ARCHIVE": flag(cfg.create_archive),
        "B_FORMAT": cfg.archive_format,
        "B_FETCH": flag(cfg.fetch_local),
        "B_DISK_CHECK": flag(cfg.disk_check),
        "B_OVERHEAD": str(cfg.disk_overhead_ratio),
        "B_REPORT_SIZE": flag(cfg.report_size),
        "B_CHECKSUMS": flag(cfg.generate_checksums),
        "B_INCLUDE_LOGS": flag(cfg.include_logs),
        "B_LOGS_OUTPUT": cfg.logs_output,
        "B_EXTRA": json.dumps(cfg.metadata_extra),
        "B_FILE_MODE": cfg.file_mode,
        "B_RSYNC_DELETE": flag(cfg.rsync_delete),
        "B_RUNNER_EXCLUDES": cfg.runner_excludes,
    }


def _run(name: str, values: dict[str, str | tuple[str, ...]], call: str, password: str) -> None:
    body = script(LIFECYCLE, values, call=f"IFS= read -r PGPW || true\n{call}")
    secret_stdin(name=name, command=f"bash -c {shlex.quote(body)}", content=SecretContent(f"{password}\n"))


@deploy("FastDeploy backup")
def deploy_fastdeploy_backup(cfg: FastdeployBackupConfig, secrets: SecretValues | None = None) -> None:
    """Dump the database, copy FastDeploy's state into a backup directory, pack and fetch it."""

    password = _password(secrets)
    name = f"{cfg.prefix}-{_stamp('fastdeploy_backup')}"
    backup_dir = f"{cfg.root}/{name}"
    _run(f"Back up FastDeploy into {backup_dir}", backup_values(cfg, backup_dir), "fd_backup", password)
    if cfg.create_archive and cfg.fetch_local:
        local_dir = str(cfg.local_dir or Path.home() / "backups" / "fastdeploy")
        python.call(name=f"Ensure {local_dir} (0700)", function=private_local_dir, path=local_dir)
        archive = f"{name}.{cfg.archive_format}"
        files.get(name="Fetch the backup archive", src=f"{cfg.root}/{archive}", dest=f"{local_dir}/{archive}")


@deploy("FastDeploy restore")
def deploy_fastdeploy_restore(cfg: FastdeployRestoreConfig, secrets: SecretValues | None = None) -> None:
    """Restore a backup over FastDeploy, with a safety backup and rollback."""

    password = _password(secrets)
    stamp = _stamp("fastdeploy_restore")
    safety = FastdeployBackupConfig(
        host_name=cfg.host_name,
        prefix=cfg.safety_backup_prefix,
        postgres_user=cfg.postgres_admin,
        postgres_admin=cfg.postgres_admin,
        fetch_local=False,
        include_logs=False,
        metadata_extra={"safety_backup": True},
    )
    site = cfg.site_path
    values: dict[str, str | tuple[str, ...]] = {
        # The safety backup (its B_DIR and B_INCLUDE_WORKSPACE are set at run time).
        **backup_values(safety, ""),
        "STAMP": stamp,
        "R_ARCHIVE": cfg.archive,
        "R_SEARCH_ROOT": cfg.search_root,
        "R_TEMP": cfg.temp_dir,
        "R_VALIDATE_CHECKSUMS": flag(cfg.validate_checksums),
        "R_DRY_RUN": flag(cfg.dry_run),
        "R_SAFETY": flag(cfg.create_safety_backup),
        "R_SAFETY_PREFIX": cfg.safety_backup_prefix,
        "R_USER": cfg.user,
        "R_GROUP": cfg.group,
        "R_SERVICES": f"{site}/services",
        "R_ENV": f"{site}/.env",
        "R_DEPLOY_USER": cfg.deploy_user,
        "R_DEPLOY_GROUP": cfg.deploy_group,
        "R_RUNNERS": f"{cfg.deploy_home}/runners",
        "R_WORKSPACE": f"{cfg.deploy_home}/_workspace",
        "R_REQUIRE_SOPS_KEY": flag(cfg.require_sops_key),
        "R_SOPS_KEY": f"{cfg.deploy_home}/.config/sops/age/keys.txt",
        "R_TRAEFIK": cfg.traefik_config_path,
        "R_PG_DATABASE": cfg.postgres_database,
        "R_PG_USER": cfg.postgres_user,
        "R_SERVICE": cfg.service_name,
        "R_HTTP_CHECK": flag(cfg.http_check),
        "R_HEALTH_URL": cfg.health_url,
        "R_HTTP_RETRIES": str(cfg.http_check_retries),
        "R_HTTP_DELAY": str(cfg.http_check_delay),
        "R_SERVICE_COUNT_CHECK": flag(cfg.service_count_check),
        "R_PSQL": cfg.psql_binary,
    }
    label = " (dry run)" if cfg.dry_run else ""
    _run(f"Restore FastDeploy{label}", values, "fd_restore", password)


def _sql_exists(query: str) -> bool:
    """Whether ``query`` returns 1; also when it fails (then the drop is attempted, errors ignored)."""

    command = f"runuser -u postgres -- psql -tAc {shlex.quote(query)}"
    found = probe(f"command -v psql >/dev/null || exit 0; cd / && {command}", name="FastDeploy database objects")
    return found is None or found.strip() == "1"


@deploy("Remove FastDeploy")
def deploy_fastdeploy_remove(cfg: FastdeployRemoveConfig) -> None:
    """Remove FastDeploy: unit, route, sudoers rules, database and role, both users and their homes."""

    if not cfg.confirm:
        raise DeployError(
            "fastdeploy_remove: removal not confirmed; this deletes FastDeploy, its database, "
            "the fastdeploy and deploy users and their homes. Set confirm to proceed."
        )
    stop_disable([f"{cfg.service_name}.service"])
    reload = remove_path(f"/etc/systemd/system/{cfg.service_name}.service")
    remove_path(cfg.traefik_config_file)
    rules = output(
        f"find {shlex.quote(cfg.sudoers_dir)} -mindepth 1 -maxdepth 1 -type f "
        f"-name {shlex.quote(cfg.sudoers_pattern)} ! -name '.*'"
    )
    for path in rules.splitlines():
        server.shell(name=f"Remove {path}", commands=[f"rm -f {shlex.quote(path)}"])
    # Like the role (ignore_errors), a database or role that cannot be dropped does not stop the removal.
    if _sql_exists(f"SELECT 1 FROM pg_database WHERE datname = '{cfg.postgres_database}'"):
        server.shell(
            name=f"Drop database {cfg.postgres_database}",
            commands=[f"cd / && runuser -u postgres -- dropdb {cfg.postgres_database} || true"],
        )
    if _sql_exists(f"SELECT 1 FROM pg_roles WHERE rolname = '{cfg.postgres_user}'"):
        server.shell(
            name=f"Drop role {cfg.postgres_user}",
            commands=[f"cd / && runuser -u postgres -- dropuser {cfg.postgres_user} || true"],
        )
    for user in (cfg.user, cfg.deploy_user):
        kill_user_processes(user, graceful=False)
    for path in (cfg.home, cfg.deploy_home):
        remove_path(path)
    remove_account(cfg.user, cfg.group)
    remove_account(cfg.deploy_user, cfg.deploy_group)
    if reload:
        systemd.daemon_reload(name="Reload systemd")
