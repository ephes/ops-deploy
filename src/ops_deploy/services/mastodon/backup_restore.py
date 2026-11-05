"""Mastodon backup and restore (the ``mastodon_backup`` and ``mastodon_restore`` roles).

A backup is ``<root>/<prefix>-<timestamp>/`` with ``database/<db>.dump``
(``pg_dump`` custom format), ``media/`` (local storage), ``config/mastodon.env``,
``systemd/``, ``traefik/``, ``nginx/`` and ``manifest.yml``, packed as
``<dir>.tar.gz`` with the directory as the archive's only top-level entry,
exactly as the role writes it. Either tool restores the other's archives.

Backup and restore run on the host as one bash script each (``files/``), so
the roles' ``block``/``always``/``rescue`` structure keeps its meaning: a
backup starts the services it stopped again whatever the capture did; a
restore validates the dump before it stops anything, takes the safety copies
(``pg_dump -Fc`` of the live database, a hard-link snapshot of the media,
copies of the env, unit, Traefik and nginx files) before the first overwrite,
rolls back to them on any later failure (leaving the services stopped) and
always removes the staging directory. The database password reaches the
scripts on stdin and the PostgreSQL tools through a private passfile, as in
the roles; it is never on a command line.

Deliberate differences from the roles:

- ``archive`` is ``latest`` or a ``.tar.gz`` name directly below the restore
  root, never an absolute path (ops-control's restore prelude uploads
  archives there). A symlinked archive is refused.
- ``dry_run`` (not in the role) unpacks the archive into the staging
  directory, validates the dump, prints what the archive holds, removes the
  staging directory (with ``cleanup``) and stops: nothing is stopped or changed.
- A dry run also reports an archive whose ``media/`` holds no files outside
  the media excludes (``media=EMPTY``) and whether the restore (like the
  role, see ``empty_media_confirmed``) refuses it.
- The script's report (archive, components, media excludes, safety paths) is
  logged after the restore operation, so a dry run (``just restore-check``)
  shows it without ``-vvv``; pyinfra shows a command's output only at
  ``-vvv`` or when it fails.
- Both read the media excludes from the archive's ``manifest.yml``; the role
  parses the ``media_rsync_excludes`` line as JSON, the script accepts only
  a JSON list of plain double-quoted strings (no quote or backslash inside,
  as :class:`MastodonBackupConfig` allows) and stops on anything else.
- ``staging_dir``, removed at the start and the end, must be a directory of
  its own: not ``/tmp``, ``/var/tmp`` or a top-level directory.
- A Traefik route that differs from the live one is written only while no
  Traefik transaction holds its lock, like every route writer on the host. A
  lock held at the start stops the restore before anything changes; a lock
  taken later leaves the route as it is, the restore finishes (the services
  start again) and then fails.
- "Installed" units (the role's ``service_facts``) are the Mastodon services
  whose ``LoadState`` is not ``not-found``, or that still run; a unit whose
  state cannot be read counts as installed (it must stop and be confirmed
  stopped).
- The payload directory is the one named after the archive, else the first
  non-hidden directory by name (the role takes ``find``'s first).
- The rollback puts the Traefik route back only when the restore wrote it,
  and only while no Traefik transaction holds its lock (otherwise it reports
  the route as not rolled back).
- The passfile's line-break check runs on the controller before anything
  runs on the host (the role asserts it before each PostgreSQL task).
- The restore's safety timestamp is the controller's UTC time when the
  restore is planned (the role evaluates ``now(utc=true)`` on the controller
  as it runs).
- The controller directory of fetched archives is ``0700`` (the role's
  ``mastodon_backup_dir_mode`` default), the copy ``0600``.
- Not configurable: the ``tar.gz`` archive format (``mastodon_backup_archive_format``,
  ``_extension``), ``mastodon_backup_fetch_become`` (pyinfra streams the
  archive either way) and ``mastodon_nginx_enabled`` (pass ``services`` and
  ``systemd_units`` without nginx instead).
"""

from __future__ import annotations

import json
import os
import shlex
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, python, server

from ops_deploy.base._common import output, require_linux
from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.ops import secret_stdin
from ops_deploy.services._lifecycle import flag, private_local_dir, script
from ops_deploy.services._lifecycle.canonical import ArchiveName, CanonicalPath, FileMode, Prefix
from ops_deploy.services.mastodon.shared import UNIT_DIR, MastodonSite

FILES = Path(__file__).parent / "files"
SLUG = "mastodon"
Binary = Annotated[str, Field(pattern=r"^[A-Za-z0-9_./+-]+$")]
DatabaseName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_]+$")]
PgHost = Annotated[str, Field(pattern=r"^[A-Za-z0-9.:_/-]*$")]
# An rsync exclude pattern (one argument; no line break, quote or backslash, so
# it stays one YAML string in the manifest and the inline script fish-safe).
Exclude = Annotated[str, Field(pattern=r"^[^\n\r\"\\]+$")]


class _Postgres(MastodonSite):
    """The PostgreSQL endpoint both roles read from ``mastodon_shared``."""

    storage_driver: Literal["local", "s3"] = "local"
    postgres_host: PgHost = "localhost"
    postgres_port: int | None = Field(default=5432, ge=1, le=65535)
    postgres_database: DatabaseName = "mastodon"
    postgres_user: UnixUser = "mastodon"

    def conn_args(self) -> tuple[str, ...]:
        """The role's connection flags: host and port when set, and the user."""

        host = (f"--host={self.postgres_host}",) if self.postgres_host else ()
        port = (f"--port={self.postgres_port}",) if self.postgres_port is not None else ()
        return (*host, *port, f"--username={self.postgres_user}")

    def admin_args(self) -> tuple[str, ...]:
        """``dropdb``/``createdb`` as the Postgres OS user: the port always, the host only when remote."""

        local = self.postgres_host in ("", "localhost", "127.0.0.1", "::1")
        host = () if local else (f"--host={self.postgres_host}",)
        port = (f"--port={self.postgres_port}",) if self.postgres_port is not None else ()
        return (*host, *port)


class MastodonBackupConfig(_Postgres):
    """``mastodon_backup``'s variables without ``mastodon_backup_`` (owner and group: ``backup_owner``/``_group``)."""

    root: CanonicalPath = "/opt/backups/mastodon"
    prefix: Prefix = "manual"
    create_archive: StrictBool = True
    fetch_local: StrictBool = True
    # None: ``~/backups/mastodon`` on the controller.
    local_dir: Path | None = None
    dir_mode: FileMode = "0700"
    file_mode: FileMode = "0600"
    backup_owner: UnixUser = "root"
    backup_group: UnixUser = "root"
    stop_services: StrictBool = True
    include_media: StrictBool = True
    include_env: StrictBool = True
    include_systemd: StrictBool = True
    include_traefik: StrictBool = True
    include_nginx: StrictBool = True
    generate_manifest: StrictBool = True
    use_delete: StrictBool = True
    media_rsync_excludes: tuple[Exclude, ...] = ("/cache/***",)
    retain: int = Field(default=7, ge=0)
    retain_all_prefixes: StrictBool = False
    postgres_dump_binary: Binary = "pg_dump"
    postgres_format: Literal["custom", "plain", "tar"] = "custom"
    postgres_compress: int = Field(default=9, ge=0, le=9)
    # None: ``backup_owner``, as the shared defaults derive it.
    postgres_become_user: UnixUser | None = None

    @model_validator(mode="after")
    def _root_apart(self) -> Self:
        # The prune removes entries directly in the root, and with
        # retain_all_prefixes every non-hidden one.
        root = PurePosixPath(self.root)
        for name, path in {"site_path": self.site_path, "media_path": self.media_path}.items():
            live = PurePosixPath(path)
            if live.is_relative_to(root) or root.is_relative_to(live):
                raise ValueError(f"root ({root}) and {name} ({live}) must lie apart")
        return self


class MastodonRestoreConfig(_Postgres):
    """``mastodon_restore``'s variables (``mastodon_restore_`` dropped; ``mastodon_restore_root`` is ``root``)."""

    home_path: CanonicalPath = "/home/mastodon"
    # None: ``<home_path>/.rbenv``.
    rbenv_root: CanonicalPath | None = None
    systemd_unit_dir: CanonicalPath = UNIT_DIR
    root: CanonicalPath = "/opt/backups/mastodon"
    archive: ArchiveName = "latest"
    dry_run: StrictBool = False
    # Allow restoring an archive whose media/ holds no files outside the
    # manifest's media excludes (a backup taken without media still has an
    # empty media/) while the live media holds files outside them, which
    # deletes those. Without it the restore refuses such an archive before
    # anything stops (ops-control: MASTODON_RESTORE_EMPTY_MEDIA_CONFIRMED=true).
    # Live paths the excludes match are always kept.
    empty_media_confirmed: StrictBool = False
    cleanup: StrictBool = True
    restart: StrictBool = True
    stop_services: StrictBool = True
    run_migrations: StrictBool = True
    staging_dir: CanonicalPath = "/var/tmp/mastodon-restore"
    safety_root: CanonicalPath = "/var/backups/mastodon-pre-restore"
    # None: ``<home_path>/media-pre-restore``.
    media_safety_root: CanonicalPath | None = None
    postgres_restore_binary: Binary = "pg_restore"
    postgres_dropdb_binary: Binary = "dropdb"
    postgres_createdb_binary: Binary = "createdb"
    postgres_dump_binary: Binary = "pg_dump"
    postgres_psql_binary: Binary = "psql"
    postgres_become_user: UnixUser = "postgres"

    @property
    def media_safety(self) -> str:
        return self.media_safety_root or f"{self.home_path}/media-pre-restore"

    @property
    def rbenv(self) -> str:
        return self.rbenv_root or f"{self.home_path}/.rbenv"

    @model_validator(mode="after")
    def _paths_apart(self) -> Self:
        # The restore starts with ``rm -rf <staging_dir>`` and removes it at
        # the end: it must hold neither the archives, the live paths nor the
        # safety copies, and lie inside none of the live paths. The media
        # snapshot must lie outside the media directory (rsync --delete would
        # remove it) and the other way round. Paths are compared as spelled;
        # symlinks are not resolved.
        staging = PurePosixPath(self.staging_dir)
        if len(staging.parts) < 3 or self.staging_dir in ("/tmp", "/var/tmp"):
            raise ValueError(f"staging_dir ({staging}) must be a directory of its own, not {staging}")
        live = {
            "site_path": self.site_path,
            "media_path": self.media_path,
            "env_file": self.env_file,
            "traefik_config_path": self.traefik_config_path,
            "nginx_config_path": self.nginx_config_path,
            "systemd_unit_dir": self.systemd_unit_dir,
        }
        kept = {"root": self.root, "safety_root": self.safety_root, "media_safety_root": self.media_safety}
        for name, path in {**kept, **live}.items():
            if PurePosixPath(path).is_relative_to(staging):
                raise ValueError(f"staging_dir ({staging}) must not contain {name} ({path})")
        for name, path in {**live, **kept}.items():
            if staging.is_relative_to(path):
                raise ValueError(f"staging_dir ({staging}) must lie outside {name} ({path})")
        # The media restore runs rsync --delete over media_path: the archives
        # and the safety copies must lie outside it.
        media = PurePosixPath(self.media_path)
        for name, path in kept.items():
            other = PurePosixPath(path)
            if other.is_relative_to(media) or (name == "media_safety_root" and media.is_relative_to(other)):
                raise ValueError(f"{name} ({other}) and media_path ({media}) must lie apart")
        return self


def manifest(cfg: MastodonBackupConfig, *, stamp: str, version: str) -> str:
    """``manifest.yml`` exactly as the role's ``copy`` content renders it."""

    name = f"{cfg.prefix}-{stamp}"
    return (
        f'version: "{version}"\n'
        f'timestamp: "{stamp}"\n'
        f'archive: "{name}.tar.gz"\n'
        f'database_dump: "{cfg.postgres_database}.dump"\n'
        f'media_root: "{cfg.media_path}"\n'
        f"media_rsync_excludes: {json.dumps(list(cfg.media_rsync_excludes))}\n"
        f'env_file: "{cfg.env_file}"\n'
        f'traefik_config: "{cfg.traefik_config_path}"\n'
        f'nginx_config: "{cfg.nginx_config_path}"\n'
    )


def _password(secrets: SecretValues | None) -> str:
    """``postgres_password`` (the playbooks pass ``mastodon_postgres_password``), else empty."""

    password = secrets.get("postgres_password", "") if secrets is not None else ""
    if "\n" in password or "\r" in password:
        raise DeployError("PostgreSQL passfile passwords cannot contain line breaks.")
    return password


def _run(name: str, body: Path, values: dict[str, str | tuple[str, ...]], password: str) -> OperationMeta:
    # postgres.sh (it reads the password from stdin) in front of the body.
    command = script(FILES / "postgres.sh", values, call=body.read_text())
    return secret_stdin(name=name, command=f"bash -c {shlex.quote(command)}", content=SecretContent(f"{password}\n"))


def report(op: OperationMeta) -> None:
    """Log the restore script's output; pyinfra prints it only at ``-vvv`` (or when the script fails)."""

    for line in op.stdout_lines:
        logger.info(f"{host.print_prefix}{line}")


def _restrict_local(path: str) -> None:
    # ``fetch`` writes the copy with the controller's umask; the archive holds the env file and the dump.
    if os.path.exists(path):
        os.chmod(path, 0o600)


def _stamp() -> str:
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("mastodon_backup: cannot read the host's time")
    return stamp


@deploy("Mastodon backup")
def deploy_mastodon_backup(cfg: MastodonBackupConfig, secrets: SecretValues | None = None) -> None:
    """Dump the database and copy media and config into a backup directory, pack, fetch and prune."""

    require_linux("Mastodon backup")
    password = _password(secrets)
    stamp = _stamp()
    name = f"{cfg.prefix}-{stamp}"
    backup_dir = f"{cfg.root}/{name}"
    _run(
        f"Back up Mastodon into {backup_dir}",
        FILES / "backup.sh",
        {
            "ROOT": cfg.root,
            "DIR": backup_dir,
            "OWNER": cfg.backup_owner,
            "GROUP": cfg.backup_group,
            "DIR_MODE": cfg.dir_mode,
            "FILE_MODE": cfg.file_mode,
            "SITE": cfg.site_path,
            "USER_NAME": cfg.user,
            "SERVICES": cfg.services,
            "STOP": flag(cfg.stop_services),
            "PASSFILE_PREFIX": "mastodon_backup",
            "PG_BECOME": cfg.postgres_become_user or cfg.backup_owner,
            "PG_DUMP": cfg.postgres_dump_binary,
            "PG_HOST": cfg.postgres_host,
            "PG_PORT": "" if cfg.postgres_port is None else str(cfg.postgres_port),
            "PG_USER": cfg.postgres_user,
            "PG_FORMAT": cfg.postgres_format,
            "PG_COMPRESS": str(cfg.postgres_compress),
            "PG_DATABASE": cfg.postgres_database,
            "DUMP": f"{backup_dir}/database/{cfg.postgres_database}.dump",
            "STORAGE": cfg.storage_driver,
            "INCLUDE_MEDIA": flag(cfg.include_media),
            "MEDIA": cfg.media_path,
            "DELETE": flag(cfg.use_delete),
            "EXCLUDES": cfg.media_rsync_excludes,
            "INCLUDE_ENV": flag(cfg.include_env),
            "ENV_FILE": cfg.env_file,
            "INCLUDE_SYSTEMD": flag(cfg.include_systemd),
            "UNITS": cfg.systemd_units,
            "INCLUDE_TRAEFIK": flag(cfg.include_traefik),
            "TRAEFIK": cfg.traefik_config_path,
            "INCLUDE_NGINX": flag(cfg.include_nginx),
            "NGINX": cfg.nginx_config_path,
            "MANIFEST": flag(cfg.generate_manifest),
            "MANIFEST_TEXT": manifest(cfg, stamp=stamp, version="@VERSION@"),
            "ARCHIVE": flag(cfg.create_archive),
        },
        password,
    )
    if cfg.create_archive and cfg.fetch_local:
        local_dir = str(cfg.local_dir or Path.home() / "backups" / SLUG)
        local = f"{local_dir}/{name}.tar.gz"
        python.call(name=f"Ensure {local_dir} (0700)", function=private_local_dir, path=local_dir)
        files.get(name="Fetch the backup archive", src=f"{backup_dir}.tar.gz", dest=local)
        python.call(name="Restrict the local archive copy (0600)", function=_restrict_local, path=local)
    if cfg.retain > 0:
        server.shell(
            name=f"Keep the newest {cfg.retain} Mastodon backups",
            commands=[
                script(
                    FILES / "prune.sh",
                    {
                        "ROOT": cfg.root,
                        "RETAIN": str(cfg.retain),
                        "GLOB": "*" if cfg.retain_all_prefixes else f"{cfg.prefix}-*",
                        "ARCHIVE": flag(cfg.create_archive),
                    },
                )
            ],
            _shell_executable="bash",
        )


@deploy("Mastodon restore")
def deploy_mastodon_restore(cfg: MastodonRestoreConfig, secrets: SecretValues | None = None) -> None:
    """Restore a backup archive over Mastodon, with safety copies and rollback."""

    require_linux("Mastodon restore")
    password = _password(secrets)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safety_dir = f"{cfg.safety_root}/{stamp}"
    restored = _run(
        "Restore Mastodon" + (" (dry run)" if cfg.dry_run else ""),
        FILES / "restore.sh",
        {
            "PASSFILE_PREFIX": "mastodon_restore",
            "RESTORE_ROOT": cfg.root,
            "ARCHIVE": cfg.archive,
            "DRY_RUN": flag(cfg.dry_run),
            "EMPTY_MEDIA_CONFIRMED": flag(cfg.empty_media_confirmed),
            "CLEANUP": flag(cfg.cleanup),
            "STAGING": cfg.staging_dir,
            "STORAGE": cfg.storage_driver,
            "USER_NAME": cfg.user,
            "GROUP_NAME": cfg.group,
            "HOME_PATH": cfg.home_path,
            "RBENV_ROOT": cfg.rbenv,
            "SITE": cfg.site_path,
            "ENV_FILE": cfg.env_file,
            "MEDIA": cfg.media_path,
            "TRAEFIK": cfg.traefik_config_path,
            "NGINX": cfg.nginx_config_path,
            "UNIT_DIR": cfg.systemd_unit_dir,
            "SERVICES": cfg.services,
            "STOP": flag(cfg.stop_services),
            "RESTART": flag(cfg.restart),
            "RUN_MIGRATIONS": flag(cfg.run_migrations),
            "SAFETY_ROOT": cfg.safety_root,
            "SAFETY_DIR": safety_dir,
            "SAFETY_DUMP": f"{safety_dir}/database/{cfg.postgres_database}.dump",
            "MEDIA_SAFETY_ROOT": cfg.media_safety,
            "MEDIA_SAFETY": f"{cfg.media_safety}/{stamp}",
            "PG_BECOME": cfg.postgres_become_user,
            "PG_DATABASE": cfg.postgres_database,
            "PG_USER": cfg.postgres_user,
            "PG_RESTORE": cfg.postgres_restore_binary,
            "PG_DROPDB": cfg.postgres_dropdb_binary,
            "PG_CREATEDB": cfg.postgres_createdb_binary,
            "PG_DUMP": cfg.postgres_dump_binary,
            "PG_PSQL": cfg.postgres_psql_binary,
            "CONN_ARGS": cfg.conn_args(),
            "ADMIN_ARGS": cfg.admin_args(),
            "ROUTE_GUARD": tuple(shlex.split(route_guard_command())),
        },
        password,
    )
    python.call(name="Show the restore report", function=report, op=restored)


__all__ = [
    "MastodonBackupConfig",
    "MastodonRestoreConfig",
    "deploy_mastodon_backup",
    "deploy_mastodon_restore",
    "manifest",
]
