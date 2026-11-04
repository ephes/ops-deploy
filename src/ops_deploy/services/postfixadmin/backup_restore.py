"""PostfixAdmin backup and restore (the ``postfixadmin_backup`` and ``postfixadmin_restore`` roles).

A backup is the directory ``<root>/<timestamp>`` with ``config.local.php``,
``admin.json`` (every column of the admin table, TOTP secrets included),
``domain_admins.json``, the optional ``log.json`` (newest 10000 rows) and
``templates_c.tar.gz``, and ``manifest.yml``, written into
``<timestamp>.tmp`` and renamed once complete, as the role does. Only the
PostfixAdmin overlay is backed up; the mail tables are covered by the
whole-database Echoport dumps. The restore puts back config.local.php
(restarting PHP-FPM when it changed), optionally templates_c, and upserts the
admin tables; nothing is stopped and no other table changes, as with the role.

One Python program on the host (``files/postfixadmin_lifecycle.py``, standard
library only) runs each action; its settings arrive as JSON on stdin with the
database password, which reaches ``psql`` only as PGPASSWORD in its
environment. Queries go through ``psql`` as the ``mail`` user over
``localhost``, the role's ``login_host``/``login_user``.

Deliberate differences from the roles:

- The JSON files are PostgreSQL's own row encoding (``json_agg``), formatted
  like ``to_nice_json``; timestamps keep PostgreSQL's ISO form.
- ``manifest.yml`` is written as JSON (valid YAML, read back with
  ``from_yaml`` by the role and by this restore).
- The admin and domain_admins rows are restored in one transaction
  (``json_populate_record`` over dollar-quoted JSON literals in the SQL on
  psql's stdin, never on its command line), not row by row; a failure changes
  no row. domain_admins rows are validated before any change too.
- A non-numeric schema version (the manifest's or the target's) is refused;
  the role's ``| int`` would read it as 0.
- PHP-FPM restarts only when config.local.php's content changed (the role's
  copy also notified it for an owner or mode change).
- ``latest`` is resolved on the host from the completed backup directories,
  as the playbook's pre tasks do; a dry run (the playbook's) checks only that
  the backup directory exists.
- ``required_mount`` (ops-control: ``/mnt/cryptdata``) is checked before the
  backup's first write.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path, PurePosixPath
from typing import Annotated, Self

from pydantic import Field, SecretStr, StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server

from ops_deploy.base._common import output
from ops_deploy.core.config import UnixUser
from ops_deploy.helpers.probes import stdin_arguments
from ops_deploy.services._lifecycle.canonical import CanonicalPath, Hostname
from ops_deploy.services._lifecycle.local_backup import MountGuard, mount_check

FILES = Path(__file__).parent / "files"
PROGRAM = (FILES / "postfixadmin_lifecycle.py").read_text()
Identifier = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]*$")]
# ``latest``, or a completed backup directory's name.
Timestamp = Annotated[str, Field(pattern=r"^(latest|[0-9]{8}T[0-9]{6})$")]
PhpVersion = Annotated[str, Field(pattern=r"^([0-9]+\.[0-9]+)?$")]


class _Database(MountGuard):
    install_path: CanonicalPath = "/opt/postfixadmin"
    db_host: Annotated[str, Field(pattern=r"^(localhost|127\.0\.0\.1)$")] = "localhost"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: Identifier = "mail"
    db_user: Identifier = "mail"
    db_password: SecretStr
    root: CanonicalPath = "/mnt/cryptdata/backups/postfixadmin"

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}

    def database(self) -> dict[str, object]:
        return {
            "install_path": self.install_path,
            "db_host": self.db_host,
            "db_port": self.db_port,
            "db_name": self.db_name,
            "db_user": self.db_user,
            "db_password": self.db_password.get_secret_value(),
            "root": self.root,
        }


class PostfixAdminBackupConfig(_Database):
    # The manifest's ``hostname`` (Ansible's ``inventory_hostname``).
    host_name: Hostname
    postfixadmin_version: Annotated[str, Field(pattern=r"^[0-9A-Za-z.+-]+$")] = "4.0.5"
    include_templates_c: StrictBool = False
    retention_days: int = Field(default=14, ge=1)
    keep_min: int = Field(default=5, ge=1)


class PostfixAdminRestoreConfig(_Database):
    archive: Timestamp = "latest"
    dry_run: StrictBool = False
    restore_config: StrictBool = True
    restore_admin_tables: StrictBool = True
    restore_templates_c: StrictBool = False
    # Empty: detected with ``php -r`` on the host, as the role does.
    php_version: PhpVersion = ""
    web_user: UnixUser = "www-data"
    web_group: UnixUser = "www-data"
    templates_c_path: CanonicalPath | None = None

    @model_validator(mode="after")
    def _templates_below_install(self) -> Self:
        path = self.templates_c_path
        if path is not None and (
            path == self.install_path or not PurePosixPath(path).is_relative_to(self.install_path)
        ):
            raise ValueError("templates_c_path must lie strictly below install_path")
        return self


def _run(name: str, settings: dict[str, object]) -> None:
    server.shell(
        name=name,
        commands=[f"python3 -I -c {shlex.quote(PROGRAM)}"],
        # The password is in the settings: stdin only, without a pty (stdin_arguments).
        **stdin_arguments(json.dumps(settings) + "\n"),
    )


def _stamp() -> tuple[str, str]:
    # Ansible's iso8601_basic_short (local time) and iso8601 (UTC) of one moment.
    found = output("date +%Y%m%dT%H%M%S; date -u +%Y-%m-%dT%H:%M:%SZ").split()
    if len(found) != 2 or len(found[0]) != 15:
        raise DeployError("postfixadmin: cannot read the host's time")
    return found[0], found[1]


@deploy("PostfixAdmin backup")
def deploy_postfixadmin_backup(cfg: PostfixAdminBackupConfig) -> None:
    """Write a complete backup directory (or nothing), then apply the role's retention."""

    stamp, created = _stamp()
    if cfg.required_mount:
        server.shell(
            name="Check the backup mount",
            commands=[mount_check(cfg.required_mount, cfg.root)],
            _shell_executable="bash",
        )
    _run(
        "Back up PostfixAdmin",
        {
            "action": "backup",
            **cfg.database(),
            "stamp": stamp,
            "created_at": created,
            "host_name": cfg.host_name,
            "postfixadmin_version": cfg.postfixadmin_version,
            "include_templates_c": cfg.include_templates_c,
            "retention_days": cfg.retention_days,
            "keep_min": cfg.keep_min,
        },
    )


def _manifest(cfg: PostfixAdminRestoreConfig) -> str:
    """The backup's manifest as JSON (read and parsed here; it holds no secret)."""

    import yaml

    if cfg.archive == "latest":
        # The host resolves ``latest``; read its manifest after resolving it the same way.
        script = (
            f"root={shlex.quote(cfg.root)}; stamp={shlex.quote(cfg.archive)}; "
            'if [ "$stamp" = latest ]; then stamp=$(find "$root/" -mindepth 1 -maxdepth 1 -type d '
            "-regextype posix-extended -regex '.*/[0-9]{8}T[0-9]{6}' -printf '%f\\n' 2>/dev/null "
            "| LC_ALL=C sort | tail -n 1); fi; "
            '[ -n "$stamp" ] && [ -f "$root/$stamp/manifest.yml" ] && cat -- "$root/$stamp/manifest.yml" || true'
        )
    else:
        path = f"{cfg.root}/{cfg.archive}/manifest.yml"
        script = f"[ -f {shlex.quote(path)} ] && cat -- {shlex.quote(path)} || true"
    text = output(script)
    try:
        return json.dumps(yaml.safe_load(text) if text.strip() else None, default=str)
    except yaml.YAMLError:
        return json.dumps(None)


@deploy("PostfixAdmin restore")
def deploy_postfixadmin_restore(cfg: PostfixAdminRestoreConfig) -> None:
    """Restore config.local.php, templates_c (when asked) and the admin tables from a backup directory."""

    templates = cfg.templates_c_path or f"{cfg.install_path}/templates_c"
    _run(
        "Restore PostfixAdmin" + (" (dry run)" if cfg.dry_run else ""),
        {
            "action": "restore",
            **cfg.database(),
            "stamp": cfg.archive,
            "dry_run": cfg.dry_run,
            "manifest": "null" if cfg.dry_run else _manifest(cfg),
            "restore_config": cfg.restore_config,
            "restore_admin_tables": cfg.restore_admin_tables,
            "restore_templates_c": cfg.restore_templates_c,
            "php_version": cfg.php_version,
            "web_user": cfg.web_user,
            "web_group": cfg.web_group,
            "templates_c_path": templates,
        },
    )


__all__ = [
    "PostfixAdminBackupConfig",
    "PostfixAdminRestoreConfig",
    "deploy_postfixadmin_backup",
    "deploy_postfixadmin_restore",
]
