"""work_app backup (the ``work_app_backup`` role).

A backup is a directory ``<root>/<prefix>-<timestamp>`` with the SQLite
database (``sqlite3 .backup`` while the service runs, a plain copy with the
service stopped as fallback), the static files, ``.env``, the systemd unit,
the Traefik config, ``metadata.yml`` and a SHA256 manifest, packed as
``<root>/<prefix>-<timestamp>.tar.gz`` with that directory as the archive's
only top-level entry, and fetched to the controller. Ansible's
``work_app_restore`` reads these archives and this module's restore reads
Ansible's.

Differences from the role: the archive is packed with ``umask 077`` (it holds
``.env``); only ``tar.gz`` archives exist.

``required_mount`` keeps the backup root on an external disk and
``retain_count``/``retain_days`` limit the snapshots a backup keeps
(:mod:`ops_deploy.services._lifecycle.local_backup`).
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

from pydantic import Field
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server

from ops_deploy.base._common import AbsolutePath, output
from ops_deploy.services._lifecycle import archive_permissions
from ops_deploy.services._lifecycle.local_backup import SnapshotRetention, backup_preflight, retention
from ops_deploy.services.work_app._lifecycle import SLUG, WorkAppPaths

SUBDIRECTORIES = ("database", "static", "configs", "env")
# ``sqlite3 .timeout``: how long one hot ``.backup`` waits for a writer's lock.
SQLITE_BUSY_TIMEOUT_MS = 30000


class WorkAppBackupConfig(WorkAppPaths, SnapshotRetention):
    root: AbsolutePath = "/opt/backups/work_app"
    prefix: str = Field(default="manual", pattern=r"^[A-Za-z0-9._-]+$")
    include_static: bool = True
    include_env: bool = True
    include_systemd: bool = True
    include_traefik: bool = True
    manifest: bool = True
    create_archive: bool = True
    fetch_local: bool = True
    # None: ``~/backups/work_app`` on the controller.
    local_dir: Path | None = None
    force_stop: bool = False
    sqlite_retries: int = Field(default=3, ge=1)
    rsync_use_delete: bool = True
    # Written to metadata.yml; the restore (either tool) compares it.
    ops_library_version: str = Field(default="unknown", pattern=r"^[A-Za-z0-9._+-]+$")
    # The inventory name of the host, written to metadata.yml.
    inventory_name: str = Field(default="macmini", pattern=r"^[A-Za-z0-9._-]+$")

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}


def _exists(path: str) -> bool:
    return output(f"test -e {shlex.quote(path)} && echo yes").strip() == "yes"


def _private_local_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _sqlite_script(cfg: WorkAppBackupConfig, target: str, mode_file: str) -> str:
    """The role's hot backup with retries and its offline fallback; records the mode used.

    Like ops-library's SQLite runners (2.53.0): ``.timeout`` before ``.backup``
    waits for a committing writer instead of failing with "database is
    locked", and a copy counts only when ``PRAGMA integrity_check`` prints
    exactly ``ok`` (a failed copy is removed). A hot copy that fails the check
    is retried but never answered with the offline copy: the source itself is
    damaged, and stopping the service would not help.
    """

    values = " ".join(
        f"{name}={shlex.quote(value)}"
        for name, value in (("db", cfg.database_path), ("tgt", target), ("mode", mode_file), ("unit", cfg.unit))
    )
    verify = (
        'verify() { out=""; if [ -f "$tgt" ] && out=$(sqlite3 "$tgt" "PRAGMA integrity_check;") '
        '&& [ "$out" = ok ]; then return 0; fi; '
        'echo "work_app_backup: integrity check of $tgt failed: $out" >&2; rm -f "$tgt"; return 1; }'
    )
    # With the service stopped; it is started again however the copy ends, a
    # failed start fails the backup, the copy is checked once it runs again, and
    # a failed copy is removed.
    offline = (
        'trap \'rc=$?; systemctl start "$unit" || rc=1; '
        'if [ $rc = 0 ]; then verify && echo offline > "$mode" || rc=1; else rm -f "$tgt"; fi; exit $rc\' EXIT; '
        'systemctl stop "$unit" && cp "$db" "$tgt"'
    )
    if cfg.force_stop:
        return f"set -e; {values}; {verify}; {offline}"
    attempts = cfg.sqlite_retries
    return (
        f'set -e; {values}; {verify}; hot=0; bad=0; for i in $(seq 1 {attempts}); do rm -f "$tgt"; '
        f'if sqlite3 "$db" ".timeout {SQLITE_BUSY_TIMEOUT_MS}" ".backup \'$tgt\'"; then '
        "if verify; then hot=1; break; fi; bad=1; fi; "
        f'echo "work_app_backup: SQLite backup attempt $i/{attempts} failed" >&2; '
        f"[ $i = {attempts} ] || sleep 2; done; "
        'if [ $hot = 1 ]; then echo hot > "$mode"; '
        'elif [ $bad = 1 ]; then rm -f "$tgt"; '
        'echo "work_app_backup: no offline copy of a database that fails its integrity check" >&2; '
        f"exit 1; else {offline}; fi"
    )


def _metadata_script(cfg: WorkAppBackupConfig, backup_dir: str, stamp: str, mode_file: str | None) -> str:
    """metadata.yml in the role's format; ``sqlite_mode`` comes from the backup step."""

    def flag(value: bool) -> str:
        return "True" if value else "False"

    read_mode = f"$(cat {shlex.quote(mode_file)})" if mode_file else "missing"
    lines = [
        f'slug: "{SLUG}"',
        f'timestamp: "{stamp}"',
        f'host: "{cfg.inventory_name}"',
        f'ops_library_version: "{cfg.ops_library_version}"',
        'sqlite_mode: "$MODE"',
        f"include_static: {flag(cfg.include_static)}",
        f"include_env: {flag(cfg.include_env)}",
        f"include_systemd: {flag(cfg.include_systemd)}",
        f"include_traefik: {flag(cfg.include_traefik)}",
        f'site_path: "{cfg.site_path}"',
        f'database_path: "{cfg.database_path}"',
        f'static_root: "{cfg.static_root}"',
        f'env_file: "{cfg.env_file}"',
    ]
    target = shlex.quote(f"{backup_dir}/metadata.yml")
    body = "\n".join(lines)
    return f'MODE="{read_mode}"; cat > {target} <<EOF\n{body}\nEOF\nchmod 0600 {target}'


@deploy("work_app backup")
def deploy_work_app_backup(cfg: WorkAppBackupConfig) -> None:
    """Write a backup directory and archive under ``root`` and fetch the archive."""

    if not _exists(cfg.site_path):
        raise DeployError(f"work_app_backup: {cfg.site_path} must exist on the target host")
    present = {
        "database": _exists(cfg.database_path),
        "static": _exists(cfg.static_root),
        "env": _exists(cfg.env_file),
        "systemd": _exists(cfg.unit_path),
        "traefik": _exists(cfg.traefik_config_path),
    }
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("work_app_backup: cannot read the host's time")
    name = f"{cfg.prefix}-{stamp}"
    backup_dir = f"{cfg.root}/{name}"
    archive = f"{backup_dir}.tar.gz"
    quoted = shlex.quote(backup_dir)
    mode_file = f"{backup_dir}/database/.mode"

    preflight = backup_preflight(cfg, cfg.root, name)
    if preflight:
        server.shell(name="Check the backup root and name", commands=[preflight], _shell_executable="bash")
    for path in (cfg.root, backup_dir, *(f"{backup_dir}/{sub}" for sub in SUBDIRECTORIES)):
        files.directory(name=f"Ensure {path}", path=path, user="root", group="root", mode="0700")
    server.shell(
        name="Restrict existing backup archives",
        commands=[archive_permissions(cfg.root)],
    )

    if present["database"]:
        target = f"{backup_dir}/database/{os.path.basename(cfg.database_path)}"
        server.shell(name="Back up the SQLite database", commands=[_sqlite_script(cfg, target, mode_file)])
    if cfg.include_static and present["static"]:
        delete = " --delete" if cfg.rsync_use_delete else ""
        server.shell(
            name="Copy the static files",
            commands=[f"rsync -a{delete} {shlex.quote(cfg.static_root)}/ {quoted}/static/"],
        )
    for label, include, key, source, dest in (
        (".env", cfg.include_env, "env", cfg.env_file, "env/.env"),
        ("systemd unit", cfg.include_systemd, "systemd", cfg.unit_path, f"configs/{cfg.unit}"),
        ("Traefik config", cfg.include_traefik, "traefik", cfg.traefik_config_path, "configs/traefik.yml"),
    ):
        if include and present[key]:
            server.shell(
                name=f"Copy the {label}",
                commands=[f"install -o root -g root -m 0600 {shlex.quote(source)} {quoted}/{dest}"],
            )
    server.shell(
        name="Write the backup metadata",
        commands=[_metadata_script(cfg, backup_dir, stamp, mode_file if present["database"] else None)],
    )
    if present["database"]:
        server.shell(name="Drop the mode marker", commands=[f"rm -f {shlex.quote(mode_file)}"])
    if cfg.manifest:
        script = (
            f"set -euo pipefail; cd {quoted}; "
            "find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum > manifest.sha256"
        )
        server.shell(name="Generate the checksum manifest", commands=[f"bash -c {shlex.quote(script)}"])
    if cfg.create_archive:
        server.shell(
            name=f"Create {archive}",
            commands=[
                f"(umask 077 && tar -C {shlex.quote(cfg.root)} -czf {shlex.quote(archive)} {shlex.quote(name)})"
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
        local_dir = str(cfg.local_dir or Path.home() / "backups" / "work_app")
        python.call(name=f"Ensure {local_dir} (0700)", function=_private_local_dir, path=local_dir)
        files.get(name="Fetch the backup archive", src=archive, dest=f"{local_dir}/{name}.tar.gz")
