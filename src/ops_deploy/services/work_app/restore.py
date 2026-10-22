"""work_app restore (the ``work_app_restore`` role).

Unpacks a backup archive (made by this module's backup or by Ansible's
``work_app_backup``) into a staging directory, checks it, and then, with the
service stopped, puts the database, static files, ``.env``, unit and Traefik
config back. Everything that can be wrong with the archive (missing, wrong
slug, missing metadata fields, an ops-library version mismatch) is found while
planning from the archive's listing and metadata, before any change.

The staging directory goes as soon as the last file has been taken from it,
and with ``cleanup`` (the default) every step that runs while it exists
removes it when that step fails, as the role's ``always`` block does; the
safety snapshot is kept then, as in the role. ``required_mount`` keeps the
staging directory on an external disk
(:mod:`ops_deploy.services._lifecycle.local_backup`).
"""

from __future__ import annotations

import posixpath
import shlex
from pathlib import PurePosixPath
from typing import Annotated

import yaml
from pydantic import Field
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server

from ops_deploy.base._common import AbsolutePath, output
from ops_deploy.helpers import http_check, mark_read_only
from ops_deploy.helpers.python import _as_user
from ops_deploy.services._lifecycle.local_backup import MountGuard, mount_check
from ops_deploy.services.work_app._lifecycle import SLUG, WorkAppPaths

# ``latest``, an archive name below ``root``, or an absolute path.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|/?[A-Za-z0-9._/+-]+\.tar\.gz)$")]
REQUIRED_METADATA = ("slug", "timestamp", "host")


class WorkAppRestoreConfig(WorkAppPaths, MountGuard):
    archive: ArchiveName = "latest"
    root: AbsolutePath = "/opt/backups/work_app"
    dry_run: bool = False
    validate_checksums: bool = True
    cleanup: bool = True
    allow_version_mismatch: bool = False
    restore_env: bool = True
    rebuild_static: bool = False
    staging_dir: AbsolutePath = "/tmp/work-app-restore"
    safe_snapshot_prefix: str = Field(default="pre-restore", pattern=r"^[A-Za-z0-9._-]+$")
    create_safe_snapshot: bool = True
    # Like the role (ops-library a811bc16): the pre-restore copy of the site
    # (database and .env included) is kept after a success too; True deletes it.
    safe_snapshot_delete: bool = False
    reload_traefik: bool = True
    reload_systemd: bool = True
    verify_http: bool = True
    app_host: str = Field(default="127.0.0.1", pattern=r"^[0-9.]+$")
    app_port: int = Field(default=10011, ge=1024, le=65535)
    healthcheck_path: str = Field(default="/accounts/login/", pattern=r"^/[A-Za-z0-9._~/-]*$")
    healthcheck_retries: int = Field(default=5, ge=1)
    healthcheck_delay: int = Field(default=3, ge=0)
    expected_content: str = Field(default="", pattern=r"^[A-Za-z0-9 ._-]*$")
    fix_permissions: bool = True
    env_mode: str = Field(default="0600", pattern=r"^0?[0-7]{3}$")
    use_rsync_delete: bool = True
    # What the archive's metadata must say, unless ``allow_version_mismatch``.
    ops_library_version: str = Field(default="unknown", pattern=r"^[A-Za-z0-9._+-]+$")
    # A timestamp for the safety snapshot's name (Ansible's ``iso8601_basic_short`` on the host).
    timestamp: str | None = Field(default=None, pattern=r"^[0-9]{8}T[0-9]{6}$")

    def guarded_paths(self) -> dict[str, str]:
        return {"staging_dir": self.staging_dir}


def _selected_archive(cfg: WorkAppRestoreConfig) -> str:
    if cfg.archive != "latest":
        path = cfg.archive if cfg.archive.startswith("/") else f"{cfg.root}/{cfg.archive}"
        if output(f"test -f {shlex.quote(path)} && echo yes").strip() != "yes":
            raise DeployError(f"work_app_restore: restore archive {path} does not exist")
        return path
    newest = output(
        f"find {shlex.quote(cfg.root)} -maxdepth 1 -type f -name '*.tar.gz' -printf '%T@ %p\\n' | sort -rn | head -n 1"
    ).strip()
    if not newest:
        raise DeployError(f"work_app_restore: no work app backup archives found under {cfg.root}")
    return newest.partition(" ")[2]


def _payload(archive: str, members: list[str]) -> tuple[str, set[str]]:
    """The payload directory name and the member paths below it."""

    names = [m.removeprefix("./").rstrip("/") for m in members if m.removeprefix("./").rstrip("/")]
    top = list(dict.fromkeys(n.split("/")[0] for n in names))
    stem = posixpath.basename(archive).removesuffix(".tar.gz")
    # Ansible: ``<staging>/<archive name>`` if it exists, else the first directory extracted.
    directories = [t for t in top if any(n.startswith(f"{t}/") for n in names)]
    if stem in directories:
        payload = stem
    elif directories:
        payload = directories[0]
    else:
        raise DeployError(
            f"work_app_restore: archive {posixpath.basename(archive)} did not contain the expected payload directory"
        )
    return payload, {n.removeprefix(f"{payload}/") for n in names if n.startswith(f"{payload}/")}


def _metadata(archive: str, payload: str) -> dict[str, object]:
    raw = output(f"tar -xzOf {shlex.quote(archive)} {shlex.quote(payload + '/metadata.yml')}")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        data = None
    if not isinstance(data, dict):
        raise DeployError("work_app_restore: the archive has no readable metadata.yml")
    return data


def _check_metadata(cfg: WorkAppRestoreConfig, metadata: dict[str, object]) -> None:
    if metadata.get("slug") != SLUG:
        raise DeployError(
            f"work_app_restore: archive slug ({metadata.get('slug')}) does not match expected slug ({SLUG})"
        )
    for field in REQUIRED_METADATA:
        if field not in metadata:
            raise DeployError(f"work_app_restore: metadata.yml missing required field '{field}'")
    archived = str(metadata.get("ops_library_version", "unknown"))
    if archived != cfg.ops_library_version and not cfg.allow_version_mismatch:
        raise DeployError(
            f"work_app_restore: archive was produced with ops-library {archived}, but the current control host "
            f"is running {cfg.ops_library_version}. Set allow_version_mismatch to continue."
        )


def _django(cfg: WorkAppRestoreConfig, *args: str) -> str:
    """The role's ``. .env; python manage.py ...`` as the service user, only when ``.env`` exists."""

    command = shlex.join([cfg.venv_python, "manage.py", *args])
    script = f"set -a; . {shlex.quote(cfg.env_file)}; set +a; exec {command}"
    shell = _as_user(
        cfg.user, PurePosixPath(cfg.home), {"DJANGO_SETTINGS_MODULE": cfg.django_settings_module}, ["sh", "-c", script]
    )
    return f"if [ -f {shlex.quote(cfg.env_file)} ]; then cd {shlex.quote(cfg.site_path)} && {shell}; fi"


def _install_config(src: str, dest: str, follow_up: str) -> str:
    """``copy`` (root, 0644): written only when content, owner or mode differ, then ``follow_up``."""

    return (
        f"if ! cmp -s {src} {dest} || [ \"$(stat -c '%a %U %G' {dest} 2>/dev/null)\" != '644 root root' ]; then "
        f"install -o root -g root -m 0644 {src} {dest} && {{ {follow_up}; }}; fi"
    )


@deploy("work_app restore")
def deploy_work_app_restore(cfg: WorkAppRestoreConfig) -> None:
    """Restore a backup archive; with ``dry_run`` only unpack and check it."""

    archive = _selected_archive(cfg)
    payload_name, members = _payload(archive, output(f"tar -tzf {shlex.quote(archive)}").splitlines())
    _check_metadata(cfg, _metadata(archive, payload_name))
    has = {
        "database": f"database/{posixpath.basename(cfg.database_path)}" in members,
        "static": "static" in members or any(m.startswith("static/") for m in members),
        "env": "env/.env" in members,
        "systemd": f"configs/{cfg.unit}" in members,
        "traefik": "configs/traefik.yml" in members,
        "manifest": "manifest.sha256" in members,
    }

    staging = shlex.quote(cfg.staging_dir)
    payload = shlex.quote(f"{cfg.staging_dir}/{payload_name}")

    def step(name: str, command: str) -> None:
        """A step while the staging directory exists: with ``cleanup`` a failure removes it."""

        if cfg.cleanup:
            # A subshell, so an ``exit`` inside the command still reaches the removal.
            command = f"( {command} ) || {{ rc=$?; rm -rf {staging}; exit $rc; }}"
        server.shell(name=name, commands=[command])

    if cfg.required_mount:
        server.shell(
            name=f"Check {cfg.required_mount} is mounted",
            commands=[mount_check(cfg.required_mount, cfg.staging_dir)],
            _shell_executable="bash",
        )
    server.shell(
        name="Reset the staging directory",
        commands=[f"rm -rf {staging} && mkdir -m 0700 {staging}"],
    )
    step(f"Extract {posixpath.basename(archive)}", f"tar -xzf {shlex.quote(archive)} -C {staging}")
    if cfg.validate_checksums and has["manifest"]:
        step("Validate the checksum manifest", f"cd {payload} && sha256sum -c manifest.sha256")

    def cleanup() -> None:
        if cfg.cleanup:
            server.shell(name="Remove the staging directory", commands=[f"rm -rf {staging}"])

    if cfg.dry_run:
        cleanup()
        return

    if has["database"]:
        step(
            "Check sqlite3 is available",
            "command -v sqlite3 >/dev/null || "
            "{ echo 'sqlite3 is required on the target to verify the restored database' >&2; exit 1; }",
        )
    site = shlex.quote(cfg.site_path)
    snapshot = ""
    if cfg.create_safe_snapshot:
        stamp = cfg.timestamp or output("date +%Y%m%dT%H%M%S").strip()
        snapshot = f"{cfg.site_path}.{cfg.safe_snapshot_prefix}-{stamp}"
    # Stop first (and fail if that fails): neither the snapshot nor the database
    # replacement may run against a live SQLite database.
    step("Stop work-app", f"systemctl stop {shlex.quote(cfg.unit)}")
    if snapshot:
        step(
            "Create the safety snapshot",
            f"install -d -o {cfg.user} -g {cfg.group} -m 0750 {shlex.quote(snapshot)} && "
            f"rsync -a {site}/ {shlex.quote(snapshot)}/",
        )
    static = shlex.quote(cfg.static_root)
    step("Ensure the static directory", f"install -d -o {cfg.user} -g {cfg.group} -m 0750 {static}")
    if has["static"] and not cfg.rebuild_static:
        delete = " --delete" if cfg.use_rsync_delete else ""
        step("Restore the static files", f"rsync -a{delete} {payload}/static/ {static}/")
    db = shlex.quote(cfg.database_path)
    if has["database"]:
        step(
            "Remove stale SQLite journal files",
            "rm -f " + " ".join(shlex.quote(cfg.database_path + s) for s in ("-wal", "-shm", "-journal")),
        )
        source = shlex.quote(f"{cfg.staging_dir}/{payload_name}/database/{posixpath.basename(cfg.database_path)}")
        step("Restore the SQLite database", f"install -o {cfg.user} -g {cfg.group} -m 0600 {source} {db}")
    if cfg.restore_env and has["env"]:
        step(
            "Restore .env",
            f"install -o {cfg.user} -g {cfg.group} -m {cfg.env_mode} {payload}/env/.env {shlex.quote(cfg.env_file)}",
        )
    if has["systemd"]:
        reload = "systemctl daemon-reload" if cfg.reload_systemd else "true"
        step(
            "Restore the systemd unit",
            _install_config(f"{payload}/configs/{shlex.quote(cfg.unit)}", shlex.quote(cfg.unit_path), reload),
        )
    if has["traefik"]:
        reload = "systemctl reload traefik || true" if cfg.reload_traefik else "true"
        step(
            "Restore the Traefik config",
            _install_config(f"{payload}/configs/traefik.yml", shlex.quote(cfg.traefik_config_path), reload),
        )
    # Nothing below reads the staging directory.
    cleanup()
    if cfg.rebuild_static:
        server.shell(name="Rebuild the static files", commands=[_django(cfg, "collectstatic", "--noinput")])
    if cfg.fix_permissions:
        server.shell(
            name="Fix ownership of the static files",
            commands=[f"chown -R {cfg.user}:{cfg.group} {static}"],
        )
    server.shell(name="Run Django system checks", commands=[_django(cfg, "check", "--deploy")])
    server.shell(name="Show migrations for audit", commands=[_django(cfg, "showmigrations")])
    if has["database"]:
        server.shell(
            name="Verify SQLite integrity",
            commands=[
                f'[ "$(sqlite3 {db} "PRAGMA integrity_check")" = ok ] || '
                '{ echo "SQLite integrity check failed" >&2; exit 1; }'
            ],
        )
    server.shell(name="Restart work-app", commands=[f"systemctl restart {shlex.quote(cfg.unit)}"])
    if cfg.verify_http:
        url = f"http://{cfg.app_host}:{cfg.app_port}{cfg.healthcheck_path}"
        _http_check(cfg, url)
    if snapshot and cfg.safe_snapshot_delete:
        server.shell(name="Remove the safety snapshot", commands=[f"rm -rf {shlex.quote(snapshot)}"])
    elif snapshot:
        kept = (
            f"Pre-restore copy of {cfg.site_path} (database and .env included) kept at {snapshot}. "
            "Nothing removes it; prune it by hand once the restored Work app is confirmed."
        )
        mark_read_only(
            server.shell(
                name=f"Report the kept pre-restore copy {snapshot}",
                commands=[f"if [ -d {shlex.quote(snapshot)} ]; then echo {shlex.quote(kept)}; fi"],
            )
        )


def _http_check(cfg: WorkAppRestoreConfig, url: str) -> None:
    if not cfg.expected_content:
        http_check(url, retries=cfg.healthcheck_retries, delay=cfg.healthcheck_delay)
        return
    curl = shlex.join(["curl", "-sS", "--max-time", "5", "-w", "\\n%{http_code}", url])
    script = (
        f"for i in $(seq 1 {cfg.healthcheck_retries}); do out=$({curl} 2>/dev/null); "
        '[ "$(printf %s "$out" | tail -n1)" = 200 ] && '
        f'printf %s "$out" | grep -qF {shlex.quote(cfg.expected_content)} && exit 0; '
        f"sleep {cfg.healthcheck_delay}; done; echo '{url} did not answer as expected' >&2; exit 1"
    )
    server.shell(name=f"Check {url}", commands=[f"sh -c {shlex.quote(script)}"])
