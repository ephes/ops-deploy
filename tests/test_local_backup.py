"""The external-disk guard, snapshot retention and restore work-directory cleanup of the backup ports.

The shell parts run locally with bash: ``findmnt`` is a stub (mounted or not),
``chown``/``stat`` are stubs for the non-root run, and ``realpath`` must be
GNU's (``-e``/``-m``), as on the Linux targets (``grealpath`` on macOS).
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.infra import (
    TraefikBackupConfig,
    TraefikRestoreConfig,
    deploy_traefik_backup,
    deploy_traefik_restore,
)
from ops_deploy.infra.traefik_backup import _canonical, _dynamic_tree_check, _resolved_paths
from ops_deploy.services._lifecycle import script
from ops_deploy.services._lifecycle.local_backup import SnapshotRetention, backup_preflight, mount_check, retention
from ops_deploy.services.fastdeploy import (
    FastdeployBackupConfig,
    FastdeployRestoreConfig,
    deploy_fastdeploy_backup,
    deploy_fastdeploy_restore,
)
from ops_deploy.services.fastdeploy.lifecycle import LIFECYCLE, backup_values
from ops_deploy.services.nyxmon import (
    NyxmonBackupConfig,
    NyxmonRestoreConfig,
    deploy_nyxmon_backup,
    deploy_nyxmon_restore,
)
from ops_deploy.services.nyxmon.lifecycle import FILES
from ops_deploy.services.work_app import (
    WorkAppBackupConfig,
    WorkAppRestoreConfig,
    deploy_work_app_backup,
    deploy_work_app_restore,
)
from ops_deploy.testing import FakeRun, run_deploy_fake

STAMP = "20261022T120000"
MOUNT = "/opt/backups"


def _gnu_realpath() -> str | None:
    for candidate in ("realpath", "grealpath"):
        path = shutil.which(candidate)
        if path and subprocess.run([path, "-m", "--", "/nonexistent/x"], capture_output=True).returncode == 0:
            return path
    return None


REALPATH = _gnu_realpath()
needs_gnu = pytest.mark.skipif(REALPATH is None, reason="needs GNU realpath (-e/-m), as on the Linux targets")


def shell_env(tmp_path: Path, *, mounted: bool) -> dict[str, str]:
    """PATH with ``findmnt`` (logging its arguments), ``chown``, ``stat`` and GNU ``realpath`` stubs first."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "findmnt.log"
    stubs = {
        "findmnt": f'echo "$*" >> {shlex.quote(str(log))}\nexit {0 if mounted else 1}\n',
        "chown": "exit 0\n",
        "stat": "echo stub\n",
        "realpath": f'exec {REALPATH} "$@"\n',
    }
    for name, body in stubs.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}")
        path.chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


def run_bash(command: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", "-c", command], capture_output=True, text=True, env=env, timeout=60)


# -- configuration ------------------------------------------------------------


def test_defaults_guard_nothing_and_keep_everything() -> None:
    for cfg in (
        TraefikBackupConfig(),
        NyxmonBackupConfig(host_name="host"),
        FastdeployBackupConfig(host_name="host"),
        WorkAppBackupConfig(),
    ):
        assert cfg.required_mount is None
        assert not cfg.retention
    for restore in (TraefikRestoreConfig(), NyxmonRestoreConfig(host_name="host"), WorkAppRestoreConfig()):
        assert restore.required_mount is None
    assert FastdeployRestoreConfig(host_name="host").safety_backup_root == "/opt/backups/fastdeploy"


@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda: TraefikBackupConfig(required_mount=MOUNT, root="/srv/traefik"), "root (/srv/traefik)"),
        (lambda: TraefikBackupConfig(required_mount=MOUNT, root=MOUNT), "root (/opt/backups)"),
        (lambda: TraefikBackupConfig(required_mount=MOUNT, root="/opt/backups/../x"), "root"),
        (lambda: TraefikBackupConfig(required_mount="/", root="/opt/backups/x"), "other than /"),
        (lambda: TraefikBackupConfig(required_mount="/opt/backups/", root="/opt/backups/x"), "canonical"),
        (lambda: TraefikRestoreConfig(required_mount=MOUNT), "staging_dir (/tmp/traefik-restore)"),
        (lambda: NyxmonRestoreConfig(host_name="m", required_mount=MOUNT), "staging_dir (/tmp/nyxmon-restore)"),
        (lambda: WorkAppRestoreConfig(required_mount=MOUNT), "staging_dir (/tmp/work-app-restore)"),
        (lambda: FastdeployRestoreConfig(host_name="m", required_mount=MOUNT), "temp_dir (/tmp/fastdeploy-restore)"),
        (
            lambda: FastdeployRestoreConfig(
                host_name="m", required_mount=MOUNT, temp_dir="/opt/backups/w", safety_backup_root="/srv/fd"
            ),
            "safety_backup_root (/srv/fd)",
        ),
        (lambda: NyxmonBackupConfig(host_name="m", retain_count=-1), "greater than or equal"),
    ],
)
def test_paths_outside_the_required_mount_are_refused(make: Any, message: str) -> None:
    with pytest.raises(ValidationError, match=message.replace("(", r"\(").replace(")", r"\)")):
        make()


def test_cutoff_counts_back_from_the_hosts_time() -> None:
    assert NyxmonBackupConfig(host_name="m", retain_days=14).cutoff(STAMP) == "20261008T120000"
    assert NyxmonBackupConfig(host_name="m", retain_count=3).cutoff(STAMP) == ""


# -- the mount check ------------------------------------------------------------


@needs_gnu
def test_mount_check_passes_for_a_path_below_a_mounted_mount(tmp_path: Path) -> None:
    mount = tmp_path / "disk"
    mount.mkdir()
    result = run_bash(mount_check(str(mount), str(mount / "backups" / "svc")), shell_env(tmp_path, mounted=True))

    assert result.returncode == 0, result.stderr
    real = os.path.realpath(mount)
    assert (tmp_path / "findmnt.log").read_text().split() == ["--mountpoint", real, "--types", "noautofs"]


@needs_gnu
def test_mount_check_stops_when_the_disk_is_not_mounted(tmp_path: Path) -> None:
    mount = tmp_path / "disk"
    mount.mkdir()
    result = run_bash(mount_check(str(mount), str(mount / "svc")), shell_env(tmp_path, mounted=False))

    assert result.returncode == 1
    assert "is not mounted; refusing to write below it" in result.stderr


@needs_gnu
def test_mount_check_stops_when_the_mount_point_is_missing(tmp_path: Path) -> None:
    result = run_bash(mount_check(str(tmp_path / "gone"), str(tmp_path / "gone/x")), shell_env(tmp_path, mounted=True))

    assert result.returncode == 1
    assert "does not exist" in result.stderr


@needs_gnu
def test_mount_check_follows_links_out_of_the_mount(tmp_path: Path) -> None:
    mount = tmp_path / "disk"
    mount.mkdir()
    (tmp_path / "rootfs").mkdir()
    (mount / "escape").symlink_to(tmp_path / "rootfs", target_is_directory=True)
    result = run_bash(mount_check(str(mount), str(mount / "escape" / "svc")), shell_env(tmp_path, mounted=True))

    assert result.returncode == 1
    assert "outside the required mount" in result.stderr


@needs_gnu
def test_nyxmon_backup_writes_nothing_without_the_mount(tmp_path: Path) -> None:
    mount = tmp_path / "disk"
    mount.mkdir()
    root = mount / "nyxmon"
    values = {
        "REQUIRED_MOUNT": str(mount),
        "RECORD": "0",
        "ROOT": str(root),
        "DIR": str(root / f"manual-{STAMP}"),
        "DB": str(tmp_path / "db.sqlite3"),
        "STOP": "1",
        "SQLITE_BACKUP": "0",
        "SQLITE_TIMEOUT_MS": "1",
        "SQLITE_ATTEMPTS": "1",
        "SQLITE_RETRY_DELAY": "0",
        "DELETE": "0",
        "STOP_ORDER": ("nyxmon.service",),
        "START_ORDER": ("nyxmon.service",),
        "DIRS": (),
        "COPIES": (),
    }
    result = run_bash(script(FILES / "backup.sh", values), shell_env(tmp_path, mounted=False))

    assert result.returncode == 1
    assert "is not mounted" in result.stderr
    assert list(mount.iterdir()) == []


@needs_gnu
def test_fastdeploy_backup_writes_nothing_without_the_mount(tmp_path: Path) -> None:
    site = tmp_path / "site"
    (site / "services").mkdir(parents=True)
    (site / ".env").write_text("X=1\n")
    mount = tmp_path / "disk"
    mount.mkdir()
    cfg = FastdeployBackupConfig(
        host_name="m", site_path=str(site), root=str(mount / "fastdeploy"), required_mount=str(mount)
    )
    values = backup_values(cfg, f"{cfg.root}/manual-{STAMP}", stamp=STAMP)
    command = script(LIFECYCLE, values, call="PGPW=\nfd_backup")
    result = run_bash(command, shell_env(tmp_path, mounted=False))

    assert result.returncode == 1
    assert "is not mounted" in result.stderr
    assert list(mount.iterdir()) == []


# -- retention ------------------------------------------------------------------


def snapshot(root: Path, name: str, *, recorded: bool = True, archive: str = "tar.gz") -> None:
    (root / name).mkdir(parents=True)
    (root / name / "metadata.yml").write_text("x\n")
    (root / f"{name}.{archive}").write_text("archive\n")
    if recorded:
        records = root / ".ops-deploy-snapshots"
        records.mkdir(exist_ok=True)
        (records / name).touch()


def remaining(root: Path) -> set[str]:
    return {p.name for p in root.iterdir()} - {".ops-deploy-snapshots"}


@needs_gnu
@pytest.mark.parametrize("archive", ["tar.gz", "tar.zst"])
def test_retention_keeps_the_newest_per_prefix_and_never_unrecorded_snapshots(tmp_path: Path, archive: str) -> None:
    root = tmp_path / "backups"
    for day in ("01", "02", "03", "04"):
        snapshot(root, f"manual-202610{day}T120000", archive=archive)
    snapshot(root, "predeploy-20261001T120000", archive=archive)
    snapshot(root, "manual-20250101T000000", recorded=False, archive=archive)  # Ansible's, or older
    (root / "notes.txt").write_text("keep\n")
    current = f"manual-{STAMP}"
    snapshot(root, current, recorded=False, archive=archive)
    cfg = SnapshotRetention(retain_count=2)

    result = run_bash(retention(cfg, str(root), current, STAMP), shell_env(tmp_path, mounted=True))

    assert result.returncode == 0, result.stderr
    assert remaining(root) == {
        current,
        f"{current}.{archive}",
        "manual-20261004T120000",
        f"manual-20261004T120000.{archive}",
        "predeploy-20261001T120000",
        f"predeploy-20261001T120000.{archive}",
        "manual-20250101T000000",
        f"manual-20250101T000000.{archive}",
        "notes.txt",
    }
    assert sorted(p.name for p in (root / ".ops-deploy-snapshots").iterdir()) == [
        "manual-20261004T120000",
        current,
        "predeploy-20261001T120000",
    ]
    assert "Pruning local snapshot" in result.stdout


@needs_gnu
def test_retention_by_age_keeps_the_snapshot_just_written(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    snapshot(root, "manual-20261001T120000")
    snapshot(root, "manual-20261009T120000")
    # A host clock that went backwards: the snapshot just written is the oldest.
    current = "manual-20260101T000000"
    snapshot(root, current, recorded=False)
    cfg = SnapshotRetention(retain_days=14)

    result = run_bash(retention(cfg, str(root), current, STAMP), shell_env(tmp_path, mounted=True))

    assert result.returncode == 0, result.stderr
    assert remaining(root) == {
        current,
        f"{current}.tar.gz",
        "manual-20261009T120000",
        "manual-20261009T120000.tar.gz",
    }


@needs_gnu
def test_a_record_name_with_a_newline_never_stands_for_another_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    snapshot(root, "manual-20261001T120000", recorded=False)  # unrecorded: must stay
    snapshot(root, "manual-20261010T120000")
    (root / ".ops-deploy-snapshots" / "invalid\nmanual-20261001T120000").touch()
    current = f"manual-{STAMP}"
    snapshot(root, current, recorded=False)

    result = run_bash(
        retention(SnapshotRetention(retain_count=1), str(root), current, STAMP), shell_env(tmp_path, mounted=True)
    )

    assert result.returncode == 0, result.stderr
    assert remaining(root) == {
        current,
        f"{current}.tar.gz",
        "manual-20261001T120000",
        "manual-20261001T120000.tar.gz",
    }


@needs_gnu
def test_retention_prunes_snapshots_with_a_dot_prefix(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    snapshot(root, ".hidden-20261001T120000")
    current = f".hidden-{STAMP}"
    snapshot(root, current, recorded=False)

    result = run_bash(
        retention(SnapshotRetention(retain_count=1), str(root), current, STAMP), shell_env(tmp_path, mounted=True)
    )

    assert result.returncode == 0, result.stderr
    assert remaining(root) == {current, f"{current}.tar.gz"}


@needs_gnu
@pytest.mark.parametrize("existing", ["", ".tar.gz", ".tar.zst", "record"])
def test_a_backup_under_retention_refuses_a_name_already_taken(tmp_path: Path, existing: str) -> None:
    root = tmp_path / "backups"
    root.mkdir()
    name = f"manual-{STAMP}"
    if existing == "record":
        (root / ".ops-deploy-snapshots").mkdir()
        (root / ".ops-deploy-snapshots" / name).touch()
    elif existing:
        (root / f"{name}{existing}").write_text("someone else's\n")
    else:
        (root / name).mkdir()
    cfg = SnapshotRetention(retain_count=3)
    preflight = backup_preflight(cfg, str(root), name)
    assert preflight is not None

    result = run_bash(preflight, shell_env(tmp_path, mounted=True))

    assert result.returncode == 1
    assert "already exists" in result.stderr


@needs_gnu
def test_fastdeploy_backup_under_retention_refuses_a_name_already_taken(tmp_path: Path) -> None:
    site = tmp_path / "site"
    (site / "services").mkdir(parents=True)
    (site / ".env").write_text("X=1\n")
    root = tmp_path / "fastdeploy"
    root.mkdir()
    (root / f"manual-{STAMP}.tar.zst").write_text("legacy\n")
    cfg = FastdeployBackupConfig(host_name="m", site_path=str(site), root=str(root), retain_count=3)
    command = script(LIFECYCLE, backup_values(cfg, f"{cfg.root}/manual-{STAMP}", stamp=STAMP), call="PGPW=\nfd_backup")

    result = run_bash(command, shell_env(tmp_path, mounted=True))

    assert result.returncode == 1
    assert "already exists" in result.stderr
    assert sorted(p.name for p in root.iterdir()) == [f"manual-{STAMP}.tar.zst"]


@needs_gnu
@pytest.mark.parametrize("guarded", [True, False])
def test_fastdeploy_restore_passfile_stays_below_the_guarded_temp_directory(tmp_path: Path, guarded: bool) -> None:
    temp = tmp_path / "work"
    log = tmp_path / "mktemp.log"
    env = shell_env(tmp_path, mounted=True)
    bin_dir = tmp_path / "bin"
    stubs = {
        # ``runuser -u USER -- CMD...`` runs CMD as this user.
        "runuser": 'shift 3\nexec "$@"\n',
        "mktemp": f'echo "$*" >> {log}\nexec /usr/bin/mktemp -d "{tmp_path}/pgpass.XXXXXX"\n',
        "dropdb": "exit 0\n",
        "createdb": "exit 0\n",
        "psql": "cat >/dev/null\n",
        "systemctl": "exit 0\n",
    }
    for name, body in stubs.items():
        (bin_dir / name).write_text(f"#!/bin/sh\n{body}")
        (bin_dir / name).chmod(0o755)
    snapshot_dir = tmp_path / "snap"
    (snapshot_dir / "database").mkdir(parents=True)
    (snapshot_dir / "database" / "fastdeploy.sql").write_text("SELECT 1;\n")
    values = {
        "PG_ADMIN": "postgres",
        "R_MOUNT": str(tmp_path) if guarded else "",
        "R_TEMP": str(temp),
        "R_SERVICE": "fastdeploy",
        "R_PG_DATABASE": "fastdeploy",
        "R_PG_USER": "fastdeploy",
        "R_PSQL": "psql",
    }
    call = f"PGPW=secret\nsnapshot={shlex.quote(str(snapshot_dir))}\nincludes_database=1\npgpass_dir=\nrestore_database"

    result = run_bash(script(LIFECYCLE, values, call=call), env)

    assert result.returncode == 0, result.stderr
    parent = str(temp) if guarded else "/tmp"
    assert log.read_text().split() == ["-d", f"{parent}/fastdeploy_restore-pgpass-XXXXXXXXXX"]


@needs_gnu
def test_retention_ignores_records_that_are_not_snapshot_names(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    snapshot(root, "manual-20261001T120000")
    records = root / ".ops-deploy-snapshots"
    (records / "notes").touch()
    (root / "notes").mkdir()
    current = f"manual-{STAMP}"
    snapshot(root, current, recorded=False)

    result = run_bash(
        retention(SnapshotRetention(retain_count=1), str(root), current, STAMP), shell_env(tmp_path, mounted=True)
    )

    assert result.returncode == 0, result.stderr
    assert remaining(root) == {current, f"{current}.tar.gz", "notes"}


# -- what the deploys run -------------------------------------------------------


def test_work_app_backup_checks_the_mount_first_and_prunes_after_the_archive(tmp_path: Path) -> None:
    cfg = WorkAppBackupConfig(required_mount=MOUNT, retain_count=3, retain_days=14, fetch_local=False)
    responses = {
        "date +%Y%m%dT%H%M%S": [STAMP],
        "test -e /home/work/site &&": ["yes"],
    }
    run = run_deploy_fake(deploy_work_app_backup, cfg, responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "require_mount /opt/backups /opt/backups/work_app" in commands[0]
    assert f"require_new_snapshot /opt/backups/work_app manual-{STAMP}" in commands[0]
    assert (
        commands[-1]
        .rstrip()
        .endswith(
            f"record_snapshot /opt/backups/work_app manual-{STAMP}\n"
            f"prune_snapshots /opt/backups/work_app 3 20261008T120000 manual-{STAMP}"
        )
    )
    archive = next(i for i, c in enumerate(commands) if "tar -C /opt/backups/work_app -czf" in c)
    assert archive == len(commands) - 2


def test_work_app_backup_without_a_policy_runs_neither(tmp_path: Path) -> None:
    run = run_deploy_fake(
        deploy_work_app_backup,
        WorkAppBackupConfig(fetch_local=False),
        responses={"date +%Y%m%dT%H%M%S": [STAMP], "test -e /home/work/site &&": ["yes"]},
    )

    assert run.succeeded, run.error
    assert not any(
        call in c
        for c in run.executed_commands
        for call in ("require_mount", "require_new_snapshot", "prune_snapshots")
    )


def test_a_failed_mount_check_stops_the_work_app_backup_before_any_write() -> None:
    cfg = WorkAppBackupConfig(required_mount=MOUNT, fetch_local=False)
    check = "require_mount /opt/backups /opt/backups/work_app"
    responses = {
        "date +%Y%m%dT%H%M%S": [STAMP],
        "test -e /home/work/site &&": ["yes"],
        check: {"success": False},
    }
    run = run_deploy_fake(deploy_work_app_backup, cfg, responses=responses)

    assert not run.succeeded
    (command,) = run.executed_commands
    assert check in command


def test_work_app_restore_checks_the_mount_before_the_staging_directory() -> None:
    staging = "/opt/backups/work_app/.restore-work"
    cfg = WorkAppRestoreConfig(required_mount=MOUNT, staging_dir=staging, dry_run=True)
    archive = f"/opt/backups/work_app/manual-{STAMP}.tar.gz"
    payload = f"manual-{STAMP}"
    responses = {
        "find /opt/backups/work_app -maxdepth 1": [f"1760000000.5 {archive}"],
        f"tar -tzf {archive}": [f"{payload}/", f"{payload}/metadata.yml"],
        f"tar -xzOf {archive} {payload}/metadata.yml": ['slug: "work_app"', f'timestamp: "{STAMP}"', 'host: "m"'],
    }
    run = run_deploy_fake(deploy_work_app_restore, cfg, responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert f"require_mount /opt/backups {staging}" in commands[0]
    assert commands[1] == f"rm -rf {staging} && mkdir -m 0700 {staging}"
    assert commands[-1] == f"rm -rf {staging}"


@pytest.mark.parametrize(
    ("command", "code"),
    [
        ("true", 0),
        ("false", 1),
        # The sqlite3 check's own ``exit``: it must still reach the removal.
        ("command -v no-such-tool-here >/dev/null || { echo missing >&2; exit 3; }", 3),
    ],
)
def test_work_app_restore_step_removes_the_staging_directory_when_it_fails(
    tmp_path: Path, command: str, code: int
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "payload").write_text("x\n")
    cfg = WorkAppRestoreConfig(staging_dir=str(staging), dry_run=False)
    archive = f"/opt/backups/work_app/manual-{STAMP}.tar.gz"
    payload = f"manual-{STAMP}"
    responses = {
        "find /opt/backups/work_app -maxdepth 1": [f"1760000000.5 {archive}"],
        f"tar -tzf {archive}": [f"{payload}/", f"{payload}/database/db.sqlite3", f"{payload}/metadata.yml"],
        f"tar -xzOf {archive} {payload}/metadata.yml": ['slug: "work_app"', f'timestamp: "{STAMP}"', 'host: "m"'],
        "date +%Y%m%dT%H%M%S": [STAMP],
    }
    run = run_deploy_fake(deploy_work_app_restore, cfg, responses=responses)
    assert run.succeeded, run.error
    check = next(c for c in run.executed_commands if "sqlite3 is required" in c)
    wrapped = check.replace(
        "command -v sqlite3 >/dev/null || { echo 'sqlite3 is required on the target to verify "
        "the restored database' >&2; exit 1; }",
        command,
    )
    assert wrapped != check

    result = subprocess.run(["sh", "-c", wrapped], capture_output=True, text=True)

    assert result.returncode == code
    assert staging.exists() is (code == 0)


def traefik_backup(cfg: TraefikBackupConfig, responses: dict[str, Any] | None = None) -> FakeRun:
    base = {"date +%Y%m%dT%H%M%S": [STAMP], "stat -c %a ": ["700"]}
    base[_dynamic_tree_check(cfg.dynamic_dir) + " && echo yes"] = ["yes"]
    base[_resolved_paths(cfg.root, cfg.dynamic_dir)] = [_canonical(cfg.root), _canonical(cfg.dynamic_dir)]
    return run_deploy_fake(deploy_traefik_backup, cfg, responses={**base, **(responses or {})})


def test_traefik_backup_checks_the_mount_first_and_prunes_last() -> None:
    cfg = TraefikBackupConfig(required_mount=MOUNT, retain_count=3, fetch_local=False)
    run = traefik_backup(cfg)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "require_mount /opt/backups /opt/backups/traefik" in commands[0]
    assert f"require_new_snapshot /opt/backups/traefik manual-{STAMP}" in commands[0]
    assert f"prune_snapshots /opt/backups/traefik 3 '' manual-{STAMP}" in commands[-1]


def test_traefik_backup_without_an_archive_still_prunes() -> None:
    run = traefik_backup(TraefikBackupConfig(retain_days=7, create_archive=False))

    assert run.succeeded, run.error
    assert not any("tar -czf" in c for c in run.executed_commands)
    assert "prune_snapshots /opt/backups/traefik 0 20261015T120000" in run.executed_commands[-1]


def test_a_failed_mount_check_stops_the_traefik_restore() -> None:
    staging = "/opt/backups/traefik/.restore-work"
    cfg = TraefikRestoreConfig(required_mount=MOUNT, staging_dir=staging)
    check = f"require_mount /opt/backups {staging}"
    responses = {
        "find /opt/backups/traefik -maxdepth 1": ["1.0 /opt/backups/traefik/manual-1.tar.gz"],
        check: {"success": False},
    }
    run = run_deploy_fake(deploy_traefik_restore, cfg, responses=responses)

    assert not run.succeeded
    (command,) = run.executed_commands
    assert check in command


@pytest.mark.parametrize("payload", [True, False])
def test_traefik_restore_removes_the_staging_directory_on_success_and_failure(tmp_path: Path, payload: bool) -> None:
    content = tmp_path / "content"
    (content / f"manual-{STAMP}").mkdir(parents=True)
    archive = tmp_path / f"manual-{STAMP}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        if payload:
            tar.add(content / f"manual-{STAMP}", arcname=f"manual-{STAMP}")
        else:
            (content / "loose").write_text("x\n")
            tar.add(content / "loose", arcname="loose")
    staging = tmp_path / "staging"
    cfg = TraefikRestoreConfig(archive=str(archive), staging_dir=str(staging))
    run = run_deploy_fake(deploy_traefik_restore, cfg, responses={f"test -e {archive}": ["yes"]})
    assert run.succeeded, run.error
    (command,) = run.executed_commands

    result = subprocess.run(["sh", "-c", command], capture_output=True, text=True)

    assert (result.returncode == 0) is payload, result.stderr
    assert not staging.exists()


@needs_gnu
def test_nyxmon_restore_removes_nothing_when_the_mount_check_fails(tmp_path: Path) -> None:
    mount = tmp_path / "disk"
    mount.mkdir()
    base = mount / "work"
    (base / STAMP).mkdir(parents=True)
    (base / STAMP / "keep").write_text("x\n")
    cfg = NyxmonRestoreConfig(host_name="m", required_mount=str(mount), staging_dir=str(base))
    run = run_deploy_fake(deploy_nyxmon_restore, cfg, responses={"date +%Y%m%dT%H%M%S": [STAMP]})
    (command,) = run.executed_commands

    result = run_bash(command, shell_env(tmp_path, mounted=False))

    assert result.returncode == 1
    assert "is not mounted" in result.stderr
    assert (base / STAMP / "keep").exists()


def test_nyxmon_passes_the_mount_and_prunes_after_the_archive() -> None:
    cfg = NyxmonBackupConfig(host_name="host", required_mount=MOUNT, retain_count=3, fetch_local=False)
    responses = {
        "date +%Y%m%dT%H%M%S": [STAMP],
        **{f"test -e {path} &&": ["yes"] for path in ("/home/nyxmon/site", "/home/nyxmon/site/.env")},
        "test -e /home/nyxmon/site/db.sqlite3 &&": ["yes"],
        "test -e /home/nyxmon/site/staticfiles &&": ["yes"],
        "test -e /home/nyxmon/logs &&": ["yes"],
    }
    run = run_deploy_fake(deploy_nyxmon_backup, cfg, responses=responses)

    assert run.succeeded, run.error
    copy = next(c for c in run.executed_commands if "STOP_ORDER=" in c)
    assert "REQUIRED_MOUNT=/opt/backups\n" in copy
    assert 'if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$ROOT"; fi' in copy
    assert f"prune_snapshots /opt/backups/nyxmon 3 '' manual-{STAMP}" in run.executed_commands[-1]


def test_nyxmon_restore_passes_the_mount() -> None:
    cfg = NyxmonRestoreConfig(host_name="m", required_mount=MOUNT, staging_dir="/opt/backups/nyxmon/.restore-work")
    run = run_deploy_fake(deploy_nyxmon_restore, cfg, responses={"date +%Y%m%dT%H%M%S": [STAMP]})

    assert run.succeeded, run.error
    (command,) = run.executed_commands
    assert "REQUIRED_MOUNT=/opt/backups\n" in command
    assert "STAGING_BASE=/opt/backups/nyxmon/.restore-work\n" in command
    assert 'require_mount "$REQUIRED_MOUNT" "$STAGING_BASE"' in command


def fastdeploy_values(command: str) -> dict[str, str]:
    body = shlex.split(command)[2]
    values = {}
    for line in body.splitlines():
        name, sep, value = line.partition("=")
        if sep and name.isidentifier() and name.isupper() and not value.startswith("("):
            try:
                values[name] = (shlex.split(value) or [""])[0]
            except ValueError:
                continue
    return values


def test_fastdeploy_backup_records_and_prunes() -> None:
    cfg = FastdeployBackupConfig(host_name="m", required_mount=MOUNT, retain_count=3, retain_days=14, fetch_local=False)
    run = run_deploy_fake(deploy_fastdeploy_backup, cfg, responses={"date +%Y%m%dT%H%M%S": [STAMP]})

    assert run.succeeded, run.error
    values = fastdeploy_values(run.executed_commands[0])
    assert values["B_MOUNT"] == MOUNT
    assert (values["B_RECORD"], values["B_PRUNE"], values["B_KEEP"], values["B_CUTOFF"]) == (
        "1",
        "1",
        "3",
        "20261008T120000",
    )


def test_fastdeploy_restore_guards_its_work_and_never_prunes() -> None:
    cfg = FastdeployRestoreConfig(
        host_name="m",
        required_mount=MOUNT,
        temp_dir="/opt/backups/fastdeploy/.restore-work",
        safety_backup_retention=True,
    )
    run = run_deploy_fake(deploy_fastdeploy_restore, cfg, responses={"date +%Y%m%dT%H%M%S": [STAMP]})

    assert run.succeeded, run.error
    values = fastdeploy_values(run.executed_commands[0])
    assert values["R_MOUNT"] == MOUNT
    assert values["R_TEMP"] == "/opt/backups/fastdeploy/.restore-work"
    # The safety backup: guarded, into the backup root, recorded for later backups, never pruned here.
    assert (values["B_MOUNT"], values["B_ROOT"]) == (MOUNT, "/opt/backups/fastdeploy")
    assert (values["B_RECORD"], values["B_PRUNE"]) == ("1", "0")
    plain = run_deploy_fake(
        deploy_fastdeploy_restore,
        FastdeployRestoreConfig(host_name="m"),
        responses={"date +%Y%m%dT%H%M%S": [STAMP]},
    )
    defaults = fastdeploy_values(plain.executed_commands[0])
    assert (defaults["R_MOUNT"], defaults["B_MOUNT"], defaults["B_RECORD"], defaults["B_PRUNE"]) == ("", "", "0", "0")
