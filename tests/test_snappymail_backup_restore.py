"""SnappyMail backup and restore: planned operations and the host scripts end to end.

The restore runs ops-library's ``preserve.py`` for real (it needs ``findmnt``,
as on the Linux targets).
"""

from __future__ import annotations

import os
import shutil
import tarfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.snappymail import (
    SnappyMailBackupConfig,
    SnappyMailRestoreConfig,
    deploy_snappymail_backup,
    deploy_snappymail_restore,
)
from ops_deploy.services.snappymail.backup_restore import FILES, backup_manifest
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.lifecycle_scripts import assignments, calls, needs_gnu, run_script

STAMP = "20261104T120000"
needs_findmnt = pytest.mark.skipif(shutil.which("findmnt") is None, reason="preserve.py needs findmnt")


def backup(cfg: SnappyMailBackupConfig, stamp: str = STAMP) -> FakeRun:
    return run_deploy_fake(deploy_snappymail_backup, cfg, responses={"date +%Y%m%dT%H%M%S": [stamp]})


def restore(cfg: SnappyMailRestoreConfig) -> FakeRun:
    return run_deploy_fake(deploy_snappymail_restore, cfg)


# -- planned operations ---------------------------------------------------------


def test_backup_plans_the_role_steps(tmp_path: Path) -> None:
    cfg = SnappyMailBackupConfig(host_name="macmini", fetch_dir=tmp_path / "local")

    result = backup(cfg)

    assert result.succeeded, result.error
    values = assignments(result.executed_commands[0])
    archive = f"/mnt/cryptdata/backups/snappymail/manual-{STAMP}.tar.gz"
    assert values["ARCHIVE"] == archive
    assert values["PARENT"] == "/mnt/cryptdata"
    assert values["BASENAME"] == "snappymail"
    assert values["ZSTD"] == "0"
    assert values["STOP"] == "0"
    assert f'archive: "{archive}"' in result.executed_commands[0]
    assert "SnappyMail backup | Fetch the backup archive" in result.changed_ops
    assert (tmp_path / "local").stat().st_mode & 0o777 == 0o700


def test_backup_manifest_matches_the_role_template() -> None:
    cfg = SnappyMailBackupConfig(host_name="macmini", archive_format="tar.zst")

    text = backup_manifest(cfg, stamp=STAMP, archive="/r/a.tar.zst")

    assert text == (
        f'timestamp: "{STAMP}"\nhost: "macmini"\ndata_dir: "/mnt/cryptdata/snappymail"\n'
        'archive: "/r/a.tar.zst"\nformat: "tar.zst"\nversion: 1\n'
    )


def test_backup_root_must_lie_outside_the_data_directory() -> None:
    with pytest.raises(ValidationError):
        SnappyMailBackupConfig(host_name="m", root="/mnt/cryptdata/snappymail/backups")
    with pytest.raises(ValidationError):
        SnappyMailBackupConfig(host_name="m", required_mount="/opt/backups")


def test_restore_runs_one_labelled_script() -> None:
    cfg = SnappyMailRestoreConfig(host_name="macmini", archive="manual-1.tar.zst", required_mount="/mnt/cryptdata")

    result = restore(cfg)

    assert result.succeeded, result.error
    command = next(c for c in result.executed_commands if c.startswith("set -euo pipefail"))
    values = assignments(command)
    assert values["ARCHIVE"] == "manual-1.tar.zst"
    assert values["REQUIRED_MOUNT"] == "/mnt/cryptdata"
    assert values["PARENT"] == "/mnt/cryptdata"
    assert result.changed_ops[-1] == "SnappyMail restore | Restore SnappyMail"
    dry = restore(cfg.model_copy(update={"dry_run": True}))
    assert dry.changed_ops == ["SnappyMail restore | Restore SnappyMail (dry run)"]


@pytest.mark.parametrize("archive", ["../x.tar.gz", "/mnt/cryptdata/backups/snappymail/a.tar.gz", "dir", "a.zip"])
def test_restore_archive_must_be_a_name_below_the_root(archive: str) -> None:
    with pytest.raises(ValidationError):
        SnappyMailRestoreConfig(host_name="m", archive=archive)


@pytest.mark.parametrize("path", ["/tmp/x/", "/tmp/./x", "/tmp//x", "/tmp/../etc", "/"])
def test_restore_paths_must_be_canonical(path: str) -> None:
    with pytest.raises(ValidationError):
        SnappyMailRestoreConfig(host_name="m", data_dir=path)


# -- the host scripts -----------------------------------------------------------

UNITS = r"""
systemctl() {
    printf 'systemctl %s\n' "$*" >>"$LOG"
    case $1 in
        is-active)
            if [[ " ${ACTIVE_UNITS:-} " == *" ${*: -1} "* ]]; then echo active; else echo inactive; return 3; fi
            ;;
        stop) [ -z "${SYSTEMCTL_STOP_FAILS:-}" ] ;;
        *) return 0 ;;
    esac
}
"""


def tree(tmp_path: Path) -> dict[str, Path]:
    p = {name: tmp_path / name for name in ("crypt", "php")}
    data = p["crypt"] / "snappymail"
    (data / "_data_" / "_default_" / "configs").mkdir(parents=True)
    (data / "_data_" / "_default_" / "configs" / "application.ini").write_text("original\n")
    (data / "logs").mkdir()
    (p["php"] / "8.3" / "fpm" / "pool.d").mkdir(parents=True)
    (p["php"] / "8.3" / "fpm" / "pool.d" / "snappymail.conf").write_text("[snappymail]\n")
    p["data"] = data
    p["root"] = p["crypt"] / "backups" / "snappymail"
    return p


def stubs(p: dict[str, Path], extra: str = "") -> str:
    return UNITS + f"PHP_ETC={p['php']}\n" + extra


def take_backup(p: dict[str, Path], tmp_path: Path, stamp: str = STAMP, **extra: Any) -> FakeRun:
    cfg = SnappyMailBackupConfig(
        host_name="macmini", data_dir=str(p["data"]), root=str(p["root"]), fetch_local=False, **extra
    )
    result = backup(cfg, stamp)
    assert result.succeeded, result.error
    done = run_script(
        result.executed_commands[0], FILES / "backup.sh", tmp_path, stubs=stubs(p), ACTIVE_UNITS="nginx php8.3-fpm"
    )
    assert done.returncode == 0, done.stderr
    return result


def restore_command(p: dict[str, Path], **extra: Any) -> str:
    cfg = SnappyMailRestoreConfig(host_name="macmini", data_dir=str(p["data"]), root=str(p["root"]), **extra)
    result = restore(cfg)
    assert result.succeeded, result.error
    return next(c for c in result.executed_commands if c.startswith("set -euo pipefail"))


def run_restore(p: dict[str, Path], tmp_path: Path, extra: str = "", **settings: Any) -> Any:
    env = {"ACTIVE_UNITS": "nginx php8.3-fpm"}
    return run_script(restore_command(p, **settings), FILES / "restore.sh", tmp_path, stubs=stubs(p, extra), **env)


def copies(p: dict[str, Path]) -> list[Path]:
    return sorted(p["crypt"].glob("snappymail.pre-restore-*"))


@needs_gnu
def test_backup_script_writes_the_role_archive_and_manifest(tmp_path: Path) -> None:
    p = tree(tmp_path)
    p["root"].mkdir(parents=True)
    (p["root"] / "old.tar.gz").write_text("x")
    os.chmod(p["root"] / "old.tar.gz", 0o644)

    take_backup(p, tmp_path)

    archive = p["root"] / f"manual-{STAMP}.tar.gz"
    assert archive.stat().st_mode & 0o777 == 0o600
    assert (p["root"] / "old.tar.gz").stat().st_mode & 0o777 == 0o600
    with tarfile.open(archive) as tar:
        assert {name.split("/")[0] for name in tar.getnames()} == {"snappymail"}
    manifest = (p["root"] / f"manual-{STAMP}.tar.gz.yml").read_text()
    assert manifest.startswith(f'timestamp: "{STAMP}"\n')
    assert (p["root"] / f"manual-{STAMP}.tar.gz.yml").stat().st_mode & 0o777 == 0o600
    # Services keep running by default.
    assert calls(tmp_path) == []


@needs_gnu
def test_backup_script_stops_and_restarts_the_units_in_reverse_order(tmp_path: Path) -> None:
    p = tree(tmp_path)

    take_backup(p, tmp_path, stop_services=True)

    assert [line for line in calls(tmp_path) if not line.startswith("systemctl is-active")] == [
        "systemctl stop nginx",
        "systemctl stop php8.3-fpm",
        "systemctl start php8.3-fpm",
        "systemctl start nginx",
    ]


@needs_gnu
def test_backup_script_retention_keeps_the_newest_archives_and_their_manifests(tmp_path: Path) -> None:
    p = tree(tmp_path)
    for index, stamp in enumerate(("20261101T000000", "20261102T000000", "20261103T000000")):
        take_backup(p, tmp_path, stamp=stamp, retain=2)
        archive = p["root"] / f"manual-{stamp}.tar.gz"
        os.utime(archive, (1_000_000_000 + index, 1_000_000_000 + index))

    take_backup(p, tmp_path, retain=2)

    assert sorted(path.name for path in p["root"].iterdir()) == [
        "manual-20261103T000000.tar.gz",
        "manual-20261103T000000.tar.gz.yml",
        f"manual-{STAMP}.tar.gz",
        f"manual-{STAMP}.tar.gz.yml",
    ]


@needs_gnu
@needs_findmnt
def test_restore_script_keeps_the_live_data_and_restores_the_archive(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    ini = p["data"] / "_data_" / "_default_" / "configs" / "application.ini"
    ini.write_text("changed\n")
    (p["data"] / "new.txt").write_text("new\n")
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_restore(p, tmp_path)

    assert done.returncode == 0, done.stderr + done.stdout
    assert ini.read_text() == "original\n"
    assert not (p["data"] / "new.txt").exists()
    assert ini.stat().st_mode & 0o777 == 0o750
    (copy,) = copies(p)
    assert (copy / "new.txt").exists()
    assert "Pre-restore copy:" in done.stdout
    assert not list(p["crypt"].glob(".snappymail-restore-*"))
    log = [line for line in calls(tmp_path) if line.startswith("systemctl") and "is-active" not in line]
    assert log == [
        "systemctl stop nginx",
        "systemctl stop php8.3-fpm",
        "systemctl enable nginx",
        "systemctl restart nginx",
        "systemctl enable php8.3-fpm",
        "systemctl restart php8.3-fpm",
    ]


@needs_gnu
@needs_findmnt
def test_restore_script_dry_run_validates_and_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["data"] / "new.txt").write_text("new\n")
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_restore(p, tmp_path, dry_run=True)

    assert done.returncode == 0, done.stderr
    assert "nothing changed" in done.stdout
    assert (p["data"] / "new.txt").exists()
    assert copies(p) == []
    assert not list(p["crypt"].glob(".snappymail-restore-*"))
    assert [line for line in calls(tmp_path) if not line.startswith("systemctl is-active")] == []


@needs_gnu
@needs_findmnt
def test_restore_script_refuses_an_archive_without_the_data_directory(tmp_path: Path) -> None:
    p = tree(tmp_path)
    p["root"].mkdir(parents=True)
    other = tmp_path / "other"
    other.mkdir()
    with tarfile.open(p["root"] / "manual-x.tar.gz", "w:gz") as tar:
        tar.add(other, arcname="other")

    done = run_restore(p, tmp_path)

    assert done.returncode == 1
    assert "has no snappymail directory" in done.stderr
    assert copies(p) == []
    assert not list(p["crypt"].glob(".snappymail-restore-*"))
    assert [line for line in calls(tmp_path) if line.startswith("systemctl stop")] == []


@needs_gnu
@needs_findmnt
def test_restore_script_refuses_to_stop_nginx_without_the_php_pool(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    shutil.rmtree(p["php"])
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_restore(p, tmp_path)

    assert done.returncode == 1
    assert "PHP-FPM pool not found" in done.stderr
    assert [line for line in calls(tmp_path) if not line.startswith("systemctl is-active")] == []


@needs_gnu
@needs_findmnt
def test_restore_script_restarts_the_stopped_units_when_preservation_fails_before_a_copy(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (tmp_path / "calls.log").unlink(missing_ok=True)
    failing = (
        'fake() { if [ "${2:-}" = --preflight ] || [ "$1" = --validate-layout ]; then return 0; fi; return 1; }\n'
        "PRESERVE=(fake)\n"
    )

    done = run_restore(p, tmp_path, failing)

    assert done.returncode == 1
    log = [line for line in calls(tmp_path) if not line.startswith("systemctl is-active")]
    assert log == [
        "systemctl stop nginx",
        "systemctl stop php8.3-fpm",
        "systemctl start nginx",
        "systemctl start php8.3-fpm",
    ]


@needs_gnu
@needs_findmnt
def test_restore_script_leaves_the_units_stopped_after_the_live_data_was_touched(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_restore(p, tmp_path, "rsync() { return 1; }\n")

    assert done.returncode == 1
    assert "inspect the retained copy" in done.stderr
    assert len(copies(p)) == 1
    assert not list(p["crypt"].glob(".snappymail-restore-*"))
    log = [line for line in calls(tmp_path) if not line.startswith("systemctl is-active")]
    assert log == ["systemctl stop nginx", "systemctl stop php8.3-fpm"]


@needs_gnu
@needs_findmnt
def test_restore_script_latest_without_archives_names_the_root(tmp_path: Path) -> None:
    p = tree(tmp_path)

    done = run_restore(p, tmp_path)

    assert done.returncode == 1
    assert f"No SnappyMail backups found under {p['root']}" in done.stderr


@needs_gnu
def test_backup_script_starts_the_stopped_units_when_the_archive_fails(tmp_path: Path) -> None:
    p = tree(tmp_path)
    cfg = SnappyMailBackupConfig(
        host_name="m", data_dir=str(p["data"]), root=str(p["root"]), fetch_local=False, stop_services=True
    )
    result = backup(cfg)
    assert result.succeeded, result.error

    done = run_script(
        result.executed_commands[0],
        FILES / "backup.sh",
        tmp_path,
        stubs=stubs(p, "tar() { return 1; }\n"),
        ACTIVE_UNITS="nginx php8.3-fpm",
    )

    assert done.returncode != 0
    assert [line for line in calls(tmp_path) if "is-active" not in line] == [
        "systemctl stop nginx",
        "systemctl stop php8.3-fpm",
        "systemctl start php8.3-fpm",
        "systemctl start nginx",
    ]


@needs_gnu
@needs_findmnt
def test_restore_script_round_trips_a_zstd_archive_and_latest_picks_the_newest(tmp_path: Path) -> None:
    if shutil.which("zstd") is None:
        pytest.skip("needs zstd")
    p = tree(tmp_path)
    take_backup(p, tmp_path, stamp="20261101T000000")
    os.utime(p["root"] / "manual-20261101T000000.tar.gz", (1_000_000_000, 1_000_000_000))
    ini = p["data"] / "_data_" / "_default_" / "configs" / "application.ini"
    ini.write_text("zstd\n")
    take_backup(p, tmp_path, archive_format="tar.zst")
    ini.write_text("changed\n")

    done = run_restore(p, tmp_path)

    assert done.returncode == 0, done.stderr
    assert f"manual-{STAMP}.tar.zst" in done.stdout
    assert ini.read_text() == "zstd\n"


@needs_gnu
@needs_findmnt
def test_restore_script_without_clean_keeps_the_live_files_too(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["data"] / "new.txt").write_text("new\n")

    done = run_restore(p, tmp_path, clean=False)

    assert done.returncode == 0, done.stderr
    assert (p["data"] / "new.txt").exists()
    (copy,) = copies(p)
    assert (copy / "new.txt").exists()
    assert '"method": "copy"' in done.stdout


@needs_gnu
@needs_findmnt
def test_restore_script_a_failed_stop_starts_the_units_stopped_so_far(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (tmp_path / "calls.log").unlink(missing_ok=True)
    second_fails = (
        'systemctl() { printf "systemctl %s\\n" "$*" >>"$LOG"; case "$1 $2" in "stop php8.3-fpm") return 1 ;; '
        '"is-active "*) echo active ;; esac; }\n'
    )

    done = run_restore(p, tmp_path, second_fails)

    assert done.returncode == 1
    log = [line for line in calls(tmp_path) if "is-active" not in line]
    assert log == [
        "systemctl stop nginx",
        "systemctl stop php8.3-fpm",
        "systemctl start nginx",
    ]
    assert copies(p) == []


@needs_gnu
@needs_findmnt
def test_restore_script_a_reported_copy_then_failure_leaves_the_units_stopped(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (tmp_path / "calls.log").unlink(missing_ok=True)
    reported = (
        'fake() { case "${2:-}${1:-}" in --preflight*|*--validate-layout*) return 0 ;; esac; '
        "echo 'RESTORE_PRESERVED {\"path\": null}'; return 1; }\n"
        "PRESERVE=(fake)\n"
    )

    done = run_restore(p, tmp_path, reported)

    assert done.returncode == 1
    log = [line for line in calls(tmp_path) if "is-active" not in line]
    assert log == ["systemctl stop nginx", "systemctl stop php8.3-fpm"]


@needs_gnu
def test_backup_script_leaves_stopped_units_stopped(tmp_path: Path) -> None:
    p = tree(tmp_path)
    cfg = SnappyMailBackupConfig(
        host_name="m", data_dir=str(p["data"]), root=str(p["root"]), fetch_local=False, stop_services=True
    )
    result = backup(cfg)

    done = run_script(result.executed_commands[0], FILES / "backup.sh", tmp_path, stubs=stubs(p), ACTIVE_UNITS="nginx")

    assert done.returncode == 0, done.stderr
    assert [line for line in calls(tmp_path) if "is-active" not in line] == [
        "systemctl stop nginx",
        "systemctl start nginx",
    ]


@needs_gnu
def test_backup_script_stops_a_starting_unit_too(tmp_path: Path) -> None:
    p = tree(tmp_path)
    cfg = SnappyMailBackupConfig(
        host_name="m", data_dir=str(p["data"]), root=str(p["root"]), fetch_local=False, stop_services=True
    )
    result = backup(cfg)
    starting = 'systemctl() { printf "systemctl %s\\n" "$*" >>"$LOG"; [ "$1" != is-active ] || echo activating; }\n'

    done = run_script(result.executed_commands[0], FILES / "backup.sh", tmp_path, stubs=stubs(p, starting))

    assert done.returncode == 0, done.stderr
    assert "systemctl stop php8.3-fpm" in calls(tmp_path)


def test_restore_installs_rsync_only_for_a_real_restore() -> None:
    cfg = SnappyMailRestoreConfig(host_name="m")

    assert "SnappyMail restore | Ensure rsync" in [op.name for op in restore(cfg).ops]
    assert "SnappyMail restore | Ensure rsync" not in [
        op.name for op in restore(cfg.model_copy(update={"dry_run": True})).ops
    ]
