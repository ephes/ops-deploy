"""homelab backup and restore: planned operations and the host scripts end to end."""

from __future__ import annotations

import os
import sqlite3
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.services.homelab import (
    HomelabBackupConfig,
    HomelabRestoreConfig,
    deploy_homelab_backup,
    deploy_homelab_restore,
)
from ops_deploy.services.homelab.backup_restore import FILES, backup_metadata
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.lifecycle_scripts import assignments, calls, needs_gnu, repack, run_script

STAMP = "20261104T120000"
LATER = "20261104T130000"
SITE = "/home/homelab/site"


def backup(cfg: HomelabBackupConfig, *, site: bool = True, git: str | None = None) -> FakeRun:
    responses: dict[str, Any] = {"date +%Y%m%dT%H%M%S": [STAMP]}
    if site:
        responses[f"test -e {cfg.site_path} &&"] = ["yes"]
    if git is not None:
        responses[f"test -e {cfg.site_path}/.git &&"] = ["yes"]
        responses["rev-parse --verify --quiet HEAD"] = [git]
    return run_deploy_fake(deploy_homelab_backup, cfg, responses=responses)


def restore(cfg: HomelabRestoreConfig) -> FakeRun:
    return run_deploy_fake(deploy_homelab_restore, cfg, responses={"date +%Y%m%dT%H%M%S": [LATER]})


# -- planned operations ---------------------------------------------------------


def test_backup_plans_the_role_steps(tmp_path: Path) -> None:
    cfg = HomelabBackupConfig(host_name="macmini", local_dir=tmp_path / "local", ops_library_version="2.60.0")

    result = backup(cfg, git="abc123")

    assert result.succeeded, result.error
    script = result.executed_commands[0]
    values = assignments(script)
    assert values["DIR"] == f"/opt/backups/homelab/manual-{STAMP}"
    assert values["DB"] == f"{SITE}/db.sqlite3"
    assert values["SQLITE_ATTEMPTS"] == "4"
    assert values["DIRS"] == (f"(1:{SITE}/staticfiles:static 1:{SITE}/media:media 0:{SITE}/cache:cache)")
    assert values["COPIES"] == (
        f"(1:{SITE}/.env:env/.env 1:/etc/systemd/system/homelab.service:configs/homelab.service "
        "1:/etc/traefik/dynamic/homelab.yml:configs/traefik.yml)"
    )
    assert 'source_commit: "abc123"' in script
    assert "homelab backup | Fetch the backup archive" in result.changed_ops
    assert (tmp_path / "local").stat().st_mode & 0o777 == 0o700


def test_backup_refuses_a_host_without_the_site() -> None:
    result = backup(HomelabBackupConfig(host_name="macmini"), site=False)

    assert "must exist on the target host" in str(result.error)
    assert result.executed_commands == []


def test_backup_retention_records_and_prunes() -> None:
    cfg = HomelabBackupConfig(
        host_name="macmini", required_mount="/opt/backups", retain_count=3, retain_days=14, fetch_local=False
    )

    result = backup(cfg)

    assert result.succeeded, result.error
    values = assignments(result.executed_commands[0])
    assert values["REQUIRED_MOUNT"] == "/opt/backups"
    assert values["RECORD"] == "1"
    assert any("prune_snapshots /opt/backups/homelab 3" in c for c in result.executed_commands)


def test_backup_metadata_matches_the_role_template() -> None:
    cfg = HomelabBackupConfig(host_name="macmini", ops_library_version="2.60.0")

    text = backup_metadata(cfg, stamp=STAMP, commit="unknown", sqlite_mode="hot")

    assert text.startswith(f'slug: "homelab"\ntimestamp: "{STAMP}"\nhost: "macmini"\n')
    assert "include_cache: False\ninclude_env: True\n" in text
    assert yaml.safe_load(text) == {
        "slug": "homelab",
        "timestamp": STAMP,
        "host": "macmini",
        "ops_library_version": "2.60.0",
        "source_commit": "unknown",
        "sqlite_mode": "hot",
        "include_static": True,
        "include_media": True,
        "include_cache": False,
        "include_env": True,
        "include_systemd": True,
        "include_traefik": True,
        "site_path": SITE,
        "database_path": f"{SITE}/db.sqlite3",
        "static_root": f"{SITE}/staticfiles",
        "media_root": f"{SITE}/media",
        "cache_dir": f"{SITE}/cache",
        "env_file": f"{SITE}/.env",
    }


def test_restore_runs_one_labelled_script() -> None:
    cfg = HomelabRestoreConfig(host_name="macmini", archive="manual-1.tar.gz")

    result = restore(cfg)

    assert result.succeeded, result.error
    (command,) = result.executed_commands
    values = assignments(command)
    assert values["ARCHIVE"] == "manual-1.tar.gz"
    assert values["REQUIRED_FIELDS"] == "(slug timestamp host)"
    assert values["HEALTH_URL"] == "http://127.0.0.1:10010/admin/"
    assert values["SAFETY_DELETE"] == "0"
    assert result.changed_ops == ["homelab restore | Restore homelab"]
    dry = restore(cfg.model_copy(update={"dry_run": True}))
    assert dry.changed_ops == ["homelab restore | Restore homelab (dry run)"]


@pytest.mark.parametrize("archive", ["../x.tar.gz", "/opt/backups/homelab/a.tar.gz", "a b.tar.gz", "x"])
def test_restore_archive_must_be_a_name_below_the_root(archive: str) -> None:
    with pytest.raises(ValidationError):
        HomelabRestoreConfig(host_name="m", archive=archive)


@pytest.mark.parametrize("path", ["/tmp/x/", "/tmp/./x", "/tmp//x", "/tmp/../etc", "/", "//tmp/x"])
@pytest.mark.parametrize("field", ["staging_dir", "site_path", "media_root"])
def test_restore_paths_must_be_canonical(field: str, path: str) -> None:
    with pytest.raises(ValidationError):
        HomelabRestoreConfig.model_validate({"host_name": "m", field: path})


def test_restore_staging_must_lie_below_the_required_mount() -> None:
    with pytest.raises(ValidationError):
        HomelabRestoreConfig(host_name="m", required_mount="/opt/backups")
    ok = HomelabRestoreConfig(host_name="m", required_mount="/opt/backups", staging_dir="/opt/backups/homelab/.w")
    assert ok.staging_dir == "/opt/backups/homelab/.w"


# -- the host scripts -----------------------------------------------------------


def make_site(site: Path, marker: str) -> None:
    for sub in ("staticfiles", "media/services/logos", "cache"):
        (site / sub).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(site / "db.sqlite3")
    conn.executescript(f"CREATE TABLE IF NOT EXISTS t(v TEXT); DELETE FROM t; INSERT INTO t VALUES ('{marker}');")
    conn.commit()
    conn.close()
    (site / ".env").write_text(f"MARKER={marker}\n")
    (site / "staticfiles" / "app.css").write_text(f"/* {marker} */\n")
    (site / "media" / "services" / "logos" / "logo.png").write_text(f"{marker}\n")


def tree(tmp_path: Path) -> dict[str, Path]:
    paths = {name: tmp_path / name for name in ("site", "etc", "backups", "staging")}
    make_site(paths["site"], "original")
    paths["etc"].mkdir()
    (paths["etc"] / "homelab.service").write_text("[Service]\n")
    (paths["etc"] / "homelab.yml").write_text("http: {}\n")
    return paths


def site_settings(p: dict[str, Path]) -> dict[str, Any]:
    return {
        "site_path": str(p["site"]),
        "systemd_unit_path": str(p["etc"] / "homelab.service"),
        "traefik_config_path": str(p["etc"] / "homelab.yml"),
    }


def take_backup(p: dict[str, Path], tmp_path: Path, *, stubs: str = "", stamp: str = STAMP, **extra: Any) -> Path:
    cfg = HomelabBackupConfig(
        host_name="macmini",
        root=str(p["backups"]),
        fetch_local=False,
        ops_library_version="2.60.0",
        **site_settings(p),
        **extra,
    )
    result = run_deploy_fake(
        deploy_homelab_backup,
        cfg,
        responses={"date +%Y%m%dT%H%M%S": [stamp], f"test -e {cfg.site_path} &&": ["yes"]},
    )
    assert result.succeeded, result.error
    done = run_script(result.executed_commands[0], FILES / "backup.sh", tmp_path, stubs=stubs)
    assert done.returncode == 0, done.stderr
    return p["backups"] / f"manual-{stamp}"


def restore_command(p: dict[str, Path], **extra: Any) -> str:
    settings = {"ops_library_version": "2.60.0", "healthcheck_delay": 0, **site_settings(p), **extra}
    cfg = HomelabRestoreConfig(
        host_name="macmini", search_root=str(p["backups"]), staging_dir=str(p["staging"]), **settings
    )
    result = restore(cfg)
    assert result.succeeded, result.error
    (command,) = result.executed_commands
    return command


@needs_gnu
def test_backup_script_writes_the_role_layout(tmp_path: Path) -> None:
    p = tree(tmp_path)

    directory = take_backup(p, tmp_path)

    copy = sqlite3.connect(directory / "database" / "db.sqlite3")
    assert copy.execute("SELECT v FROM t").fetchall() == [("original",)]
    copy.close()
    assert (directory / "env" / ".env").read_text() == "MARKER=original\n"
    assert (directory / "static" / "app.css").exists()
    assert (directory / "media" / "services" / "logos" / "logo.png").exists()
    assert list((directory / "cache").iterdir()) == []
    assert (directory / "configs" / "homelab.service").read_text() == "[Service]\n"
    assert (directory / "configs" / "traefik.yml").read_text() == "http: {}\n"
    metadata = yaml.safe_load((directory / "metadata.yml").read_text())
    assert metadata["sqlite_mode"] == "hot"
    assert not (directory / "metadata.yml.new").exists()
    manifest = (directory / "manifest.sha256").read_text()
    assert "./metadata.yml" in manifest
    assert "./manifest.sha256" not in manifest
    archive = p["backups"] / f"manual-{STAMP}.tar.gz"
    assert archive.stat().st_mode & 0o777 == 0o600
    with tarfile.open(archive) as tar:
        assert {name.split("/")[0] for name in tar.getnames()} == {f"manual-{STAMP}"}
    # A hot backup never stops homelab.
    assert calls(tmp_path) == []


@needs_gnu
def test_backup_script_offline_copy_starts_homelab_again(tmp_path: Path) -> None:
    p = tree(tmp_path)

    directory = take_backup(p, tmp_path, force_stop=True)

    assert yaml.safe_load((directory / "metadata.yml").read_text())["sqlite_mode"] == "offline"
    assert calls(tmp_path) == ["systemctl stop homelab", "systemctl start homelab"]


@needs_gnu
def test_restore_script_puts_the_backup_back_and_keeps_a_pre_restore_copy(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p["site"], "changed")
    os.utime(p["site"] / "db.sqlite3", (1_000_000_000, 1_000_000_000))
    (p["site"] / "media" / "new.png").write_text("x\n")
    (p["site"] / "db.sqlite3-wal").write_text("stale\n")
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_script(restore_command(p), FILES / "restore.sh", tmp_path)

    assert done.returncode == 0, done.stderr + done.stdout
    db = sqlite3.connect(p["site"] / "db.sqlite3")
    assert db.execute("SELECT v FROM t").fetchall() == [("original",)]
    db.close()
    assert not (p["site"] / "db.sqlite3-wal").exists()
    assert not (p["site"] / "media" / "new.png").exists()
    assert (p["site"] / ".env").read_text() == "MARKER=original\n"
    assert (p["site"] / "media").stat().st_mode & 0o777 == 0o755
    log = calls(tmp_path)
    assert log[0] == "systemctl stop homelab"
    assert any(
        line.startswith("runuser -u homelab -- env DJANGO_SETTINGS_MODULE=") and "check --deploy" in line
        for line in log
    )
    assert "systemctl restart homelab" in log
    assert any(line.startswith("curl ") for line in log)
    # Unchanged unit and route: no reloads.
    assert "systemctl daemon-reload" not in log
    assert not any(line.startswith("systemctl reload") for line in log)
    assert not p["staging"].exists()
    (snapshot,) = tmp_path.glob("site.pre-restore-*")
    assert (snapshot / ".env").read_text() == "MARKER=changed\n"
    assert "kept at" in done.stderr


@needs_gnu
def test_restore_script_dry_run_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p["site"], "changed")
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_script(restore_command(p, dry_run=True), FILES / "restore.sh", tmp_path)

    assert done.returncode == 0, done.stderr
    assert "Dry-run: True" in done.stdout
    assert (p["site"] / ".env").read_text() == "MARKER=changed\n"
    assert calls(tmp_path) == []
    assert not list(tmp_path.glob("site.pre-restore-*"))


@needs_gnu
@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda text: text.replace('slug: "homelab"', 'slug: "other"'), "does not match expected homelab slug"),
        (lambda text: text.replace('host: "macmini"\n', ""), "missing required field 'host'"),
        (lambda text: text.replace("2.60.0", "2.59.0"), "Archive was produced with ops-library 2.59.0"),
    ],
)
def test_restore_script_refuses_a_foreign_or_mismatched_archive(tmp_path: Path, edit: Any, message: str) -> None:
    p = tree(tmp_path)
    directory = take_backup(p, tmp_path)
    metadata = directory / "metadata.yml"
    metadata.write_text(edit(metadata.read_text()))
    repack(directory)
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_script(restore_command(p, validate_checksums=False), FILES / "restore.sh", tmp_path)

    assert done.returncode == 1
    assert message in done.stderr
    assert calls(tmp_path) == []
    assert not p["staging"].exists()


@needs_gnu
def test_restore_script_version_mismatch_can_be_allowed(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)

    command = restore_command(p, ops_library_version="2.61.0", allow_version_mismatch=True, dry_run=True)
    done = run_script(command, FILES / "restore.sh", tmp_path)

    assert done.returncode == 0, done.stderr
    assert "Version mismatch detected" in done.stderr


@needs_gnu
def test_restore_script_stops_on_a_bad_checksum_before_any_change(tmp_path: Path) -> None:
    p = tree(tmp_path)
    directory = take_backup(p, tmp_path)
    (directory / "env" / ".env").write_text("TAMPERED=1\n")
    repack(directory)
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_script(restore_command(p), FILES / "restore.sh", tmp_path)

    assert done.returncode != 0
    assert calls(tmp_path) == []
    assert (p["site"] / ".env").read_text() == "MARKER=original\n"


@needs_gnu
def test_restore_script_reports_a_failed_health_check_and_keeps_the_copy(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)

    done = run_script(
        restore_command(p, healthcheck_retries=1, safe_snapshot_delete=True),
        FILES / "restore.sh",
        tmp_path,
        CURL_CODE="502",
    )

    assert done.returncode == 1
    assert "answered 502" in done.stderr
    # Not a success: the pre-restore copy stays even with safe_snapshot_delete.
    assert len(list(tmp_path.glob("site.pre-restore-*"))) == 1


@needs_gnu
def test_restore_script_reloads_after_a_changed_unit_and_route_and_deletes_the_copy(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["etc"] / "homelab.service").write_text("[Service]\nchanged\n")
    (p["etc"] / "homelab.yml").write_text("changed: 1\n")

    done = run_script(restore_command(p, safe_snapshot_delete=True), FILES / "restore.sh", tmp_path)

    assert done.returncode == 0, done.stderr
    assert (p["etc"] / "homelab.service").read_text() == "[Service]\n"
    log = calls(tmp_path)
    assert "systemctl daemon-reload" in log
    assert "systemctl reload traefik" in log
    assert not list(tmp_path.glob("site.pre-restore-*"))


@needs_gnu
def test_backup_script_falls_back_to_the_offline_copy_when_every_hot_attempt_fails(tmp_path: Path) -> None:
    p = tree(tmp_path)
    failing = r"""
sqlite3() { case "$*" in *.backup*) printf 'sqlite3 backup\n' >>"$LOG"; return 1 ;; esac; command sqlite3 "$@"; }
sleep() { :; }
"""

    directory = take_backup(p, tmp_path, stubs=failing)

    assert yaml.safe_load((directory / "metadata.yml").read_text())["sqlite_mode"] == "offline"
    log = calls(tmp_path)
    assert log == ["sqlite3 backup"] * 4 + ["systemctl stop homelab", "systemctl start homelab"]
    copy = sqlite3.connect(directory / "database" / "db.sqlite3")
    assert copy.execute("SELECT v FROM t").fetchall() == [("original",)]
    copy.close()


@needs_gnu
def test_restore_script_latest_is_the_newest_archive(tmp_path: Path) -> None:
    p = tree(tmp_path)
    old = take_backup(p, tmp_path)
    os.utime(p["backups"] / f"{old.name}.tar.gz", (1_000_000_000, 1_000_000_000))
    make_site(p["site"], "newer")
    take_backup(p, tmp_path, stamp=LATER)

    done = run_script(restore_command(p, dry_run=True), FILES / "restore.sh", tmp_path)

    assert done.returncode == 0, done.stderr
    assert f"Archive: manual-{LATER}.tar.gz" in done.stdout


@needs_gnu
def test_restore_script_without_the_search_root_names_it(tmp_path: Path) -> None:
    p = tree(tmp_path)

    done = run_script(restore_command(p), FILES / "restore.sh", tmp_path)

    assert done.returncode == 1
    assert f"No homelab backup archives found under {p['backups']}" in done.stderr


@needs_gnu
def test_restore_script_a_held_route_lock_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["etc"] / "homelab.yml").write_text("changed: 1\n")
    make_site(p["site"], "changed")
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_script(restore_command(p), FILES / "restore.sh", tmp_path, stubs="ROUTE_GUARD=(false)\n")

    assert done.returncode == 1
    assert "holds its lock" in done.stderr
    assert calls(tmp_path) == []
    assert (p["site"] / ".env").read_text() == "MARKER=changed\n"
    assert not list(tmp_path.glob("site.pre-restore-*"))


@needs_gnu
def test_restore_script_a_route_lock_taken_later_restores_the_rest_and_fails(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["etc"] / "homelab.yml").write_text("changed: 1\n")
    make_site(p["site"], "changed")
    later = 'guard() { [ -e "$LOG.guard" ] && return 1; : >"$LOG.guard"; }\nROUTE_GUARD=(guard)\n'

    done = run_script(restore_command(p), FILES / "restore.sh", tmp_path, stubs=later)

    assert done.returncode == 1
    assert "was not restored" in done.stderr
    assert (p["etc"] / "homelab.yml").read_text() == "changed: 1\n"
    assert (p["site"] / ".env").read_text() == "MARKER=original\n"
    log = calls(tmp_path)
    assert "systemctl restart homelab" in log
    assert not any(line.startswith("systemctl reload") for line in log)
    assert len(list(tmp_path.glob("site.pre-restore-*"))) == 1


@needs_gnu
def test_restore_script_a_failed_stop_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p["site"], "changed")

    done = run_script(restore_command(p), FILES / "restore.sh", tmp_path, SYSTEMCTL_STOP_FAILS="1")

    assert done.returncode == 1
    assert (p["site"] / ".env").read_text() == "MARKER=changed\n"
    assert not list(tmp_path.glob("site.pre-restore-*"))


@needs_gnu
def test_backup_script_a_failed_offline_copy_still_starts_homelab(tmp_path: Path) -> None:
    p = tree(tmp_path)
    cfg = HomelabBackupConfig(
        host_name="macmini", root=str(p["backups"]), fetch_local=False, force_stop=True, **site_settings(p)
    )
    result = backup(cfg)
    assert result.succeeded, result.error

    done = run_script(result.executed_commands[0], FILES / "backup.sh", tmp_path, stubs="cp() { return 1; }\n")

    assert done.returncode != 0
    assert calls(tmp_path) == ["systemctl stop homelab", "systemctl start homelab"]
