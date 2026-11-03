"""Home Assistant backup and restore: planned operations and the host scripts end to end.

The script tests run ``backup.sh`` and ``restore.sh`` locally in a temporary
tree. ``systemctl``, ``curl`` and the account commands are recording stubs,
``ensure_dir``/``copy_file``/``chown_tree`` stand in for the root-only
helpers, and the Traefik route guard is ``true``. They need GNU find/sha256sum
and rsync, as on the Linux targets.
"""

from __future__ import annotations

import os
import shlex
import shutil
import sqlite3
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.services.homeassistant import (
    HomeAssistantBackupConfig,
    HomeAssistantRestoreConfig,
    deploy_homeassistant_backup,
    deploy_homeassistant_restore,
)
from ops_deploy.services.homeassistant.lifecycle import FILES, backup_metadata
from ops_deploy.testing import FakeRun, run_deploy_fake

STAMP = "20261103T120000"
LATER = "20261103T130000"
CONFIG = "/home/homeassistant/site/config"


def _gnu() -> bool:
    if shutil.which("rsync") is None or shutil.which("sqlite3") is None:
        return False
    probe = subprocess.run(["find", ".", "-maxdepth", "0", "-printf", "%p"], capture_output=True, text=True)
    return probe.returncode == 0 and probe.stdout == "."


needs_gnu = pytest.mark.skipif(not _gnu(), reason="needs GNU find, rsync and sqlite3, as on the Linux targets")


def assignments(command: str) -> dict[str, str]:
    values = {}
    for line in command.splitlines():
        name, sep, value = line.partition("=")
        if sep and name.isidentifier() and name.isupper():
            values[name] = value if value.startswith("(") else shlex.split(value)[0] if value else ""
    return values


def split(result: FakeRun) -> tuple[str, str, str]:
    """The backup script, the manifest command and the archive command."""

    commands = result.executed_commands
    script = next(c for c in commands if c.startswith("set -euo pipefail"))
    manifest = next(c for c in commands if "manifest.sha256" in c and "sha256sum" in c)
    archive = next(c for c in commands if "tar -C" in c)
    return script, manifest, archive


def backup(cfg: HomeAssistantBackupConfig, *missing: str, stamp: str = STAMP) -> FakeRun:
    responses: dict[str, Any] = {"date +%Y%m%dT%H%M%S": [stamp]}
    if cfg.config_path not in missing:
        responses[f"test -e {cfg.config_path} &&"] = ["yes"]
    return run_deploy_fake(deploy_homeassistant_backup, cfg, responses=responses)


def restore(cfg: HomeAssistantRestoreConfig, stamp: str = LATER) -> FakeRun:
    return run_deploy_fake(deploy_homeassistant_restore, cfg, responses={"date +%Y%m%dT%H%M%S": [stamp]})


# -- planned operations ---------------------------------------------------------


def test_backup_plans_the_role_steps(tmp_path: Path) -> None:
    cfg = HomeAssistantBackupConfig(host_name="macmini", local_dir=tmp_path / "local")

    result = backup(cfg)

    assert result.succeeded, result.error
    script, manifest, archive = split(result)
    values = assignments(script)
    assert values["DIR"] == f"/opt/backups/homeassistant/manual-{STAMP}"
    assert values["DB"] == f"{CONFIG}/home-assistant_v2.db"
    # Matter storage below the data directory and the /data chip factory are not extra.
    assert values["EXTRAS"] == "(thread:/var/lib/thread)"
    assert values["COPIES"] == (
        "(/etc/systemd/system/homeassistant.service:homeassistant.service "
        "/etc/traefik/dynamic/homeassistant.yml:homeassistant.traefik.yml)"
    )
    assert "sha256sum > manifest.sha256" in manifest
    assert f"-czf manual-{STAMP}.tar.gz manual-{STAMP})" in archive
    assert "Home Assistant backup | Fetch the backup archive" in result.changed_ops
    assert (tmp_path / "local").stat().st_mode & 0o777 == 0o700


def test_backup_refuses_a_host_without_the_config_directory() -> None:
    result = backup(HomeAssistantBackupConfig(host_name="macmini"), CONFIG)

    assert "config directory not found" in str(result.error)
    assert result.executed_commands == []


def test_backup_retention_records_and_prunes() -> None:
    cfg = HomeAssistantBackupConfig(
        host_name="macmini", required_mount="/opt/backups", retain_count=3, retain_days=14, fetch_local=False
    )

    result = backup(cfg)

    assert result.succeeded, result.error
    assert assignments(result.executed_commands[0])["REQUIRED_MOUNT"] == "/opt/backups"
    assert assignments(result.executed_commands[0])["RECORD"] == "1"
    assert any("prune_snapshots /opt/backups/homeassistant 3" in c for c in result.executed_commands)


def test_backup_extra_directories_follow_the_role_include_rules() -> None:
    cfg = HomeAssistantBackupConfig(
        host_name="m", matter_server_storage_path="/srv/matter", matter_server_chip_factory_dir="/srv/chip"
    )

    assert cfg.extra_dirs() == [
        ("thread", "/var/lib/thread"),
        ("matter-server", "/srv/matter"),
        ("matter-chip-factory", "/srv/chip"),
    ]
    inside = HomeAssistantBackupConfig(host_name="m", matter_server_chip_factory_dir=f"{cfg.data_path}/chip")
    assert inside.extra_dirs() == [("thread", "/var/lib/thread")]


def test_backup_metadata_is_valid_yaml_with_the_role_keys() -> None:
    cfg = HomeAssistantBackupConfig(host_name="macmini", ansible_user="root")

    text = backup_metadata(cfg, stamp=STAMP)

    assert yaml.safe_load(text) == {
        "timestamp": STAMP,
        "host": "macmini",
        "config_path": CONFIG,
        "data_path": "/home/homeassistant/site/data",
        "logs_included": True,
        "traefik_config": "/etc/traefik/dynamic/homeassistant.yml",
        "service_unit": "/etc/systemd/system/homeassistant.service",
        "extra_paths": [{"name": "thread", "path": "/var/lib/thread"}],
        "ansible_user": "root",
    }
    assert "logs_included: True\n" in text
    none = HomeAssistantBackupConfig(host_name="m", include_thread=False)
    assert yaml.safe_load(backup_metadata(none, stamp=STAMP))["extra_paths"] == []


def test_restore_runs_one_labelled_script() -> None:
    cfg = HomeAssistantRestoreConfig(host_name="macmini", archive="manual-1.tar.gz", manage_matter_server=True)

    result = restore(cfg)

    assert result.succeeded, result.error
    (script,) = result.executed_commands
    values = assignments(script)
    assert values["ARCHIVE"] == "manual-1.tar.gz"
    assert values["REQUIRED_FIELDS"] == "(timestamp host config_path data_path)"
    assert values["EXTRAS"] == "(thread:/var/lib/thread:root:root:0750)"
    assert values["START_RETRIES"] == "20"
    assert values["FORWARDED_FOR"] == "@default-ipv4"
    assert values["VERIFY_HTTP"] == "0"
    assert values["SYSTEM_FILES"] == "0"
    assert result.changed_ops == ["Home Assistant restore | Restore Home Assistant"]
    dry = restore(cfg.model_copy(update={"dry_run": True}))
    assert dry.changed_ops == ["Home Assistant restore | Restore Home Assistant (dry run)"]


@pytest.mark.parametrize("archive", ["../x.tar.gz", "/opt/backups/homeassistant/a.tar.gz", "a b.tar.gz", "x"])
def test_restore_archive_must_be_a_name_below_the_root(archive: str) -> None:
    with pytest.raises(ValidationError):
        HomeAssistantRestoreConfig(host_name="m", archive=archive)


@pytest.mark.parametrize("path", ["/tmp/x/", "/tmp/./x", "/tmp//x", "/tmp/../etc", "/", "//", "//tmp/x"])
@pytest.mark.parametrize("field", ["staging_dir", "data_path", "site_root"])
def test_restore_paths_must_be_canonical(field: str, path: str) -> None:
    with pytest.raises(ValidationError):
        HomeAssistantRestoreConfig.model_validate({"host_name": "m", field: path})


@pytest.mark.parametrize("path", ["/", "//", "//x", "/x/../y"])
def test_backup_local_dir_and_root_must_be_canonical(path: str) -> None:
    for field in ("local_dir", "root"):
        with pytest.raises(ValidationError):
            HomeAssistantBackupConfig.model_validate({"host_name": "m", field: path})


def test_restore_staging_must_lie_below_the_required_mount() -> None:
    with pytest.raises(ValidationError):
        HomeAssistantRestoreConfig(host_name="m", required_mount="/opt/backups")


# -- the host scripts -----------------------------------------------------------

STUBS = r"""
ensure_dir() { mkdir -p "$4"; }
copy_file() { local dest=$5; [ -d "$dest" ] && dest="$dest/$(basename "$4")"; cp "$4" "$dest"; chmod "$3" "$dest"; }
chown_tree() { printf 'chown_tree %s\n' "$*" >>"$LOG"; }
systemctl() {
    printf 'systemctl %s\n' "$*" >>"$LOG"
    case $1 in
        is-active) printf '%s\n' "$ACTIVE"; [ "$ACTIVE" = active ] ;;
        stop) [ -z "${SYSTEMCTL_STOP_FAILS:-}" ] ;;
        show) printf '%s\n' "${LOAD_STATE:-not-found}" ;;
        *) return 0 ;;
    esac
}
curl() { printf 'curl %s\n' "$*" >>"$LOG"; printf 200; }
getent() { return 0; }
groupadd() { printf 'groupadd %s\n' "$*" >>"$LOG"; }
useradd() { printf 'useradd %s\n' "$*" >>"$LOG"; }
ROUTE_GUARD=(true)
"""


def run_script(command: str, body: str, tmp_path: Path, **env: str) -> subprocess.CompletedProcess[str]:
    """``command`` (as planned) with the stubs between the shared helpers and ``body``."""

    text = (FILES / body).read_text().rstrip()
    head, sep, tail = command.rpartition(text)
    assert sep, "script body not found"
    return subprocess.run(
        ["bash", "-c", head + STUBS + sep + tail],
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "LOG": str(tmp_path / "calls.log"), "ACTIVE": "active", **env},
    )


def calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls.log"
    return log.read_text().splitlines() if log.exists() else []


def make_site(site: Path, marker: str) -> None:
    for sub in ("config", "data", "logs"):
        (site / sub).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(site / "config" / "home-assistant_v2.db")
    conn.executescript(f"CREATE TABLE IF NOT EXISTS t(v TEXT); DELETE FROM t; INSERT INTO t VALUES ('{marker}');")
    conn.commit()
    conn.close()
    (site / "config" / "configuration.yaml").write_text(f"name: {marker}\n")
    (site / "data" / "state.json").write_text(f'"{marker}"\n')
    (site / "logs" / "home-assistant.log").write_text(f"{marker}\n")


def tree(tmp_path: Path) -> dict[str, Path]:
    paths = {name: tmp_path / name for name in ("site", "thread", "etc", "backups", "staging", "local")}
    make_site(paths["site"], "original")
    (paths["thread"]).mkdir()
    (paths["thread"] / "settings").write_text("thread-original\n")
    paths["etc"].mkdir()
    (paths["etc"] / "homeassistant.service").write_text("[Service]\n")
    (paths["etc"] / "homeassistant.yml").write_text("http: {}\n")
    return paths


def path_settings(p: dict[str, Path]) -> dict[str, Any]:
    site = p["site"]
    return {
        "config_path": str(site / "config"),
        "data_path": str(site / "data"),
        "logs_path": str(site / "logs"),
        "otbr_state_path": str(p["thread"]),
        "service_unit_path": str(p["etc"] / "homeassistant.service"),
        "traefik_config_path": str(p["etc"] / "homeassistant.yml"),
    }


def take_backup(p: dict[str, Path], tmp_path: Path) -> Path:
    cfg = HomeAssistantBackupConfig(host_name="macmini", root=str(p["backups"]), fetch_local=False, **path_settings(p))
    result = run_deploy_fake(
        deploy_homeassistant_backup,
        cfg,
        responses={"date +%Y%m%dT%H%M%S": [STAMP], f"test -e {cfg.config_path} &&": ["yes"]},
    )
    assert result.succeeded, result.error
    script, manifest, archive = split(result)
    done = run_script(script, "backup.sh", tmp_path)
    assert done.returncode == 0, done.stderr
    directory = p["backups"] / f"manual-{STAMP}"
    (directory / "metadata.yml").write_bytes(result.upload(f"{directory}/metadata.yml"))
    for command in (manifest, archive):
        done = subprocess.run(["bash", "-c", command], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    return directory


def restore_command(p: dict[str, Path], **extra: Any) -> str:
    cfg = HomeAssistantRestoreConfig(
        host_name="macmini",
        search_root=str(p["backups"]),
        staging_dir=str(p["staging"]),
        site_root=str(p["site"]),
        manage_matter_server=True,
        start_timeout=0,
        **path_settings(p),
        **extra,
    )
    result = restore(cfg)
    assert result.succeeded, result.error
    (command,) = result.executed_commands
    return command


@needs_gnu
def test_backup_script_snapshots_state_and_excludes_the_live_database(tmp_path: Path) -> None:
    p = tree(tmp_path)
    (p["site"] / "config" / "home-assistant_v2.db-wal").write_text("live wal\n")
    (p["site"] / "config" / "home-assistant_v2.db-shm").write_text("live shm\n")

    directory = take_backup(p, tmp_path)

    assert (directory / "config" / "configuration.yaml").read_text() == "name: original\n"
    assert not (directory / "config" / "home-assistant_v2.db-wal").exists()
    assert not (directory / "config" / "home-assistant_v2.db-shm").exists()
    copy = sqlite3.connect(directory / "config" / "home-assistant_v2.db")
    assert copy.execute("SELECT v FROM t").fetchall() == [("original",)]
    copy.close()
    assert (directory / "data" / "state.json").exists()
    assert (directory / "logs" / "home-assistant.log").exists()
    assert (directory / "thread" / "settings").read_text() == "thread-original\n"
    assert (directory / "homeassistant.service").read_text() == "[Service]\n"
    assert (directory / "homeassistant.traefik.yml").read_text() == "http: {}\n"
    manifest = (directory / "manifest.sha256").read_text()
    assert "./metadata.yml" in manifest
    assert "./manifest.sha256" not in manifest
    with tarfile.open(p["backups"] / f"manual-{STAMP}.tar.gz") as tar:
        assert {name.split("/")[0] for name in tar.getnames()} == {f"manual-{STAMP}"}
    assert calls(tmp_path) == []


@needs_gnu
def test_restore_script_puts_the_snapshot_back_and_starts_the_services(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p["site"], "changed")
    # rsync's quick check compares size and mtime: date the same-size change back.
    os.utime(p["site"] / "config" / "home-assistant_v2.db", (1_000_000_000, 1_000_000_000))
    (p["site"] / "config" / "new.yaml").write_text("x\n")
    (p["thread"] / "settings").write_text("thread-changed\n")
    (tmp_path / "calls.log").unlink(missing_ok=True)

    done = run_script(restore_command(p), "restore.sh", tmp_path, LOAD_STATE="loaded")

    assert done.returncode == 0, done.stderr + done.stdout
    assert (p["site"] / "config" / "configuration.yaml").read_text() == "name: original\n"
    assert not (p["site"] / "config" / "new.yaml").exists()
    db = sqlite3.connect(p["site"] / "config" / "home-assistant_v2.db")
    assert db.execute("SELECT v FROM t").fetchall() == [("original",)]
    db.close()
    assert (p["thread"] / "settings").read_text() == "thread-original\n"
    log = calls(tmp_path)
    assert log.index("systemctl stop homeassistant") < log.index("systemctl start otbr-agent")
    assert "systemctl stop matter-server" in log
    assert "systemctl stop otbr-agent" in log
    assert log[-2:] == ["systemctl start homeassistant", "systemctl is-active homeassistant"]
    assert f"chown_tree homeassistant homeassistant {p['site']}" in log
    # Staging and the safety snapshot are gone after success.
    assert list(p["staging"].iterdir()) == []
    assert not list(tmp_path.glob("site.pre-restore-*"))
    assert "completed" in done.stdout


def gps_database(site: Path, marker: str) -> sqlite3.Connection:
    """GPS Timeline's WAL database with an uncheckpointed row; the caller closes it."""

    (site / "config" / "gps_timeline").mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(site / "config" / "gps_timeline" / "gps_timeline.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.executescript(f"CREATE TABLE IF NOT EXISTS p(v TEXT); DELETE FROM p; INSERT INTO p VALUES ('{marker}');")
    conn.commit()
    return conn


def test_backup_covers_the_gps_timeline_database_by_default() -> None:
    cfg = HomeAssistantBackupConfig(host_name="macmini", fetch_local=False)
    assert cfg.config_sqlite_databases == ("gps_timeline/gps_timeline.db",)
    script, _, _ = split(backup(cfg))
    assert assignments(script)["CONFIG_DBS"] == "(gps_timeline/gps_timeline.db)"
    for bad in ("../x.db", "/abs.db", "a/../b.db", ".hidden/x.db", "a//b.db", "a/b.db/"):
        with pytest.raises(ValidationError):
            HomeAssistantBackupConfig(host_name="macmini", config_sqlite_databases=(bad,))


@needs_gnu
def test_backup_and_restore_handle_the_gps_timeline_wal_database(tmp_path: Path) -> None:
    p = tree(tmp_path)
    live = gps_database(p["site"], "original")
    gps = p["site"] / "config" / "gps_timeline"
    assert (gps / "gps_timeline.db-wal").stat().st_size > 0  # the row lives only in the WAL

    directory = take_backup(p, tmp_path)
    live.close()

    snapshot = directory / "config" / "gps_timeline"
    assert sorted(path.name for path in snapshot.iterdir()) == ["gps_timeline.db"]
    copy = sqlite3.connect(snapshot / "gps_timeline.db")
    assert copy.execute("SELECT v FROM p").fetchall() == [("original",)]
    copy.close()

    changed = gps_database(p["site"], "changed")
    changed.close()
    os.utime(gps / "gps_timeline.db", (1_000_000_000, 1_000_000_000))
    (gps / "gps_timeline.db-wal").write_bytes(b"stale wal")
    (gps / "gps_timeline.db-shm").write_bytes(b"stale shm")

    done = run_script(restore_command(p), "restore.sh", tmp_path, LOAD_STATE="loaded")

    assert done.returncode == 0, done.stderr + done.stdout
    # The restore's rsync --delete drops the stale sidecars with the database.
    assert sorted(path.name for path in gps.iterdir()) == ["gps_timeline.db"]
    db = sqlite3.connect(gps / "gps_timeline.db")
    assert db.execute("SELECT v FROM p").fetchall() == [("original",)]
    db.close()


@needs_gnu
def test_restore_script_reads_an_archive_whose_metadata_the_role_wrote(tmp_path: Path) -> None:
    p = tree(tmp_path)
    directory = take_backup(p, tmp_path)
    # The role's rendering: the extra_paths list lands on the key's line.
    (directory / "metadata.yml").write_text(
        'timestamp: "x"\nhost: "macmini"\nconfig_path: "c"\ndata_path: "d"\n'
        'extra_paths:  - name: "thread"\n    path: "/var/lib/thread"\nansible_user: ""\n'
    )
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load((directory / "metadata.yml").read_text())
    (p["backups"] / f"manual-{STAMP}.tar.gz").unlink()
    subprocess.run(["tar", "-C", str(p["backups"]), "-czf", f"{directory}.tar.gz", directory.name], check=True)

    done = run_script(restore_command(p, validate_checksums=False), "restore.sh", tmp_path)

    assert done.returncode == 0, done.stderr


@needs_gnu
def test_restore_script_rolls_back_everything_it_overwrote(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p["site"], "current")
    (p["thread"] / "settings").write_text("thread-current\n")
    (p["etc"] / "homeassistant.yml").unlink()
    # Same bytes as the archived unit, but a mode the restore's copy changes.
    (p["etc"] / "homeassistant.service").chmod(0o600)
    (tmp_path / "calls.log").unlink(missing_ok=True)

    # Home Assistant never becomes active: verification fails after the copy.
    done = run_script(
        restore_command(p, restore_system_files=True), "restore.sh", tmp_path, ACTIVE="failed", LOAD_STATE="loaded"
    )

    assert done.returncode == 1
    assert "Rollback completed" in done.stdout
    assert (p["site"] / "config" / "configuration.yaml").read_text() == "name: current\n"
    assert (p["thread"] / "settings").read_text() == "thread-current\n"
    assert (p["etc"] / "homeassistant.service").stat().st_mode & 0o777 == 0o600
    # The route did not exist before the restore, so the rollback removes it again.
    assert not (p["etc"] / "homeassistant.yml").exists()
    log = calls(tmp_path)
    assert log[-3:] == ["systemctl start otbr-agent", "systemctl start matter-server", "systemctl start homeassistant"]
    # The role keeps the safety snapshot after a rollback (cleanup_after_rollback false).
    assert sorted(path.name.endswith(".extra") for path in tmp_path.glob("site.pre-restore-*")) == [False, True]
    assert list(p["staging"].iterdir()) == []


@needs_gnu
def test_rollback_recovers_files_when_the_unit_is_absent(tmp_path: Path) -> None:
    p = tree(tmp_path)
    directory = take_backup(p, tmp_path)
    # A snapshot without its required data directory fails after config was copied.
    shutil.rmtree(directory / "data")
    (p["backups"] / f"manual-{STAMP}.tar.gz").unlink()
    subprocess.run(["tar", "-C", str(p["backups"]), "-czf", f"{directory}.tar.gz", directory.name], check=True)
    make_site(p["site"], "current")
    (p["etc"] / "homeassistant.service").unlink()

    stubs = {"SYSTEMCTL_STOP_FAILS": "1"}
    done = run_script(restore_command(p, validate_checksums=False), "restore.sh", tmp_path, **stubs)

    assert done.returncode == 1
    assert "Required directory 'data' is missing" in done.stderr
    assert "Rollback completed" in done.stdout
    assert (p["site"] / "config" / "configuration.yaml").read_text() == "name: current\n"
    assert "systemctl start homeassistant" not in calls(tmp_path)


@needs_gnu
def test_restore_refuses_a_linked_staging_directory(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    target = tmp_path / "elsewhere"
    target.mkdir()
    p["staging"].symlink_to(target)

    done = run_script(restore_command(p, dry_run=True), "restore.sh", tmp_path)

    assert done.returncode == 1
    assert "not a plain directory" in done.stderr
    assert list(target.iterdir()) == []


@needs_gnu
def test_restore_dry_run_validates_and_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p["site"], "current")

    done = run_script(restore_command(p, dry_run=True), "restore.sh", tmp_path)

    assert done.returncode == 0, done.stderr
    assert (p["site"] / "config" / "configuration.yaml").read_text() == "name: current\n"
    assert calls(tmp_path) == []
    assert not list(tmp_path.glob("site.pre-restore-*"))
    assert list(p["staging"].iterdir()) == []


@needs_gnu
def test_restore_refuses_an_archive_of_another_host_or_with_a_bad_checksum(tmp_path: Path) -> None:
    p = tree(tmp_path)
    directory = take_backup(p, tmp_path)

    other = restore_command(p).replace("HOST_NAME=macmini", "HOST_NAME=studio")
    done = run_script(other, "restore.sh", tmp_path)
    assert done.returncode == 1
    assert "does not match current inventory host studio" in done.stderr

    (directory / "data" / "state.json").write_text("tampered\n")
    (p["backups"] / f"manual-{STAMP}.tar.gz").unlink()
    subprocess.run(["tar", "-C", str(p["backups"]), "-czf", f"{directory}.tar.gz", directory.name], check=True)
    done = run_script(restore_command(p), "restore.sh", tmp_path)
    assert done.returncode == 1
    assert calls(tmp_path) == []
    assert list(p["staging"].iterdir()) == []
