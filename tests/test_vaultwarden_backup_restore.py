"""Vaultwarden backup and restore: planned operations and the host scripts end to end.

Fixtures only: a throwaway SQLite vault and, for the encrypted path, an age
key pair generated into the test's temporary directory.
"""

from __future__ import annotations

import base64
import os
import shutil
import sqlite3
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from pyinfra.api import DeployError

from ops_deploy.services.vaultwarden import (
    VaultwardenBackupConfig,
    VaultwardenRestoreConfig,
    deploy_vaultwarden_backup,
    deploy_vaultwarden_restore,
)
from ops_deploy.services.vaultwarden.backup_restore import FILES, archive_bytes, backup_manifest, select_archive
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.lifecycle_scripts import STUBS, assignments, calls, needs_gnu, run_script

STAMP = "20261104T120000"
UTC = "20261104T110000Z"
needs_age = pytest.mark.skipif(shutil.which("age") is None or shutil.which("age-keygen") is None, reason="needs age")
RECIPIENT = "age1" + "q" * 58


def backup(cfg: VaultwardenBackupConfig) -> FakeRun:
    return run_deploy_fake(
        deploy_vaultwarden_backup, cfg, responses={"date +%Y%m%dT%H%M%S": [STAMP], "--version": ["Vaultwarden 1.34.3"]}
    )


def restore(cfg: VaultwardenRestoreConfig) -> FakeRun:
    return run_deploy_fake(deploy_vaultwarden_restore, cfg, responses={"date -u +%Y%m%dT%H%M%SZ": [UTC]})


def body(result: FakeRun) -> str:
    return next(c for c in result.executed_commands if c.startswith("set -euo pipefail"))


# -- planned operations ---------------------------------------------------------


def test_backup_plans_the_role_steps(tmp_path: Path) -> None:
    cfg = VaultwardenBackupConfig(local_dir=tmp_path / "local", encrypt=True, age_recipient=RECIPIENT)

    result = backup(cfg)

    assert result.succeeded, result.error
    values = assignments(body(result))
    assert values["DIR"] == f"/opt/backups/vaultwarden/manual-{STAMP}"
    assert values["ENCRYPT"] == "1"
    assert values["RECIPIENT"] == RECIPIENT
    assert values["RETAIN"] == "7"
    assert 'version: "Vaultwarden 1.34.3"' in body(result)
    assert "Vaultwarden backup | Ensure age" in result.changed_ops
    assert "Vaultwarden backup | Fetch the backup archive" in result.changed_ops
    assert (tmp_path / "local").stat().st_mode & 0o777 == 0o700


def test_backup_needs_a_recipient_to_encrypt() -> None:
    with pytest.raises(ValidationError):
        VaultwardenBackupConfig(encrypt=True)
    with pytest.raises(ValidationError):
        VaultwardenBackupConfig(encrypt=True, age_recipient="not-a-key")


def test_backup_manifest_matches_the_role_template() -> None:
    text = backup_manifest(VaultwardenBackupConfig(), version="1.34.3", stamp=STAMP)

    assert text == (
        f'version: "1.34.3"\ntimestamp: "{STAMP}"\narchive: "manual-{STAMP}.tar.gz"\n'
        'data_dir: "/var/lib/vaultwarden/data"\nconfig: "/etc/vaultwarden.env"\n'
        'service_unit: "/lib/systemd/system/vaultwarden.service"\n'
        'traefik_config: "/etc/traefik/dynamic/vaultwarden.yml"\n'
    )


def test_restore_refuses_without_the_legacy_confirmation(tmp_path: Path) -> None:
    (tmp_path / "manual-1.tar.gz").write_bytes(b"x")

    result = restore(VaultwardenRestoreConfig(local_dir=tmp_path))

    assert isinstance(result.error, DeployError)
    assert "Refusing the legacy Vaultwarden restore" in str(result.error)
    assert result.executed_commands == []


def test_restore_streams_the_archive_on_stdin(tmp_path: Path) -> None:
    (tmp_path / "manual-1.tar.gz").write_bytes(b"archive bytes")

    result = restore(VaultwardenRestoreConfig(local_dir=tmp_path, legacy_restore_confirmed=True))

    assert result.succeeded, result.error
    values = assignments(body(result))
    assert values["ARCHIVE_NAME"] == "manual-1.tar.gz"
    assert values["SAFETY_DIR"] == f"/var/backups/vaultwarden-pre-restore/{UTC}"
    (_, payload) = next(item for item in result.stdin if item[0].startswith("set -euo pipefail"))
    assert base64.b64decode(payload) == b"archive bytes"
    assert "archive bytes" not in body(result)


def test_restore_feeds_the_archive_without_a_pty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from pyinfra.operations import server

    (tmp_path / "manual-1.tar.gz").write_bytes(b"archive bytes")
    seen: list[dict[str, Any]] = []
    real = server.shell

    def shell(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(server, "shell", shell)
    result = restore(VaultwardenRestoreConfig(local_dir=tmp_path, legacy_restore_confirmed=True))

    assert result.succeeded, result.error
    (call,) = [kwargs for kwargs in seen if "_stdin" in kwargs]
    assert call["_get_pty"] is False
    assert repr(call["_stdin"]) == "<stdin redacted>"


def test_restore_dry_run_uploads_nothing(tmp_path: Path) -> None:
    (tmp_path / "manual-1.tar.gz").write_bytes(b"archive bytes")
    cfg = VaultwardenRestoreConfig(local_dir=tmp_path, legacy_restore_confirmed=True, dry_run=True)

    result = restore(cfg)

    assert result.succeeded, result.error
    assert result.stdin == []
    assert assignments(body(result))["DRY_RUN"] == "1"
    assert result.changed_ops == ["Vaultwarden restore | Restore Vaultwarden (dry run)"]


def test_select_archive_takes_the_newest_plain_or_encrypted(tmp_path: Path) -> None:
    for index, name in enumerate(["manual-1.tar.gz", "manual-2.tar.gz.age", ".hidden.tar.gz", "notes.txt"]):
        (tmp_path / name).write_text("x")
        os.utime(tmp_path / name, (1_000_000 + index, 1_000_000 + index))

    assert select_archive(tmp_path, "latest").name == "manual-2.tar.gz.age"
    assert select_archive(tmp_path, "manual-1.tar.gz").name == "manual-1.tar.gz"
    with pytest.raises(DeployError):
        select_archive(tmp_path, "missing.tar.gz")
    with pytest.raises(DeployError, match="No Vaultwarden backup archives"):
        select_archive(tmp_path / "empty", "latest")


@pytest.mark.parametrize("archive", ["../x.tar.gz", "/home/x/manual.tar.gz", "x.zip"])
def test_restore_archive_must_be_a_name(archive: str) -> None:
    with pytest.raises(ValidationError):
        VaultwardenRestoreConfig(archive=archive)


@pytest.mark.parametrize(
    "update",
    [
        {"staging_dir": "/var/lib/vaultwarden"},
        {"staging_dir": "/var/lib/vaultwarden/data/tmp"},
        {"safety_root": "/var/lib/vaultwarden/data/safety"},
        {"staging_dir": "/var/backups"},
        {"staging_dir": "/tmp/x/"},
    ],
)
def test_restore_paths_must_lie_apart(update: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        VaultwardenRestoreConfig.model_validate(update)


@needs_age
def test_archive_bytes_decrypts_in_memory(tmp_path: Path) -> None:
    identity = tmp_path / "key.txt"
    subprocess.run(["age-keygen", "-o", str(identity)], check=True, capture_output=True)
    recipient = subprocess.run(["age-keygen", "-y", str(identity)], check=True, capture_output=True, text=True)
    plain = tmp_path / "a.tar.gz"
    plain.write_bytes(b"plain archive")
    encrypted = tmp_path / "a.tar.gz.age"
    subprocess.run(["age", "-r", recipient.stdout.strip(), "-o", str(encrypted), str(plain)], check=True)
    plain.unlink()

    assert archive_bytes(encrypted, identity) == b"plain archive"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["a.tar.gz.age", "key.txt"]
    with pytest.raises(DeployError):
        archive_bytes(encrypted, tmp_path / "missing")


# -- the host scripts -----------------------------------------------------------

UNITS = r"""
install() {
    local args=()
    while [ $# -gt 0 ]; do case $1 in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done
    command install "${args[@]}"
}
systemctl() {
    printf 'systemctl %s\n' "$*" >>"$LOG"
    case $1 in
        is-active) if [ -e "$LOG.running" ]; then echo active; else echo inactive; return 3; fi ;;
        stop) [ -z "${SYSTEMCTL_STOP_FAILS:-}" ] && rm -f "$LOG.running" ;;
        start|restart) [ -z "${SYSTEMCTL_START_FAILS:-}" ] && : >"$LOG.running" ;;
        show) echo loaded ;;
        *) return 0 ;;
    esac
}
"""


def tree(tmp_path: Path) -> dict[str, Path]:
    p = {name: tmp_path / name for name in ("data", "etc", "backups", "staging", "safety", "local", "log")}
    p["data"].mkdir()
    vault(p["data"], "original")
    (p["data"] / "attachments").mkdir()
    (p["data"] / "attachments" / "a.bin").write_text("original\n")
    (p["data"] / "rsa_key.pem").write_text("fixture key\n")
    p["etc"].mkdir()
    (p["etc"] / "vaultwarden.env").write_text("DOMAIN=https://vault.example\n")
    (p["etc"] / "override.d").mkdir()
    (p["etc"] / "override.d" / "override.conf").write_text("[Service]\n")
    (p["etc"] / "vaultwarden.yml").write_text("http: {}\n")
    return p


def vault(data: Path, marker: str) -> None:
    conn = sqlite3.connect(data / "db.sqlite3")
    conn.executescript(f"CREATE TABLE IF NOT EXISTS t(v TEXT); DELETE FROM t; INSERT INTO t VALUES ('{marker}');")
    conn.commit()
    conn.close()


def paths(p: dict[str, Path]) -> dict[str, Any]:
    return {
        "data_dir": str(p["data"]),
        "config_file": str(p["etc"] / "vaultwarden.env"),
        "service_override_dir": str(p["etc"] / "override.d"),
        "traefik_config_path": str(p["etc"] / "vaultwarden.yml"),
    }


def take_backup(p: dict[str, Path], tmp_path: Path, **extra: Any) -> Path:
    cfg = VaultwardenBackupConfig(
        root=str(p["backups"]), skip_dependencies=True, local_dir=p["local"], fetch_local=False, **paths(p), **extra
    )
    result = backup(cfg)
    assert result.succeeded, result.error
    (tmp_path / "calls.log.running").touch()
    done = run_script(body(result), FILES / "backup.sh", tmp_path, stubs=UNITS)
    assert done.returncode == 0, done.stderr
    return p["backups"] / f"manual-{STAMP}.tar.gz"


def run_restore(p: dict[str, Path], tmp_path: Path, archive: Path, stubs: str = "", **extra: Any) -> Any:
    p["local"].mkdir(exist_ok=True)
    shutil.copy(archive, p["local"] / archive.name)
    settings = {"staging_dir": str(p["staging"]), "safety_root": str(p["safety"]), "log_dir": str(p["log"]), **extra}
    cfg = VaultwardenRestoreConfig(legacy_restore_confirmed=True, local_dir=p["local"], **paths(p), **settings)
    result = restore(cfg)
    assert result.succeeded, result.error
    command = body(result)
    stdin = next((data for text, data in result.stdin if text == command), "")
    (tmp_path / "calls.log").unlink(missing_ok=True)
    (tmp_path / "calls.log.running").touch()
    script_text = (FILES / "restore.sh").read_text().rstrip()
    head, sep, tail = command.rpartition(script_text)
    return subprocess.run(
        ["bash", "-c", head + STUBS + UNITS + stubs + sep + tail],
        input=stdin,
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "LOG": str(tmp_path / "calls.log"), "COPYFILE_DISABLE": "1"},
    )


def read_vault(data: Path) -> list[tuple[str]]:
    conn = sqlite3.connect(data / "db.sqlite3")
    rows = conn.execute("SELECT v FROM t").fetchall()
    conn.close()
    return rows


@needs_gnu
def test_backup_script_writes_the_role_archive(tmp_path: Path) -> None:
    p = tree(tmp_path)

    archive = take_backup(p, tmp_path)

    assert archive.stat().st_mode & 0o777 == 0o600
    with tarfile.open(archive) as tar:
        names = tar.getnames()
    top = f"manual-{STAMP}"
    assert {name.split("/")[0] for name in names} == {top}
    for member in (
        "data/db.sqlite3",
        "data/attachments/a.bin",
        "data/rsa_key.pem",
        "config/vaultwarden.env",
        "systemd/override.conf",
        "traefik/vaultwarden.yml",
        "manifest.yml",
    ):
        assert f"{top}/{member}" in names
    assert not (p["backups"] / top).exists()
    assert calls(tmp_path) == [
        "systemctl is-active vaultwarden",
        "systemctl stop vaultwarden",
        "systemctl daemon-reload",
        "systemctl start vaultwarden",
    ]


@needs_gnu
def test_backup_script_leaves_a_stopped_service_stopped_and_prunes(tmp_path: Path) -> None:
    p = tree(tmp_path)
    p["backups"].mkdir()
    for index in range(3):
        old = p["backups"] / f"manual-2026010{index}T000000.tar.gz{'.age' if index else ''}"
        old.write_text("x")
        os.utime(old, (1_000_000 + index, 1_000_000 + index))
    (p["backups"] / "other-20260101T000000.tar.gz").write_text("x")
    cfg = VaultwardenBackupConfig(
        root=str(p["backups"]), skip_dependencies=True, fetch_local=False, retain=2, **paths(p)
    )
    result = backup(cfg)

    done = run_script(body(result), FILES / "backup.sh", tmp_path, stubs=UNITS)

    assert done.returncode == 0, done.stderr
    assert "systemctl start vaultwarden" not in calls(tmp_path)
    assert sorted(path.name for path in p["backups"].iterdir()) == [
        "manual-20260102T000000.tar.gz.age",
        f"manual-{STAMP}.tar.gz",
        "other-20260101T000000.tar.gz",
    ]


@needs_gnu
def test_backup_script_starts_the_service_again_when_the_copy_fails(tmp_path: Path) -> None:
    p = tree(tmp_path)
    cfg = VaultwardenBackupConfig(root=str(p["backups"]), skip_dependencies=True, fetch_local=False, **paths(p))
    result = backup(cfg)
    (tmp_path / "calls.log.running").touch()

    done = run_script(body(result), FILES / "backup.sh", tmp_path, stubs=UNITS + "sqlite3() { return 1; }\n")

    assert done.returncode != 0
    assert calls(tmp_path)[-1] == "systemctl start vaultwarden"


@needs_gnu
@needs_age
def test_backup_script_encrypts_and_removes_the_plain_archive(tmp_path: Path) -> None:
    p = tree(tmp_path)
    identity = tmp_path / "key.txt"
    subprocess.run(["age-keygen", "-o", str(identity)], check=True, capture_output=True)
    recipient = subprocess.run(["age-keygen", "-y", str(identity)], check=True, capture_output=True, text=True)

    plain = take_backup(p, tmp_path, encrypt=True, age_recipient=recipient.stdout.strip())

    assert not plain.exists()
    encrypted = Path(f"{plain}.age")
    assert encrypted.stat().st_mode & 0o777 == 0o600
    assert archive_bytes(encrypted, identity)[:2] == b"\x1f\x8b"


@needs_gnu
def test_restore_script_overwrites_with_a_safety_copy(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    vault(p["data"], "changed")
    (p["data"] / "db.sqlite3-wal").write_text("stale\n")
    (p["etc"] / "vaultwarden.env").write_text("DOMAIN=changed\n")

    done = run_restore(p, tmp_path, archive)

    assert done.returncode == 0, done.stderr + done.stdout
    assert read_vault(p["data"]) == [("original",)]
    assert not (p["data"] / "db.sqlite3-wal").exists()
    assert (p["etc"] / "vaultwarden.env").read_text() == "DOMAIN=https://vault.example\n"
    safety = p["safety"] / UTC
    assert read_vault(safety / "data") == [("changed",)]
    assert (safety / "files" / "config").read_text() == "DOMAIN=changed\n"
    assert not p["staging"].exists()
    log = calls(tmp_path)
    assert log.index("systemctl stop vaultwarden") < log.index("systemctl restart vaultwarden")
    assert "systemctl enable vaultwarden" in log


@needs_gnu
def test_restore_script_dry_run_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    vault(p["data"], "changed")

    done = run_restore(p, tmp_path, archive, dry_run=True)

    assert done.returncode == 0, done.stderr
    assert read_vault(p["data"]) == [("changed",)]
    assert calls(tmp_path) == []
    assert not p["safety"].exists()
    assert not p["staging"].exists()


@needs_gnu
def test_restore_script_refuses_a_corrupt_database_before_stopping(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    bad = tmp_path / "bad" / "manual-x"
    (bad / "data").mkdir(parents=True)
    (bad / "data" / "db.sqlite3").write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
    archive = tmp_path / "manual-x.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(bad, arcname="manual-x")
    vault(p["data"], "changed")

    done = run_restore(p, tmp_path, archive)

    assert done.returncode != 0
    assert "systemctl stop vaultwarden" not in calls(tmp_path)
    assert read_vault(p["data"]) == [("changed",)]
    assert not p["safety"].exists()


@needs_gnu
def test_restore_script_a_failed_stop_leaves_the_data_untouched(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    vault(p["data"], "changed")

    done = run_restore(p, tmp_path, archive, "export SYSTEMCTL_STOP_FAILS=1\n")

    assert done.returncode == 1
    assert "aborted before any live file was overwritten" in done.stderr
    assert read_vault(p["data"]) == [("changed",)]
    assert not p["safety"].exists()
    assert "systemctl restart vaultwarden" not in calls(tmp_path)


@needs_gnu
def test_restore_script_a_failed_overwrite_puts_the_safety_copy_back_and_stays_stopped(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    vault(p["data"], "changed")
    (p["etc"] / "vaultwarden.env").write_text("DOMAIN=changed\n")

    done = run_restore(p, tmp_path, archive, "export SYSTEMCTL_START_FAILS=1\n")

    assert done.returncode == 1
    assert "The pre-restore safety copy was put back" in done.stderr
    assert read_vault(p["data"]) == [("changed",)]
    assert (p["etc"] / "vaultwarden.env").read_text() == "DOMAIN=changed\n"
    assert (p["safety"] / UTC).is_dir()
    assert not p["staging"].exists()


@needs_gnu
def test_restore_script_refuses_symlinked_data_paths(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    elsewhere = tmp_path / "elsewhere"
    shutil.move(p["data"] / "attachments", elsewhere)
    (p["data"] / "attachments").symlink_to(elsewhere)

    done = run_restore(p, tmp_path, archive)

    assert done.returncode == 1
    assert "attachments under" in done.stderr
    assert "systemctl stop vaultwarden" not in calls(tmp_path)


@needs_gnu
def test_restore_script_aborts_when_the_unit_still_reports_active(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    vault(p["data"], "changed")
    sticky = (
        'systemctl() { printf "systemctl %s\\n" "$*" >>"$LOG"; '
        "case $1 in is-active) echo active ;; show) echo loaded ;; esac; }\n"
    )

    done = run_restore(p, tmp_path, archive, sticky)

    assert done.returncode == 1
    assert "aborted before any live file was overwritten" in done.stderr
    assert read_vault(p["data"]) == [("changed",)]
    assert not p["safety"].exists()


@needs_gnu
def test_restore_script_does_not_roll_back_while_the_unit_runs(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    vault(p["data"], "changed")
    # The stop works once (before the copy), then restart fails and the unit stays up.
    flaky = (
        'systemctl() { printf "systemctl %s\\n" "$*" >>"$LOG"; case $1 in '
        'is-active) if [ -e "$LOG.up" ]; then echo active; else echo inactive; fi ;; '
        'restart) : >"$LOG.up"; return 1 ;; show) echo loaded ;; esac; }\n'
    )

    done = run_restore(p, tmp_path, archive, flaky)

    assert done.returncode == 1
    assert "could not be stopped, so the safety copy was NOT put back" in done.stderr
    assert read_vault(p["data"]) == [("original",)]
    assert (p["safety"] / UTC).is_dir()


@needs_gnu
def test_restore_script_a_held_route_lock_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    (p["etc"] / "vaultwarden.yml").write_text("changed: 1\n")

    done = run_restore(p, tmp_path, archive, "ROUTE_GUARD=(false)\n")

    assert done.returncode == 1
    assert "holds its lock" in done.stderr
    assert "systemctl stop vaultwarden" not in calls(tmp_path)
    assert not p["safety"].exists()


@needs_gnu
@needs_age
def test_restore_decrypts_an_encrypted_archive_end_to_end(tmp_path: Path) -> None:
    p = tree(tmp_path)
    identity = tmp_path / "key.txt"
    subprocess.run(["age-keygen", "-o", str(identity)], check=True, capture_output=True)
    recipient = subprocess.run(["age-keygen", "-y", str(identity)], check=True, capture_output=True, text=True)
    plain = take_backup(p, tmp_path, encrypt=True, age_recipient=recipient.stdout.strip())
    vault(p["data"], "changed")

    done = run_restore(p, tmp_path, Path(f"{plain}.age"), age_identity=identity)

    assert done.returncode == 0, done.stderr
    assert "(encrypted: True)" in done.stdout
    assert read_vault(p["data"]) == [("original",)]
    assert sorted(path.name for path in p["local"].iterdir()) == [f"manual-{STAMP}.tar.gz.age"]


@needs_gnu
def test_restore_script_keeps_the_staging_parent_mode(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    os.chmod(shared, 0o1777)

    done = run_restore(p, tmp_path, archive, staging_dir=str(shared / "vaultwarden-restore"))

    assert done.returncode == 0, done.stderr
    assert shared.stat().st_mode & 0o7777 == 0o1777
    assert not (shared / "vaultwarden-restore").exists()


@needs_gnu
def test_restore_script_without_an_installed_unit_needs_it_inactive(tmp_path: Path) -> None:
    p = tree(tmp_path)
    archive = take_backup(p, tmp_path)
    absent = (
        'systemctl() { printf "systemctl %s\\n" "$*" >>"$LOG"; '
        "case $1 in show) echo not-found ;; is-active) echo inactive; return 3 ;; esac; }\n"
    )

    done = run_restore(p, tmp_path, archive, absent)

    assert done.returncode == 0, done.stderr
    assert "systemctl stop vaultwarden" not in calls(tmp_path)
    assert (p["safety"] / UTC).is_dir()
