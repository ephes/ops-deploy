"""Paperless backup and restore: planned operations and the host scripts end to end.

The scripts run locally in a temporary tree. ``runuser`` runs its command
without switching users, ``manage.py`` is a fake Python that records its
calls, ``pg_dump``/``psql`` are recording fakes, and ``systemctl``/``curl``
are stubs. Fixtures only: no real documents, database or secrets.
"""

from __future__ import annotations

import os
import pwd
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import SecretStr, ValidationError

from ops_deploy.services.paperless import (
    PaperlessBackupConfig,
    PaperlessRestoreConfig,
    deploy_paperless_backup,
    deploy_paperless_restore,
)
from ops_deploy.services.paperless.backup_restore import FILES, backup_metadata, safety_config
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.lifecycle_scripts import assignments, calls, needs_gnu, run_script

STAMP = "20261104T120000"
LATER = "20261104T130000"
PHRASE = "fixture-passphrase"  # pragma: allowlist secret
PG_SECRET = "fixture-pg-password"  # pragma: allowlist secret


def backup(cfg: PaperlessBackupConfig, stamp: str = STAMP) -> FakeRun:
    return run_deploy_fake(deploy_paperless_backup, cfg, responses={"date +%Y%m%dT%H%M%S": [stamp]})


def restore(cfg: PaperlessRestoreConfig) -> FakeRun:
    return run_deploy_fake(deploy_paperless_restore, cfg, responses={"date +%Y%m%dT%H%M%S": [LATER]})


def body(result: FakeRun) -> str:
    return next(c for c in result.executed_commands if c.startswith("set -euo pipefail"))


# -- planned operations ---------------------------------------------------------


def test_backup_plans_the_role_steps_with_secrets_on_stdin(tmp_path: Path) -> None:
    cfg = PaperlessBackupConfig(
        host_name="macmini",
        local_dir=tmp_path / "local",
        exporter_passphrase=SecretStr(PHRASE),
        postgres_password=SecretStr(PG_SECRET),
    )

    result = backup(cfg)

    assert result.succeeded, result.error
    command = body(result)
    values = assignments(command)
    assert values["DIR"] == f"/opt/backups/paperless/manual-{STAMP}"
    assert values["EXPORTER_TARGET"] == f"/opt/backups/paperless/manual-{STAMP}/exporter"
    assert values["EXPORTER_FLAGS"] == "(-z --delete)"
    assert values["PG_DUMP_OPTIONS"] == "(--clean --if-exists --no-owner)"
    assert PHRASE not in command
    assert PG_SECRET not in command
    (_text, payload) = next(item for item in result.stdin if item[0] == command)
    assert payload == f"{PHRASE}\n{PG_SECRET}\n"
    assert "passphrase_set: True" in command
    assert "Paperless backup | Fetch the backup archive" in result.changed_ops


def test_backup_metadata_matches_the_role_template() -> None:
    cfg = PaperlessBackupConfig(host_name="macmini", metadata_extra={"backup_prefix": "manual"})

    text = backup_metadata(cfg, stamp=STAMP, backup_dir="/b/manual-x", exporter_target="/b/manual-x/exporter")

    data = yaml.safe_load(text.replace("@VERSION@", "3.2.1"))
    assert data["paperless_version"] == "3.2.1"
    assert data["storage"]["include_consume"] is False
    assert data["exporter"]["flags"] == "-z --delete"
    assert data["extra"] == {"backup_prefix": "manual"}
    assert "  include_logs: False\n" in text


def test_restore_safety_snapshot_uses_the_role_overrides() -> None:
    base = PaperlessBackupConfig(
        host_name="macmini", dir_owner="paperless", dir_group="postgres", exporter_passphrase=SecretStr(PHRASE)
    )
    cfg = PaperlessRestoreConfig(host_name="macmini", safety_backup=base)

    safety = safety_config(cfg, LATER)

    assert safety.prefix == "pre-restore"
    assert (safety.create_archive, safety.fetch_local, safety.exporter_enabled) == (False, False, False)
    assert (safety.postgres_user, safety.postgres_become_user, safety.database_dir_owner) == (
        "paperless",
        "paperless",
        "paperless",
    )
    assert safety.postgres_password.get_secret_value() == ""
    assert (safety.dir_owner, safety.dir_group) == ("paperless", "postgres")
    assert safety.metadata_extra["safety_snapshot"] is True


def test_restore_plans_one_script_with_its_secrets_on_stdin() -> None:
    cfg = PaperlessRestoreConfig(
        host_name="macmini",
        archive="manual-1.tar.gz",
        postgres_password=SecretStr(PG_SECRET),
        importer_passphrase=SecretStr(PHRASE),
    )

    result = restore(cfg)

    assert result.succeeded, result.error
    command = body(result)
    assert PG_SECRET not in command
    assert PHRASE not in command
    (_text, payload) = next(item for item in result.stdin if item[0] == command)
    assert payload == f"{PHRASE}\n{PG_SECRET}\n\n"
    values = assignments(command)
    assert values["SAFETY_DIR"] == f"/opt/backups/paperless/pre-restore-{LATER}"
    assert values["STAGING_GROUP"] == "postgres"
    assert values["PG_DB_IDENT"] == '"paperless"'


@pytest.mark.parametrize("archive", ["../x.tar.gz", "/abs/x.tar.gz", "dir", "x.zip"])
def test_restore_archive_must_be_a_name(archive: str) -> None:
    with pytest.raises(ValidationError):
        PaperlessRestoreConfig(host_name="m", archive=archive)


def test_secrets_must_be_single_lines() -> None:
    with pytest.raises(ValidationError):
        PaperlessRestoreConfig(host_name="m", postgres_password=SecretStr("a\nb"))
    with pytest.raises(ValidationError):
        PaperlessBackupConfig(host_name="m", exporter_passphrase=SecretStr("a\rb"))


@pytest.mark.parametrize("staging", ["/home/paperless", "/mnt/cryptdata", "/opt/backups", "/home/paperless/site/x"])
def test_restore_staging_lies_apart_from_live_data(staging: str) -> None:
    with pytest.raises(ValidationError):
        PaperlessRestoreConfig(host_name="m", staging_dir=staging)
    assert PaperlessRestoreConfig(host_name="m", staging_dir="/opt/backups/paperless/.restore-work")


# -- the host scripts -----------------------------------------------------------

FAKE_PYTHON = r"""#!PYTHON
import json, os, sys
log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manage.log")
args = sys.argv[2:]
with open(log, "a") as out:
    out.write(json.dumps({"args": args, "passphrase": os.environ.get("PAPERLESS_PASSPHRASE")}) + "\n")
if args == ["--version"]:
    print("3.2.1")
elif args and args[0] == "document_exporter":
    os.makedirs(args[-1], exist_ok=True)
    open(os.path.join(args[-1], "manifest.json"), "w").write("[]")
elif args and args[0] == "document_importer":
    sys.exit(1 if os.path.exists(os.path.join(os.path.dirname(log), "importer-fails")) else 0)
"""

FAKE_PG = r"""#!/bin/bash
name=$(basename "$0")
printf '%s %s\n' "$name" "$*" >>"$(dirname "$0")/pg.log"
if [ "$name" = pg_dump ]; then printf -- '-- fixture dump\n'; else cat >>"$(dirname "$0")/psql.sql"; fi
"""

STUBS = r"""
runuser() { printf 'runuser %s\n' "$*" >>"$LOG"; shift 3; "$@"; }
install() {
    local args=()
    while [ $# -gt 0 ]; do case $1 in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done
    command install "${args[@]}"
}
systemctl() {
    printf 'systemctl %s\n' "$*" >>"$LOG"
    case $1 in
        is-active) printf 'active\n' ;;
        *) return 0 ;;
    esac
}
sleep() { :; }
"""


def tree(tmp_path: Path) -> dict[str, Path]:
    p = {name: tmp_path / name for name in ("site", "ext", "etc", "backups", "staging", "bin")}
    for sub in ("media/documents", "data/index"):
        (p["ext"] / sub).mkdir(parents=True)
    (p["ext"] / "media" / "documents" / "doc.pdf").write_text("original\n")
    (p["ext"] / "data" / "index" / "seg").write_text("index\n")
    src = p["site"] / "paperless-ngx" / "src"
    src.mkdir(parents=True)
    (p["site"] / ".venv" / "bin").mkdir(parents=True)
    python = p["site"] / ".venv" / "bin" / "python"
    python.write_text(FAKE_PYTHON.replace("#!PYTHON", "#!" + sys.executable))
    python.chmod(0o755)
    (p["site"] / ".env").write_text("PAPERLESS_SECRET_KEY=fixture\n")
    (p["site"] / "gunicorn.conf.py").write_text("bind = '127.0.0.1:10030'\n")
    p["etc"].mkdir()
    (p["etc"] / "paperless.service").write_text("[Service]\n")
    (p["etc"] / "paperless.yml").write_text("http: {}\n")
    p["bin"].mkdir()
    for name in ("pg_dump", "psql"):
        (p["bin"] / name).write_text(FAKE_PG)
        (p["bin"] / name).chmod(0o755)
    return p


def backup_cfg(p: dict[str, Path], **extra: Any) -> PaperlessBackupConfig:
    return PaperlessBackupConfig(
        host_name="macmini",
        root=str(p["backups"]),
        site_root=str(p["site"]),
        external_root=str(p["ext"]),
        fetch_local=False,
        disk_check_enabled=False,
        postgres_dump_binary=str(p["bin"] / "pg_dump"),
        systemd_units=(str(p["etc"] / "paperless.service"),),
        traefik_config_path=str(p["etc"] / "paperless.yml"),
        ssh_config_path="",
        **extra,
    )


def take_backup(p: dict[str, Path], tmp_path: Path, **extra: Any) -> Path:
    cfg = backup_cfg(p, **extra)
    result = backup(cfg)
    assert result.succeeded, result.error
    command = body(result)
    stdin = next(data for text, data in result.stdin if text == command)
    done = run_script(command, FILES / "backup.sh", tmp_path, stubs=STUBS, stdin=stdin)
    assert done.returncode == 0, done.stderr
    return p["backups"] / f"manual-{STAMP}.tar.gz"


def restore_cfg(p: dict[str, Path], **extra: Any) -> PaperlessRestoreConfig:
    values: dict[str, Any] = {
        "host_name": "macmini",
        "search_root": str(p["backups"]),
        "staging_dir": str(p["staging"]),
        "site_root": str(p["site"]),
        "external_root": str(p["ext"]),
        "psql_binary": str(p["bin"] / "psql"),
        "check_disk_space": False,
        "systemd_units": ({"src": "systemd/paperless.service", "dest": str(p["etc"] / "paperless.service")},),
        "traefik_file": {"src": "traefik/paperless.yml", "dest": str(p["etc"] / "paperless.yml")},
        "ssh_file": {"src": "ssh/sftp-scanner.conf", "dest": str(p["etc"] / "sftp-scanner.conf")},
        "safety_backup": backup_cfg(p),
        **extra,
    }
    return PaperlessRestoreConfig.model_validate(values)


def run_restore(p: dict[str, Path], tmp_path: Path, extra_stubs: str = "", **settings: Any) -> Any:
    result = restore(restore_cfg(p, **settings))
    assert result.succeeded, result.error
    command = body(result)
    stdin = next(data for text, data in result.stdin if text == command)
    (tmp_path / "calls.log").unlink(missing_ok=True)
    return run_script(command, FILES / "restore.sh", tmp_path, stubs=STUBS + extra_stubs, stdin=stdin)


def manage_calls(p: dict[str, Path]) -> list[dict[str, Any]]:
    import json

    log = p["site"] / ".venv" / "bin" / "manage.log"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@needs_gnu
def test_backup_script_writes_the_role_snapshot_and_archive(tmp_path: Path) -> None:
    p = tree(tmp_path)

    archive = take_backup(p, tmp_path, exporter_passphrase=SecretStr(PHRASE))

    assert archive.stat().st_mode & 0o777 == 0o600
    directory = p["backups"] / f"manual-{STAMP}"
    assert (directory / "database" / "paperless.sql").read_text() == "-- fixture dump\n"
    assert (directory / "exporter" / "manifest.json").exists()
    assert (directory / "media" / "documents" / "doc.pdf").read_text() == "original\n"
    assert (directory / "config" / "paperless.env").exists()
    assert (directory / "systemd" / "paperless.service").exists()
    assert (directory / "traefik" / "paperless.yml").exists()
    metadata = yaml.safe_load((directory / "metadata.yml").read_text())
    assert metadata["paperless_version"] == "3.2.1"
    assert "./metadata.yml" in (directory / "manifest.sha256").read_text()
    with tarfile.open(archive) as tar:
        assert {name.split("/")[0] for name in tar.getnames()} == {f"manual-{STAMP}"}
    exporter = next(call for call in manage_calls(p) if call["args"][0] == "document_exporter")
    assert exporter["passphrase"] == PHRASE
    assert exporter["args"] == ["document_exporter", "-z", "--delete", str(directory / "exporter")]
    assert not list(Path("/tmp").glob("paperless_backup-pgpass-*"))


@needs_gnu
def test_backup_script_refuses_a_missing_media_directory(tmp_path: Path) -> None:
    p = tree(tmp_path)
    import shutil

    shutil.rmtree(p["ext"] / "media")
    cfg = backup_cfg(p)
    result = backup(cfg)

    done = run_script(body(result), FILES / "backup.sh", tmp_path, stubs=STUBS, stdin="\n\n")

    assert done.returncode == 1
    assert "Media directory not found" in done.stderr
    assert not p["backups"].exists()


@needs_gnu
def test_restore_script_imports_and_keeps_a_safety_snapshot_until_success(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["ext"] / "media" / "documents" / "doc.pdf").write_text("changed\n")
    (p["site"] / ".env").write_text("PAPERLESS_SECRET_KEY=changed\n")

    done = run_restore(p, tmp_path)

    assert done.returncode == 0, done.stderr + done.stdout
    assert "completed successfully" in done.stdout
    log = calls(tmp_path)
    assert log.index("systemctl stop paperless-consumer") < log.index("systemctl start paperless")
    sql = (p["bin"] / "psql.sql").read_text()
    assert 'DROP DATABASE IF EXISTS "paperless";' in sql
    assert "CREATE DATABASE" in sql
    assert any(call["args"][0] == "document_importer" for call in manage_calls(p))
    # The importer restored the documents: no SQL file restore, no raw copy.
    assert "--file" not in (p["bin"] / "pg.log").read_text()
    assert (p["ext"] / "media" / "documents" / "doc.pdf").read_text() == "changed\n"
    assert (p["site"] / ".env").read_text() == "PAPERLESS_SECRET_KEY=fixture\n"
    # Success: the safety snapshot and the staging directory are gone.
    assert not list(p["backups"].glob("pre-restore-*"))
    assert not list(p["staging"].iterdir())


@needs_gnu
def test_restore_script_falls_back_to_the_raw_snapshot_when_the_importer_fails(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["ext"] / "media" / "documents" / "doc.pdf").write_text("changed\n")
    (p["site"] / ".venv" / "bin" / "importer-fails").touch()

    done = run_restore(p, tmp_path)

    assert done.returncode == 0, done.stderr + done.stdout
    assert "falling back to raw snapshot restore" in done.stdout
    assert "--file" in (p["bin"] / "pg.log").read_text()
    assert "ALTER SCHEMA public OWNER TO" in (p["bin"] / "psql.sql").read_text()
    assert (p["ext"] / "media" / "documents" / "doc.pdf").read_text() == "original\n"


@needs_gnu
def test_restore_script_rolls_back_after_a_failed_health_check(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["site"] / ".env").write_text("PAPERLESS_SECRET_KEY=changed\n")
    failing = 'curl() { printf "502"; }\n'

    done = run_restore(p, tmp_path, failing, health_retries=1)

    assert done.returncode == 1
    assert "verification failed" in done.stderr
    # Each dump (the archive's, then the safety snapshot's) is read as its directory's owner.
    me = pwd.getpwuid(os.getuid()).pw_name
    reads = [line for line in calls(tmp_path) if line.startswith(f"runuser -u {me} -- cat -- ")]
    assert len(reads) == 2, calls(tmp_path)
    assert "/pre-restore-" in reads[1]
    # The rollback put the pre-restore .env back and kept the safety snapshot.
    assert (p["site"] / ".env").read_text() == "PAPERLESS_SECRET_KEY=changed\n"
    assert len(list(p["backups"].glob("pre-restore-*"))) == 1
    assert not list(p["staging"].iterdir())


@needs_gnu
def test_restore_script_dry_run_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["site"] / ".env").write_text("PAPERLESS_SECRET_KEY=changed\n")

    done = run_restore(p, tmp_path, dry_run=True)

    assert done.returncode == 0, done.stderr
    assert "dry-run validation" in done.stdout
    assert [line for line in calls(tmp_path) if line.startswith("systemctl")] == []
    assert not (p["bin"] / "psql.sql").exists()
    assert (p["site"] / ".env").read_text() == "PAPERLESS_SECRET_KEY=changed\n"
    assert not list(p["backups"].glob("pre-restore-*"))


@needs_gnu
def test_restore_script_refuses_another_hosts_snapshot_before_any_change(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)

    done = run_restore(p, tmp_path, host_name="other")

    assert done.returncode == 1
    assert "does not match other" in done.stderr
    assert [line for line in calls(tmp_path) if line.startswith("systemctl")] == []
    assert not list(p["backups"].glob("pre-restore-*"))


@needs_gnu
def test_restore_script_with_passwords_leaves_no_passfile_and_no_password_on_a_command_line(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path, postgres_password=SecretStr(PG_SECRET))
    before = set(Path("/tmp").glob("paperless_*-pgpass-*"))

    done = run_restore(
        p, tmp_path, postgres_password=SecretStr(PG_SECRET), postgres_admin_password=SecretStr("fixture-admin")
    )

    assert done.returncode == 0, done.stderr + done.stdout
    assert set(Path("/tmp").glob("paperless_*-pgpass-*")) == before
    log = (tmp_path / "calls.log").read_text() + (p["bin"] / "pg.log").read_text()
    assert PG_SECRET not in log
    assert "fixture-admin" not in log
    assert "PGPASSFILE=/tmp/paperless_restore-pgpass-" in log


@needs_gnu
def test_restore_script_a_held_route_lock_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["etc"] / "paperless.yml").write_text("changed: 1\n")

    done = run_restore(p, tmp_path, "ROUTE_GUARD=(false)\n")

    assert done.returncode == 1
    assert "holds its lock" in done.stderr
    assert [line for line in calls(tmp_path) if line.startswith("systemctl")] == []
    assert not list(p["backups"].glob("pre-restore-*"))


@needs_gnu
def test_restore_script_without_the_search_root_says_so(tmp_path: Path) -> None:
    p = tree(tmp_path)

    done = run_restore(p, tmp_path)

    assert done.returncode == 1
    assert "No Paperless backup archives found" in done.stderr


@needs_gnu
def test_backup_script_keeps_the_snapshot_root_owned_until_it_hands_it_over(tmp_path: Path) -> None:
    p = tree(tmp_path)
    marker = tmp_path / "snooped"
    # The exporter (running as the app user) tries to plant a link where root writes metadata.
    planting = f'rsync() {{ ln -s {marker} "$DIR/.metadata.yml.new" 2>/dev/null || true; command rsync "$@"; }}\n'
    cfg = backup_cfg(p, dir_owner="nobody", dir_group="nogroup")
    result = backup(cfg)

    done = run_script(body(result), FILES / "backup.sh", tmp_path, stubs=STUBS + planting, stdin="\n\n")

    # The test cannot keep the plant out (no real chown); root still never writes through it.
    assert done.returncode == 0, done.stderr
    assert not marker.exists()
    assert (p["backups"] / f"manual-{STAMP}" / "metadata.yml").exists()
    log = calls(tmp_path)
    assert f"chown -h nobody:nogroup {p['backups'] / f'manual-{STAMP}'}" in log


@needs_gnu
def test_restore_script_refuses_a_staging_root_that_is_a_link(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    p["staging"].symlink_to(elsewhere)

    done = run_restore(p, tmp_path)

    assert done.returncode == 1
    assert "refusing to stage there" in done.stderr
    assert list(elsewhere.iterdir()) == []
