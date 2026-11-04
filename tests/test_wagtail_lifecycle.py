"""Wagtail backup and restore: plans against the fake connector, the host program against tmp dirs.

The host program runs for real here (tar, gzip, cp, the vendored preserver);
``systemctl``, ``runuser``, the PostgreSQL clients, ``findmnt``, ``df``, ``du``
and ``rsync`` are stubs on ``PATH`` that log their calls.
"""

from __future__ import annotations

import gzip
import importlib.util
import json
import os
import pwd
import shlex
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from pyinfra.api import DeployError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services._lifecycle import wagtail
from ops_deploy.services._lifecycle.wagtail import (
    WagtailBackupConfig,
    WagtailRestoreConfig,
    deploy_wagtail_backup,
    deploy_wagtail_restore,
)
from ops_deploy.testing import FakeRun, run_deploy_fake

STAMP = "20261104T120000"
PASSWORD = "pg:secret\\value"
REF = SecretRef("secrets/prod/weeknotes_home.yml")
SECRETS = SecretValues(REF, {"postgres_password": PASSWORD})
TIME = {"date +%Y%m%dT%H%M%S": [STAMP]}
ME = pwd.getpwuid(os.getuid()).pw_name


def weeknotes_backup(**extra: Any) -> WagtailBackupConfig:
    """The values ``playbooks/weeknotes_home/backup.yml`` passes."""

    values: dict[str, Any] = {
        "service_name": "weeknotes_home",
        "root": "/opt/backups/weeknotes_home",
        "owner": "postgres",
        "group": "postgres",
        "systemd_unit_name": "weeknotes-home",
        "postgres_database": "weeknotes_home",
        "postgres_user": "weeknotes_home",
        "postgres_port": "",
        "postgres_target_opts": "--clean --if-exists --no-owner",
    }
    values.update(extra)
    return WagtailBackupConfig(**values)


def weeknotes_restore(**extra: Any) -> WagtailRestoreConfig:
    values: dict[str, Any] = {
        "service_name": "weeknotes_home",
        "root": "/opt/backups/weeknotes_home",
        "systemd_unit_name": "weeknotes-home",
        "postgres_port": "",
        "postgres_admin_user": "weeknotes_home",
        "run_migrations": False,
        "collectstatic": False,
        "update_index": False,
    }
    values.update(extra)
    return WagtailRestoreConfig(**values)


def payload_of(result: FakeRun, action: str) -> tuple[str, dict[str, Any]]:
    ((command, stdin),) = [(c, s) for c, s in result.stdin if shlex.split(c)[-1] == action]
    return command, json.loads(stdin)


# --- plans -------------------------------------------------------------------


def test_role_defaults_follow_the_service_name() -> None:
    backup = WagtailBackupConfig(service_name="site")
    restore = WagtailRestoreConfig(service_name="site")

    assert (backup.root, backup.systemd_unit_name, backup.postgres_database, backup.postgres_user) == (
        "/opt/backups/site",
        "site",
        "site",
        "site",
    )
    assert (backup.postgres_host, backup.postgres_port, backup.retain, backup.stop_service) == (
        "localhost",
        5432,
        7,
        False,
    )
    assert restore.staging_dir == "/tmp/wagtail-restore-site"
    assert restore.python == "/home/site/site/.venv/bin/python"
    assert restore.manage_py == "/home/site/site/manage.py"
    assert restore.postgres_admin_user == "site"
    assert (restore.run_migrations, restore.collectstatic, restore.update_index) == (True, True, False)
    assert restore.extra_units == ()
    assert WagtailRestoreConfig(service_name="site", db_worker_enabled=True).extra_units == ("site-db-worker",)


def test_backup_sends_the_password_on_stdin_only_then_fetches_and_prunes(tmp_path: Path) -> None:
    cfg = weeknotes_backup(local_dir=tmp_path / "local", required_mount="/opt/backups")

    result = run_deploy_fake(deploy_wagtail_backup, cfg, SECRETS, responses=TIME)

    assert result.succeeded, result.error
    command, payload = payload_of(result, "backup")
    assert PASSWORD not in command
    assert PASSWORD not in result.all_text()
    assert payload["password"] == PASSWORD
    assert payload["dir"] == f"/opt/backups/weeknotes_home/manual-{STAMP}"
    assert payload["archive"] == f"/opt/backups/weeknotes_home/manual-{STAMP}.tar.gz"
    assert payload["dump"] == f"/opt/backups/weeknotes_home/manual-{STAMP}/database/weeknotes_home.sql.gz"
    assert payload["target_opts"] == ["--clean", "--if-exists", "--no-owner"]
    assert (payload["port"], payload["owner"], payload["become_user"]) == ("", "postgres", "postgres")
    _, retention = payload_of(result, "retain")
    assert "password" not in retention
    assert retention == {
        "root": "/opt/backups/weeknotes_home",
        "prefix": "manual",
        "extension": "tar.gz",
        "retain": 7,
        "create_archive": True,
    }
    ops = result.changed_ops
    names = [op.split(" | ", 1)[1] for op in ops]
    assert names[0].startswith("Require /opt/backups below")
    assert names.index("Fetch the backup archive") < names.index("Keep the newest 7 manual backups")
    assert (tmp_path / "local").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "local" / f"manual-{STAMP}.tar.gz").stat().st_mode & 0o777 == 0o600


def test_backup_without_fetch_or_retention_plans_only_the_dump() -> None:
    cfg = weeknotes_backup(fetch_local=False, retain=0)

    result = run_deploy_fake(deploy_wagtail_backup, cfg, SECRETS, responses=TIME)

    assert result.succeeded, result.error
    assert [c for c, _ in result.stdin] == [wagtail._command("backup")]
    assert not any("Fetch" in op for op in result.changed_ops)


@pytest.mark.parametrize(
    "values",
    [{}, {"postgres_password": ""}, {"postgres_password": "CHANGEME"}],
    ids=["missing", "empty", "placeholder"],
)
def test_missing_or_unusable_password_refuses_before_any_step(values: dict[str, str]) -> None:
    for deploy_fn, cfg in ((deploy_wagtail_backup, weeknotes_backup()), (deploy_wagtail_restore, weeknotes_restore())):
        result = run_deploy_fake(deploy_fn, cfg, SecretValues(REF, values), responses=TIME)

        assert not result.succeeded
        assert result.stdin == []
        assert result.executed_commands == []


def test_restore_sends_both_passwords_on_stdin_and_labels_the_dry_run() -> None:
    secrets = SecretValues(REF, {"postgres_password": PASSWORD, "postgres_admin_password": "admin:pw"})

    result = run_deploy_fake(deploy_wagtail_restore, weeknotes_restore(dry_run=True), secrets)

    assert result.succeeded, result.error
    command, payload = payload_of(result, "restore")
    assert PASSWORD not in command
    assert "admin:pw" not in result.all_text()
    assert (payload["password"], payload["admin_password"]) == (PASSWORD, "admin:pw")
    assert payload["dry_run"] is True
    assert payload["staging"] == "/tmp/wagtail-restore-weeknotes_home"
    assert payload["unit"] == "weeknotes-home"
    assert (payload["run_migrations"], payload["collectstatic"], payload["update_index"]) == (False, False, False)
    assert any("dry run" in op for op in result.changed_ops)
    default = run_deploy_fake(deploy_wagtail_restore, weeknotes_restore(), SECRETS)
    assert payload_of(default, "restore")[1]["admin_password"] == PASSWORD


@pytest.mark.parametrize(
    "values",
    [
        {"postgres_target_opts": "--clean"},
        {"staging_dir": "/tmp"},
        {"staging_dir": "/"},
        {"site_path": "/home"},
        {"archive": "../escape.tar.gz"},
        {"root": "/opt/backups/../etc"},
    ],
)
def test_restore_config_refusals(values: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        weeknotes_restore(**values)


def test_backup_config_refusals() -> None:
    with pytest.raises(ValidationError):
        weeknotes_backup(postgres_target_opts="--clean; rm -rf /")
    with pytest.raises(ValidationError):
        weeknotes_backup(required_mount="/srv")


# --- host program ------------------------------------------------------------

STUBS = {
    "systemctl": 'if [ "$1" = show ]; then [ -n "${STUB_FAIL_SHOW:-}" ] && exit 1; '
    'echo "LoadState=${STUB_LOAD:-loaded}"; '
    'echo "ActiveState=${STUB_ACTIVE:-active}"; exit 0; fi\n'
    '[ -n "${STUB_FAIL_STOP:-}" ] && [ "$1" = stop ] && exit 1\nexit 0',
    "runuser": 'shift 3\nexec "$@"',
    "pg_dump": 'for a in "$@"; do case "$a" in --file=*) echo custom > "${a#--file=}"; exit 0;; esac; done\n'
    'echo "pw=${PGPASSWORD:+set}" >> "$STUB_LOG"\n'
    "printf 'SELECT 1;\\n--\\n-- PostgreSQL database dump complete\\n--\\n'",
    "psql": 'echo "env PGUSER=$PGUSER PGDATABASE=$PGDATABASE pw=${PGPASSWORD:+set} '
    'passfile=${PGPASSFILE:+set}" >> "$STUB_LOG"\n'
    'for a in "$@"; do case "$a" in\n'
    "  --command=*pg_get_userbyid*) echo weeknotes_home; exit 0;;\n"
    '  --command=*"FROM pg_database WHERE datname"*) [ -n "${STUB_ABSENT:-}" ] || echo 1; exit 0;;\n'
    "  --command=SHOW*) echo 160000; exit 0;;\n"
    "  --command=*pg_database_size*) echo 1000; exit 0;;\n"
    '  --command=GRANT*) [ -n "${STUB_FAIL_GRANT:-}" ] && exit 1; exit 0;;\n'
    "  --command=*) exit 0;;\n"
    "esac; done\n"
    'cat > /dev/null\n[ -n "${STUB_FAIL_RESTORE:-}" ] && exit 3\nexit 0',
    "pg_restore": "exit 0",
    "findmnt": 'echo \'{"filesystems": [{"target": "/"}]}\'',
    "df": "echo 'Filesystem 1-blocks Used Available Capacity Mounted'\necho 'fs 1 1 99999999999 1% /'",
    "du": 'printf "4242\\t%s\\n" "$2"',
    "rsync": "exit 0",
}


@pytest.fixture
def stubs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    flags = tmp_path / "flags"
    flags.mkdir()
    for name, body in STUBS.items():
        path = bin_dir / name
        # The host program gives its children a clean environment: settings come from files.
        header = f'STUB_LOG={log}\nfor f in {flags}/*; do [ -f "$f" ] && export "$(basename "$f")=$(cat "$f")"; done\n'
        path.write_text(f'#!/bin/bash\n{header}echo "{name} $*" >> "$STUB_LOG"\n{body}\n')
        path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    log.write_text("")
    return log


def flag(tmp_path: Path, name: str, value: str) -> None:
    (tmp_path / "flags" / name).write_text(value)


def host() -> Any:
    spec = importlib.util.spec_from_file_location("wagtail_host_test", wagtail.FILES / "wagtail_host.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.PRESERVE_SOURCE = (wagtail.FILES / "preserve.py").read_text()  # type: ignore[attr-defined]
    spec.loader.exec_module(module)
    return module


def backup_payload(root: Path, stamp: str = STAMP, **extra: Any) -> dict[str, Any]:
    directory = f"{root}/manual-{stamp}"
    values = {
        "service": "weeknotes_home",
        "timestamp": stamp,
        "root": str(root),
        "dir": directory,
        "archive": f"{directory}.tar.gz",
        "dump": f"{directory}/database/weeknotes_home.sql.gz",
        "owner": ME,
        "group": str(os.getgid()),
        "dir_mode": "0700",
        "file_mode": "0600",
        "stop_service": False,
        "unit": "weeknotes-home",
        "database": "weeknotes_home",
        "user": "weeknotes_home",
        "host": "localhost",
        "port": "",
        "become_user": ME,
        "target_opts": ["--clean", "--if-exists", "--no-owner"],
        "generate_manifest": True,
        "create_archive": True,
        "password": PASSWORD,
    }
    values.update(extra)
    return values


def test_backup_writes_the_role_layout_manifest_and_private_archive(tmp_path: Path, stubs: Path) -> None:
    root = tmp_path / "backups"
    root.mkdir(mode=0o755)
    old = root / "old.tar.gz"
    old.write_bytes(b"x")
    old.chmod(0o644)
    (root / ".hidden.tar.gz").write_bytes(b"x")
    (root / ".hidden.tar.gz").chmod(0o644)

    host().backup(backup_payload(root))

    directory = root / f"manual-{STAMP}"
    assert oct(root.stat().st_mode & 0o777) == "0o700"
    assert old.stat().st_mode & 0o777 == 0o600
    assert (root / ".hidden.tar.gz").stat().st_mode & 0o777 == 0o644
    dump = directory / "database/weeknotes_home.sql.gz"
    assert gzip.decompress(dump.read_bytes()).decode().splitlines()[2] == "-- PostgreSQL database dump complete"
    assert (directory / "manifest.yml").read_text() == (
        'service: "weeknotes_home"\n'
        f'timestamp: "{STAMP}"\n'
        f'archive: "manual-{STAMP}.tar.gz"\n'
        'database_dump: "weeknotes_home.sql.gz"\n'
        "postgres:\n"
        '  database: "weeknotes_home"\n'
        '  host: "localhost"\n'
        "  port: \n"
        '  user: "weeknotes_home"\n'
    )
    archive = root / f"manual-{STAMP}.tar.gz"
    assert archive.stat().st_mode & 0o777 == 0o600
    with tarfile.open(archive) as packed:
        assert sorted(packed.getnames()) == [
            f"manual-{STAMP}/database",
            f"manual-{STAMP}/database/weeknotes_home.sql.gz",
            f"manual-{STAMP}/manifest.yml",
        ]
    calls = stubs.read_text()
    assert "pg_dump weeknotes_home --host=localhost --username=weeknotes_home --clean --if-exists --no-owner" in calls
    assert "pw=set" in calls
    assert PASSWORD not in calls
    assert "systemctl" not in calls
    assert not list(root.glob(".*.partial"))


def test_backup_stops_and_starts_only_a_running_unit(
    tmp_path: Path, stubs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host().backup(backup_payload(tmp_path / "a", stop_service=True))
    calls = stubs.read_text()
    assert calls.index("systemctl stop weeknotes-home") < calls.index("pg_dump weeknotes_home")
    assert calls.index("pg_dump weeknotes_home") < calls.index(
        "systemctl daemon-reload\nsystemctl start weeknotes-home"
    )

    stubs.write_text("")
    flag(tmp_path, "STUB_ACTIVE", "inactive")
    host().backup(backup_payload(tmp_path / "b", stop_service=True))
    assert "start" not in stubs.read_text()

    stubs.write_text("")
    flag(tmp_path, "STUB_ACTIVE", "active")
    flag(tmp_path, "STUB_FAIL_STOP", "1")
    with pytest.raises(subprocess.CalledProcessError):
        host().backup(backup_payload(tmp_path / "c", stop_service=True))
    assert "systemctl start weeknotes-home" in stubs.read_text()


def test_retention_keeps_the_newest_archives_and_directories_of_the_prefix(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    for index in range(9):
        for path in (root / f"manual-{index}", root / f"manual-{index}.tar.gz"):
            path.mkdir() if path.suffix != ".gz" else path.write_bytes(b"")
            os.utime(path, (1_000_000 + index, 1_000_000 + index))
    (root / "pre-restore-1.tar.gz").write_bytes(b"")
    os.utime(root / "pre-restore-1.tar.gz", (1, 1))

    host().retain({"root": str(root), "prefix": "manual", "extension": "tar.gz", "retain": 7, "create_archive": True})

    left = sorted(path.name for path in root.iterdir())
    assert "manual-0" not in left
    assert "manual-1.tar.gz" not in left
    assert "manual-2" in left
    assert "manual-2.tar.gz" in left
    assert "pre-restore-1.tar.gz" in left
    assert len(left) == 15


def make_backup(tmp_path: Path, trailer: bool = True) -> Path:
    root = tmp_path / "backups"
    directory = root / "manual-1" / "database"
    directory.mkdir(parents=True)
    body = "SELECT 1;\n" + ("-- PostgreSQL database dump complete\n" if trailer else "")
    (directory / "weeknotes_home.sql.gz").write_bytes(gzip.compress(body.encode()))
    archive = root / "manual-1.tar.gz"
    with tarfile.open(archive, "w:gz") as packed:
        packed.add(root / "manual-1", "manual-1")
    return archive


def restore_payload(tmp_path: Path, **extra: Any) -> dict[str, Any]:
    site = tmp_path / "home" / "site"
    site.mkdir(parents=True, exist_ok=True)
    (site / "manage.py").write_text("print()\n")
    values = {
        "root": str(tmp_path / "backups"),
        "archive": "latest",
        "extension": "tar.gz",
        "cleanup": True,
        "restart": True,
        "stop_service": True,
        "dry_run": False,
        "staging": str(tmp_path / "staging"),
        "site_user": ME,
        "site_path": str(site),
        "env_path": str(site / ".env"),
        "manage_py": str(site / "manage.py"),
        "python": "/usr/bin/python3",
        "settings": "config.settings.production",
        "run_migrations": False,
        "collectstatic": False,
        "update_index": False,
        "unit": "weeknotes-home",
        "extra_units": ["weeknotes-home-db-worker"],
        "database": "weeknotes_home",
        "user": "weeknotes_home",
        "host": "localhost",
        "port": "",
        "admin_user": "weeknotes_home",
        "become_user": ME,
        "password": PASSWORD,
        "admin_password": PASSWORD,
    }
    values.update(extra)
    return values


def test_dry_run_validates_the_archive_without_touching_services_or_the_database(tmp_path: Path, stubs: Path) -> None:
    make_backup(tmp_path)

    host().restore(restore_payload(tmp_path, dry_run=True))

    calls = stubs.read_text()
    assert "systemctl" not in calls
    assert "psql" not in calls
    assert "pg_dump" not in calls
    assert not (tmp_path / "staging").exists()
    assert not list((tmp_path / "home").glob("site.pre-restore-*"))


def test_restore_runs_the_role_sequence_and_keeps_the_site_copy(tmp_path: Path, stubs: Path, capsys: Any) -> None:
    make_backup(tmp_path)

    host().restore(restore_payload(tmp_path))

    calls = stubs.read_text().splitlines()
    commands = [line for line in calls if not line.startswith(("env ", "pw="))]
    order = [
        "systemctl stop weeknotes-home-db-worker",
        "systemctl stop weeknotes-home",
        "pg_dump --format=custom",
        'psql --no-psqlrc -At -v ON_ERROR_STOP=1 --command=DROP DATABASE "weeknotes_home" WITH (FORCE)',
        'psql --no-psqlrc -At -v ON_ERROR_STOP=1 --command=GRANT ALL ON DATABASE "weeknotes_home" TO "weeknotes_home"',
        "systemctl enable weeknotes-home",
        "systemctl restart weeknotes-home",
        "systemctl restart weeknotes-home-db-worker",
    ]
    positions = [next(i for i, line in enumerate(commands) if line.startswith(step)) for step in order]
    assert positions == sorted(positions)
    assert "psql --no-psqlrc --single-transaction -v ON_ERROR_STOP=1" in commands
    # The stub reports the database (still) present with the right owner: no CREATE or ALTER.
    assert not any("CREATE DATABASE" in line or "ALTER DATABASE" in line for line in commands)
    assert "env PGUSER=weeknotes_home PGDATABASE=weeknotes_home pw= passfile=set" in calls
    assert "env PGUSER=weeknotes_home PGDATABASE=postgres pw=set passfile=" in calls
    copies = list((tmp_path / "home").glob("site.pre-restore-*"))
    assert len(copies) == 1
    assert (copies[0] / "manage.py").exists()
    assert (tmp_path / "home" / "site" / "manage.py").exists()
    assert not (tmp_path / "staging").exists()
    out = capsys.readouterr().out
    assert "RESTORE_PRESERVED" in out
    assert "size including database dump: 4242 bytes" in out
    assert PASSWORD not in out


def test_failed_sql_replacement_recovers_the_safety_dump(
    tmp_path: Path, stubs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_backup(tmp_path)
    flag(tmp_path, "STUB_FAIL_RESTORE", "1")
    module = host()

    with pytest.raises(module.Failure) as failure:
        module.restore(restore_payload(tmp_path))

    message = str(failure.value)
    assert message.startswith("Wagtail restore failed at Restore PostgreSQL dump in one transaction.")
    assert "SQL replacement committed: False; database recovery completed: True" in message
    calls = stubs.read_text()
    tail = calls[calls.index("--single-transaction -v ON_ERROR_STOP=1") :]
    assert "systemctl stop weeknotes-home\nsystemctl stop weeknotes-home-db-worker" in tail
    assert "pg_restore --single-transaction --exit-on-error --dbname=weeknotes_home" in tail
    assert "database.pre-restore.dump" in tail
    assert "systemctl restart" not in calls
    # Like the role, a failed restore leaves its staging directory.
    assert (tmp_path / "staging").exists()


def test_failure_after_the_commit_leaves_services_stopped_without_recovery(
    tmp_path: Path, stubs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_backup(tmp_path)
    flag(tmp_path, "STUB_FAIL_GRANT", "1")
    module = host()

    with pytest.raises(module.Failure, match="SQL replacement committed: True; database recovery completed: False"):
        module.restore(restore_payload(tmp_path))

    calls = stubs.read_text()
    assert "pg_restore --single-transaction" not in calls
    assert calls.rstrip().endswith("systemctl stop weeknotes-home\nsystemctl stop weeknotes-home-db-worker")


def test_failure_before_the_database_leaves_it_untouched(
    tmp_path: Path, stubs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_backup(tmp_path)
    flag(tmp_path, "STUB_FAIL_STOP", "1")
    module = host()

    with pytest.raises(module.Failure, match="failed at Stop auxiliary Wagtail units before restore"):
        module.restore(restore_payload(tmp_path))

    calls = stubs.read_text()
    assert "psql" not in calls
    assert "pg_restore" not in calls
    assert calls.count("systemctl stop") == 1


def test_incomplete_dump_refuses_before_any_service_change(tmp_path: Path, stubs: Path) -> None:
    make_backup(tmp_path, trailer=False)

    with pytest.raises(subprocess.CalledProcessError):
        host().restore(restore_payload(tmp_path))

    assert "systemctl" not in stubs.read_text()


def test_selection_latest_explicit_directory_and_missing(tmp_path: Path, stubs: Path) -> None:
    module = host()
    archive = make_backup(tmp_path)
    newer = archive.with_name("manual-2.tar.gz")
    newer.write_bytes(archive.read_bytes())
    os.utime(archive, (1, 1))
    cfg = restore_payload(tmp_path)

    assert module.select(cfg) == str(newer)
    assert module.select(dict(cfg, archive="manual-1.tar.gz")) == str(archive)
    assert module.select(dict(cfg, archive=str(archive.parent / "manual-1"))) == str(archive.parent / "manual-1")
    with pytest.raises(module.Failure, match=r"Wagtail restore archive not found: .*/nope\.tar\.gz"):
        module.select(dict(cfg, archive="nope.tar.gz"))
    with pytest.raises(module.Failure, match="No Wagtail backup archives found in"):
        module.select(dict(cfg, root=str(tmp_path / "empty")))

    # A backup directory restores without staging.
    module.restore(dict(cfg, archive=str(archive.parent / "manual-1"), dry_run=True))
    assert not (tmp_path / "staging").exists()


def test_overlapping_staging_and_site_are_refused_before_staging(tmp_path: Path, stubs: Path) -> None:
    make_backup(tmp_path)
    cfg = restore_payload(tmp_path)

    with pytest.raises(ValueError, match="disjoint"):
        host().restore(dict(cfg, staging=cfg["site_path"] + "/stage"))

    assert not Path(cfg["site_path"], "stage").exists()


def test_pgpass_escaping_matches_the_role_template() -> None:
    assert host().pgpass_line("a\\b:c") == "*:*:*:*:a\\\\b\\:c"


def test_encoded_command_runs_through_a_shell_with_the_payload_on_stdin(tmp_path: Path, stubs: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    payload = {"root": str(root), "prefix": "manual", "extension": "tar.gz", "retain": 1, "create_archive": True}
    for index in range(2):
        (root / f"manual-{index}.tar.gz").write_bytes(b"")
        os.utime(root / f"manual-{index}.tar.gz", (index + 1, index + 1))

    done = subprocess.run(
        ["bash", "-c", wagtail._command("retain")], input=json.dumps(payload) + "\n", text=True, capture_output=True
    )

    assert done.returncode == 0, done.stderr
    assert sorted(path.name for path in root.iterdir()) == ["manual-1.tar.gz"]


def test_vendored_preserver_is_the_ops_library_file() -> None:
    assert "RESTORE_PRESERVED" in (wagtail.FILES / "preserve.py").read_text()
    assert wagtail.HOST_SCRIPT.startswith("PRESERVE_SOURCE=")


def test_an_absent_database_is_created_with_its_owner_and_not_dropped(tmp_path: Path, stubs: Path) -> None:
    make_backup(tmp_path)
    flag(tmp_path, "STUB_ABSENT", "1")

    host().restore(restore_payload(tmp_path))

    commands = stubs.read_text().splitlines()
    assert not any("DROP DATABASE" in line for line in commands)
    assert (
        'psql --no-psqlrc -At -v ON_ERROR_STOP=1 --command=CREATE DATABASE "weeknotes_home" OWNER "weeknotes_home"'
        in commands
    )


def test_a_missing_site_directory_is_refused_before_any_unit_stops(tmp_path: Path, stubs: Path) -> None:
    make_backup(tmp_path)
    payload = restore_payload(tmp_path, site_path=str(tmp_path / "home" / "absent"))
    module = host()

    with pytest.raises(module.Failure, match=r"Wagtail site directory not found: .*absent; nothing was stopped"):
        module.restore(payload)

    calls = stubs.read_text()
    assert "systemctl" not in calls
    assert "psql" not in calls


def test_an_unknown_unit_fails_the_backup_as_the_systemd_module_does(tmp_path: Path, stubs: Path) -> None:
    flag(tmp_path, "STUB_LOAD", "not-found")
    module = host()

    with pytest.raises(module.Failure, match="Could not find the requested service weeknotes-home"):
        module.backup(backup_payload(tmp_path / "a", stop_service=True))

    assert "pg_dump" not in stubs.read_text()


def test_an_unreadable_unit_stops_the_backup_before_the_dump(tmp_path: Path, stubs: Path) -> None:
    flag(tmp_path, "STUB_FAIL_SHOW", "1")
    module = host()

    with pytest.raises(module.Failure, match="Service is in unknown state: weeknotes-home"):
        module.backup(backup_payload(tmp_path / "a", stop_service=True))

    assert "pg_dump" not in stubs.read_text()


def test_only_the_restore_refuses_a_line_break_in_the_password() -> None:
    secrets = SecretValues(REF, {"postgres_password": "line\nbreak"})

    assert wagtail._passwords(secrets, "backup") == ("line\nbreak", "line\nbreak")
    with pytest.raises(DeployError, match="cannot contain line breaks"):
        wagtail._passwords(secrets, "restore")
