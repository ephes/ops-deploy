"""PostfixAdmin backup and restore: planned operations and the host program end to end.

The host program runs locally against a fake ``psql`` that answers the
queries from fixture rows and records the restore's SQL; ``php`` and
``systemctl`` are recording fakes too. One round trip runs against a
throwaway local PostgreSQL when ``initdb`` is installed. No real credentials.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.services.postfixadmin import (
    PostfixAdminBackupConfig,
    PostfixAdminRestoreConfig,
    deploy_postfixadmin_backup,
    deploy_postfixadmin_restore,
)
from ops_deploy.services.postfixadmin.backup_restore import FILES
from ops_deploy.testing import FakeRun, run_deploy_fake

PASSWORD = "fixture-db-password"  # pragma: allowlist secret
STAMP = "20261104T120000"
ADMINS = [
    {"username": "admin@example.org", "password": "{BLF-CRYPT}fixture", "superadmin": True, "totp_secret": None},
    {"username": "b@example.org", "password": "{BLF-CRYPT}other", "superadmin": False, "totp_secret": "FIXTURE"},
]
DOMAIN_ADMINS = [
    {"username": "b@example.org", "domain": "example.org", "active": True, "created": "2026-01-01T00:00:00"}
]
COLUMNS = ["username", "password", "superadmin", "totp_secret", "created", "modified", "active"]

# The program gives psql only PATH, PGPASSWORD and PGCONNECT_TIMEOUT: the fake
# reads its fixtures and writes its log next to itself.
FAKE_PSQL = r"""#!PYTHON
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
sql = sys.stdin.read()
with open(os.path.join(here, "..", "psql.log"), "a") as out:
    entry = {"argv": sys.argv[1:], "sql": sql, "password": os.environ.get("PGPASSWORD"), "env": sorted(os.environ)}
    out.write(json.dumps(entry) + "\n")
with open(os.path.join(here, "fixtures.json")) as handle:
    fixtures = json.load(handle)
with open(os.path.join(here, "fail")) as handle:
    fail = handle.read()
if fail and fail in sql:
    print("ERROR: fixture failure", file=sys.stderr)
    sys.exit(3)
for key, value in fixtures.items():
    if key in sql:
        print(json.dumps(value))
        break
"""


def fixtures(**override: Any) -> dict[str, Any]:
    return {
        "FROM admin ORDER BY username": ADMINS,
        "FROM domain_admins ORDER BY": DOMAIN_ADMINS,
        "FROM config WHERE name": [{"value": "1849"}],
        "FROM log ORDER BY": [{"action": "login", "timestamp": "2026-11-01T10:00:00"}],
        "information_schema.columns": [{"column_name": name} for name in COLUMNS],
        **override,
    }


@pytest.fixture
def host(tmp_path: Path) -> dict[str, Any]:
    bins = tmp_path / "bin"
    bins.mkdir()
    psql = bins / "psql"
    psql.write_text(FAKE_PSQL.replace("#!PYTHON", "#!" + sys.executable))
    psql.chmod(0o755)
    for name, body in (("php", "printf 8.3"), ("systemctl", 'printf "systemctl %s\\n" "$*" >>"$CALLS"')):
        (bins / name).write_text(f"#!/bin/bash\n{body}\n")
        (bins / name).chmod(0o755)
    install = tmp_path / "postfixadmin"
    (install / "templates_c").mkdir(parents=True)
    (install / "config.local.php").write_text("<?php $CONF['configured'] = true;\n")
    (install / "templates_c" / "x.tpl.php").write_text("compiled\n")
    return {
        "bins": bins,
        "root": tmp_path / "backups",
        "install": install,
        "log": tmp_path / "psql.log",
        "calls": tmp_path / "calls.log",
        "user": pwd.getpwuid(os.getuid()).pw_name,
        "group": grp.getgrgid(os.getgid()).gr_name,
    }


def run_program(
    host: dict[str, Any], settings: dict[str, Any], *, rows: dict[str, Any] | None = None, fail: str = ""
) -> subprocess.CompletedProcess[str]:
    base = {
        "install_path": str(host["install"]),
        "db_host": "localhost",
        "db_port": 5432,
        "db_name": "mail",
        "db_user": "mail",
        "db_password": PASSWORD,
        "root": str(host["root"]),
        "root_owner": [os.getuid(), os.getgid()],
        "config_owner": host["user"],
    }
    (host["bins"] / "fixtures.json").write_text(json.dumps(rows or fixtures()))
    (host["bins"] / "fail").write_text(fail)
    return subprocess.run(
        [sys.executable, "-I", str(FILES / "postfixadmin_lifecycle.py")],
        input=json.dumps({**base, **settings}),
        capture_output=True,
        text=True,
        env={"PATH": f"{host['bins']}:{os.environ['PATH']}", "CALLS": str(host["calls"])},
    )


def backup_settings(**extra: Any) -> dict[str, Any]:
    return {
        "action": "backup",
        "stamp": STAMP,
        "created_at": "2026-11-04T11:00:00Z",
        "host_name": "macmini",
        "postfixadmin_version": "4.0.5",
        "include_templates_c": False,
        "retention_days": 14,
        "keep_min": 5,
        **extra,
    }


def restore_settings(host: dict[str, Any], manifest: Any, **extra: Any) -> dict[str, Any]:
    return {
        "action": "restore",
        "stamp": STAMP,
        "dry_run": False,
        "manifest": json.dumps(manifest),
        "restore_config": True,
        "restore_admin_tables": True,
        "restore_templates_c": False,
        "php_version": "",
        "web_user": host["user"],
        "web_group": host["group"],
        "templates_c_path": str(host["install"] / "templates_c"),
        **extra,
    }


def psql_calls(host: dict[str, Any]) -> list[dict[str, Any]]:
    return [json.loads(line) for line in host["log"].read_text().splitlines()] if host["log"].exists() else []


# -- planned operations ---------------------------------------------------------


def test_backup_sends_the_password_only_on_stdin() -> None:
    cfg = PostfixAdminBackupConfig(host_name="macmini", db_password=PASSWORD, required_mount="/mnt/cryptdata")

    result = run_deploy_fake(
        deploy_postfixadmin_backup,
        cfg,
        responses={"date +%Y%m%dT%H%M%S": [f"{STAMP}\n2026-11-04T11:00:00Z"]},
    )

    assert result.succeeded, result.error
    assert all(PASSWORD not in command for command in result.executed_commands)
    (_command, payload) = next(item for item in result.stdin if "python3 -I -c" in item[0])
    settings = json.loads(payload)
    assert settings["db_password"] == PASSWORD
    assert settings["stamp"] == STAMP
    assert settings["root"] == "/mnt/cryptdata/backups/postfixadmin"
    assert any(
        "require_mount /mnt/cryptdata /mnt/cryptdata/backups/postfixadmin" in c for c in result.executed_commands
    )
    assert "password" not in repr(cfg).lower() or "**********" in repr(cfg)


def test_restore_dry_run_reads_no_manifest() -> None:
    cfg = PostfixAdminRestoreConfig(db_password=PASSWORD, dry_run=True)

    result: FakeRun = run_deploy_fake(deploy_postfixadmin_restore, cfg)

    assert result.succeeded, result.error
    assert result.changed_ops == ["PostfixAdmin restore | Restore PostfixAdmin (dry run)"]
    (_, payload) = next(item for item in result.stdin if "python3 -I -c" in item[0])
    assert json.loads(payload)["dry_run"] is True


@pytest.mark.parametrize("archive", ["../x", "/abs", "2026", "20261104T12000"])
def test_restore_archive_is_latest_or_a_timestamp(archive: str) -> None:
    with pytest.raises(ValidationError):
        PostfixAdminRestoreConfig(db_password=PASSWORD, archive=archive)


def test_backup_retention_must_keep_something() -> None:
    with pytest.raises(ValidationError):
        PostfixAdminBackupConfig(host_name="m", db_password=PASSWORD, keep_min=0)


# -- the host program -----------------------------------------------------------


def test_backup_writes_the_role_directory_and_manifest(host: dict[str, Any]) -> None:
    done = run_program(host, backup_settings())

    assert done.returncode == 0, done.stderr
    directory = host["root"] / STAMP
    assert sorted(path.name for path in directory.iterdir()) == [
        "admin.json",
        "config.local.php",
        "domain_admins.json",
        "log.json",
        "manifest.yml",
    ]
    assert json.loads((directory / "admin.json").read_text()) == ADMINS
    assert (directory / "admin.json").read_text().startswith('[\n    {\n        "password"')
    assert (directory / "admin.json").stat().st_mode & 0o777 == 0o600
    manifest = yaml.safe_load((directory / "manifest.yml").read_text())
    assert manifest["contents"] == ["admin.json", "config.local.php", "domain_admins.json", "log.json"]
    assert manifest["db_schema_version"] == 1849
    assert manifest["backup_type"] == "postfixadmin"
    assert not (host["root"] / f"{STAMP}.tmp").exists()
    assert all(call["password"] == PASSWORD for call in psql_calls(host))
    assert all(PASSWORD not in " ".join(call["argv"]) for call in psql_calls(host))
    # Nothing else from the program's environment (macOS adds __CF_*, Python the coerced LC_CTYPE).
    for call in psql_calls(host):
        assert {name for name in call["env"] if not name.startswith("__CF") and name != "LC_CTYPE"} == {
            "PATH",
            "PGCLIENTENCODING",
            "PGCONNECT_TIMEOUT",
            "PGPASSWORD",
        }


def test_backup_without_an_admin_publishes_nothing(host: dict[str, Any]) -> None:
    done = run_program(host, backup_settings(), rows=fixtures(**{"FROM admin ORDER BY username": []}))

    assert done.returncode == 1
    assert "admin table is empty" in done.stderr
    assert list(host["root"].iterdir()) == []


def test_backup_skips_a_failing_log_part_with_a_warning(host: dict[str, Any]) -> None:
    done = run_program(host, backup_settings(include_templates_c=True), fail="FROM log")

    assert done.returncode == 0, done.stderr
    assert "WARNING: optional part not backed up: log.json" in done.stdout
    manifest = yaml.safe_load((host["root"] / STAMP / "manifest.yml").read_text())
    assert "log.json" not in manifest["contents"]
    assert "templates_c.tar.gz" in manifest["contents"]
    assert manifest["skipped"][0].startswith("log.json: ")


def test_backup_refuses_an_existing_directory_and_prunes_only_old_extras(host: dict[str, Any]) -> None:
    host["root"].mkdir()
    old = []
    for day in range(1, 8):
        path = host["root"] / f"202610{day:02d}T000000"
        path.mkdir()
        os.utime(path, (1_000_000, 1_000_000))
        old.append(path)
    (host["root"] / "migration").mkdir()

    done = run_program(host, backup_settings())

    assert done.returncode == 0, done.stderr
    left = sorted(path.name for path in host["root"].iterdir())
    # The newest five completed backups stay; the two oldest go; other names stay.
    assert left == ["20261004T000000", "20261005T000000", "20261006T000000", "20261007T000000", STAMP, "migration"]
    again = run_program(host, backup_settings())
    assert again.returncode == 1
    assert "already exists" in again.stderr


def make_backup(host: dict[str, Any]) -> dict[str, Any]:
    done = run_program(host, backup_settings())
    assert done.returncode == 0, done.stderr
    host["log"].unlink()
    manifest: dict[str, Any] = yaml.safe_load((host["root"] / STAMP / "manifest.yml").read_text())
    return manifest


def test_restore_upserts_in_one_transaction_and_restarts_php_on_a_changed_config(host: dict[str, Any]) -> None:
    manifest = make_backup(host)
    (host["install"] / "config.local.php").write_text("<?php changed\n")

    done = run_program(host, restore_settings(host, manifest))

    assert done.returncode == 0, done.stderr
    assert (host["install"] / "config.local.php").read_text() == "<?php $CONF['configured'] = true;\n"
    assert (host["install"] / "config.local.php").stat().st_mode & 0o777 == 0o640
    writes = [call for call in psql_calls(host) if "BEGIN;" in call["sql"]]
    assert len(writes) == 1
    sql = writes[0]["sql"]
    assert sql.count("INSERT INTO admin") == 2
    assert 'ON CONFLICT (username) DO UPDATE SET "password" = EXCLUDED."password"' in sql
    assert sql.count("INSERT INTO domain_admins") == 1
    assert sql.rstrip().endswith("COMMIT;")
    # Row data (hashes, TOTP secrets) travels in the SQL on stdin, never on psql's command line.
    for call in psql_calls(host):
        argv = " ".join(call["argv"])
        assert PASSWORD not in argv
        assert "BLF-CRYPT" not in argv
        assert "FIXTURE" not in argv
    assert "{BLF-CRYPT}other" in sql
    assert host["calls"].read_text().splitlines() == ["systemctl restart php8.3-fpm"]


def test_restore_with_an_unchanged_config_restarts_nothing(host: dict[str, Any]) -> None:
    manifest = make_backup(host)

    done = run_program(host, restore_settings(host, manifest))

    assert done.returncode == 0, done.stderr
    assert not host["calls"].exists()


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda m: {**m, "backup_type": "other"}, "not a usable PostfixAdmin manifest"),
        (lambda m: {**m, "contents": ["admin.json"]}, "not a usable PostfixAdmin manifest"),
        (lambda m: {**m, "db_schema_version": 9999}, "schema version 9999"),
        (lambda m: {**m, "timestamp": "20260101T000000"}, "changed while the restore was prepared"),
        (lambda m: None, "not a usable PostfixAdmin manifest"),
    ],
)
def test_restore_validates_before_any_change(host: dict[str, Any], edit: Any, message: str) -> None:
    manifest = make_backup(host)
    (host["install"] / "config.local.php").write_text("<?php changed\n")

    done = run_program(host, restore_settings(host, edit(manifest)))

    assert done.returncode == 1
    assert message in done.stderr
    assert (host["install"] / "config.local.php").read_text() == "<?php changed\n"
    assert not [call for call in psql_calls(host) if "BEGIN;" in call["sql"]]


def test_restore_refuses_columns_the_target_lacks(host: dict[str, Any]) -> None:
    manifest = make_backup(host)
    narrow = fixtures(**{"information_schema.columns": [{"column_name": "username"}, {"column_name": "password"}]})

    done = run_program(host, restore_settings(host, manifest), rows=narrow)

    assert done.returncode == 1
    assert "only columns the target's admin table has" in done.stderr


def test_restore_latest_and_dry_run(host: dict[str, Any]) -> None:
    make_backup(host)
    (host["root"] / "20261104T120000.tmp").mkdir()

    done = run_program(host, restore_settings(host, None, stamp="latest", dry_run=True))

    assert done.returncode == 0, done.stderr
    assert f"{STAMP} exists; nothing changed" in done.stdout
    assert not host["log"].exists()
    empty = run_program(host, restore_settings(host, None, stamp="latest", root=str(host["root"] / "none")))
    assert "No PostfixAdmin backups found" in empty.stderr


# -- against a real PostgreSQL --------------------------------------------------

PG_BIN = next(
    (
        Path(p)
        for p in ("/usr/lib/postgresql/17/bin", "/usr/lib/postgresql/16/bin", "/opt/homebrew/opt/postgresql@17/bin")
        if Path(p, "initdb").exists()
    ),
    None,
)
SCHEMA = """
CREATE TABLE admin (
    username varchar(255) PRIMARY KEY, password varchar(255) NOT NULL, superadmin boolean NOT NULL DEFAULT false,
    created timestamp with time zone NOT NULL DEFAULT now(), modified timestamp with time zone NOT NULL DEFAULT now(),
    active boolean NOT NULL DEFAULT true, totp_secret varchar(255)
);
CREATE TABLE domain_admins (
    username varchar(255) NOT NULL, domain varchar(255) NOT NULL, created timestamp NOT NULL DEFAULT now(),
    active boolean NOT NULL DEFAULT true
);
CREATE TABLE config (id serial PRIMARY KEY, name varchar(20) UNIQUE, value varchar(20));
CREATE TABLE log ("timestamp" timestamp NOT NULL DEFAULT now(), username varchar(255), action varchar(255));
INSERT INTO config (name, value) VALUES ('version', '1851');
INSERT INTO admin (username, password, superadmin, totp_secret)
    VALUES ('admin@example.org', '{BLF-CRYPT}original', true, NULL),
           ('b@example.org', 'it''s $1$x :name \\ "q"', false, 'TOTP1');
INSERT INTO domain_admins (username, domain) VALUES ('b@example.org', 'example.org');
INSERT INTO log (username, action) VALUES ('admin@example.org', 'login');
"""


@pytest.fixture
def postgres(tmp_path: Path) -> Any:
    if PG_BIN is None:
        pytest.skip("needs PostgreSQL 16 or 17 (initdb, pg_ctl)")
    import shutil as _shutil
    import socket
    import tempfile

    data = tmp_path / "pg"
    # Unix socket paths are limited to about 100 bytes: a short directory.
    sock = Path(tempfile.mkdtemp(prefix="pfa-", dir="/tmp"))
    pwfile = tmp_path / "pw"
    pwfile.write_text(PASSWORD + "\n")
    subprocess.run(
        [
            PG_BIN / "initdb",
            "-D",
            data,
            "-U",
            "postgres",
            "--auth-local=trust",
            "--auth-host=scram-sha-256",
            "--pwfile",
            pwfile,
            "-E",
            "UTF8",
        ],
        check=True,
        capture_output=True,
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    subprocess.run(
        [
            PG_BIN / "pg_ctl",
            "-D",
            data,
            "-w",
            "-l",
            tmp_path / "pg.log",
            "-o",
            f"-p {port} -k {sock} -c listen_addresses=localhost -c shared_memory_type=mmap",
            "start",
        ],
        check=True,
        capture_output=True,
    )

    def sql(text: str, db: str = "mail", user: str = "postgres") -> str:
        done = subprocess.run(
            [PG_BIN / "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-h", sock, "-p", str(port), "-U", user, "-d", db],
            input=text,
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout

    try:
        sql(f"CREATE ROLE mail LOGIN PASSWORD '{PASSWORD}'; CREATE DATABASE mail OWNER mail;", db="postgres")
        sql("SET ROLE mail;" + SCHEMA)
        yield {"port": port, "sql": sql}
    finally:
        subprocess.run([PG_BIN / "pg_ctl", "-D", data, "-m", "fast", "stop"], capture_output=True)
        _shutil.rmtree(sock, ignore_errors=True)


def test_backup_and_restore_round_trip_on_postgresql(host: dict[str, Any], postgres: Any) -> None:
    # The real psql, as the mail user over localhost with the password.
    (host["bins"] / "psql").unlink()
    (host["bins"] / "psql").symlink_to(PG_BIN / "psql")  # type: ignore[operator]

    done = run_program(host, {**backup_settings(), "db_port": postgres["port"]})
    assert done.returncode == 0, done.stderr
    directory = host["root"] / STAMP
    admins = json.loads((directory / "admin.json").read_text())
    assert [row["username"] for row in admins] == ["admin@example.org", "b@example.org"]
    assert admins[1]["password"] == 'it\'s $1$x :name \\ "q"'
    assert admins[0]["superadmin"] is True
    manifest = yaml.safe_load((directory / "manifest.yml").read_text())
    assert manifest["db_schema_version"] == 1851

    postgres["sql"](
        "SET ROLE mail; UPDATE admin SET password = 'changed', totp_secret = NULL; "
        "DELETE FROM domain_admins; DELETE FROM admin WHERE username = 'admin@example.org';"
    )
    done = run_program(host, {**restore_settings(host, manifest), "db_port": postgres["port"]})

    assert done.returncode == 0, done.stderr
    rows = postgres["sql"]("SELECT username, password, superadmin, coalesce(totp_secret, '-') FROM admin ORDER BY 1;")
    assert rows.splitlines() == [
        "admin@example.org|{BLF-CRYPT}original|t|-",
        'b@example.org|it\'s $1$x :name \\ "q"|f|TOTP1',
    ]
    assert (
        postgres["sql"]("SELECT username, domain, active FROM domain_admins;").strip() == "b@example.org|example.org|t"
    )
    # A second restore changes nothing and adds no duplicate domain_admins row.
    done = run_program(host, {**restore_settings(host, manifest), "db_port": postgres["port"]})
    assert done.returncode == 0, done.stderr
    assert postgres["sql"]("SELECT count(*) FROM domain_admins;").strip() == "1"
