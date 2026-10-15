"""The scripts echoport runs on the host, executed here against stand-ins.

``crontab`` is a small shell script over a file; Nyxmon's database is a real
SQLite file with the two tables the check touches.
"""

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.echoport import deploy as echoport

FAKE_CRONTAB = """#!/bin/sh
# usage: crontab -l -u USER | crontab -u USER -
store="$FAKE_CRONTAB_FILE"
if [ "$1" = "-l" ]; then
    [ -f "$store" ] || { echo "no crontab for $3" >&2; exit 1; }
    cat "$store"
elif [ "$3" = "-" ]; then
    cat > "$store"
else
    exit 2
fi
"""
JOB = (
    "cd /home/echoport/site && DJANGO_SETTINGS_MODULE=config.settings.production python manage.py run_scheduled_backups"
)
SCHEDULED = {
    "user": "echoport",
    "name": "Echoport scheduled backups",
    "state": "present",
    "minute": "*/5",
    "hour": "*",
    "job": JOB,
}
CLEANUP = {**SCHEDULED, "name": "Echoport cleanup old backups", "minute": "0", "hour": "3", "job": "cleanup"}


@pytest.fixture
def crontab(tmp_path: Path) -> Path:
    binary = tmp_path / "bin" / "crontab"
    binary.parent.mkdir()
    binary.write_text(FAKE_CRONTAB)
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    return tmp_path


def edit(root: Path, params: dict[str, Any], *, apply: bool) -> str:
    env = {**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}", "FAKE_CRONTAB_FILE": str(root / "crontab")}
    result = subprocess.run(
        [sys.executable, "-I", "-c", echoport.CRON_EDIT, json.dumps({**params, "apply": apply})],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_a_job_is_added_with_ansibles_header(crontab: Path) -> None:
    assert edit(crontab, SCHEDULED, apply=False) == "pending"
    assert not (crontab / "crontab").exists()
    assert edit(crontab, SCHEDULED, apply=True) == "updated"

    assert (crontab / "crontab").read_text() == f"#Ansible: Echoport scheduled backups\n*/5 * * * * {JOB}\n"
    assert edit(crontab, SCHEDULED, apply=False) == "unchanged"


def test_other_entries_are_kept_and_the_job_is_updated_in_place(crontab: Path) -> None:
    (crontab / "crontab").write_text(
        f"MAILTO=ops\n#Ansible: Echoport scheduled backups\n*/10 * * * * {JOB}\n#Ansible: other\n1 2 * * * other\n"
    )

    assert edit(crontab, SCHEDULED, apply=True) == "updated"
    assert (crontab / "crontab").read_text() == (
        f"MAILTO=ops\n#Ansible: Echoport scheduled backups\n*/5 * * * * {JOB}\n#Ansible: other\n1 2 * * * other\n"
    )


def test_a_second_job_is_appended_after_the_first(crontab: Path) -> None:
    edit(crontab, SCHEDULED, apply=True)
    edit(crontab, CLEANUP, apply=True)

    assert (crontab / "crontab").read_text() == (
        f"#Ansible: Echoport scheduled backups\n*/5 * * * * {JOB}\n"
        "#Ansible: Echoport cleanup old backups\n0 3 * * * cleanup\n"
    )
    assert edit(crontab, CLEANUP, apply=False) == "unchanged"


def test_an_identical_job_without_header_is_adopted_not_duplicated(crontab: Path) -> None:
    (crontab / "crontab").write_text(f"*/5 * * * * {JOB}\n")

    assert edit(crontab, SCHEDULED, apply=True) == "updated"
    assert (crontab / "crontab").read_text() == f"#Ansible: Echoport scheduled backups\n*/5 * * * * {JOB}\n"


def test_an_absent_job_is_removed_with_its_header(crontab: Path) -> None:
    edit(crontab, SCHEDULED, apply=True)
    edit(crontab, CLEANUP, apply=True)
    absent = {**SCHEDULED, "state": "absent"}

    assert edit(crontab, absent, apply=False) == "pending"
    assert edit(crontab, absent, apply=True) == "updated"
    assert (crontab / "crontab").read_text() == "#Ansible: Echoport cleanup old backups\n0 3 * * * cleanup\n"
    assert edit(crontab, absent, apply=False) == "unchanged"


def test_absent_without_a_crontab_changes_nothing(crontab: Path) -> None:
    assert edit(crontab, {**SCHEDULED, "state": "absent"}, apply=True) == "unchanged"
    assert not (crontab / "crontab").exists()


def nyxmon_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE service (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);
        CREATE TABLE health_check (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, service_id INTEGER, check_type TEXT, url TEXT,
            check_interval INTEGER, status TEXT, next_check_time INTEGER, processing_started_at INTEGER,
            disabled INTEGER, data TEXT
        );
        """
    )
    conn.commit()
    conn.close()


def run_nyxmon(path: Path, checks: list[dict[str, Any]], *, apply: bool) -> str:
    env = {
        "PATH": os.environ["PATH"],
        "NYXMON_DB_PATH": str(path),
        "NYXMON_SERVICE_NAME": "echoport",
        "NYXMON_CHECKS_JSON": json.dumps(checks),
        "NYXMON_APPLY": "1" if apply else "0",
    }
    result = subprocess.run(
        [sys.executable, "-I", "-c", echoport.NYXMON_CHECK], env=env, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def test_nyxmon_check_is_created_then_unchanged_then_updated(tmp_path: Path) -> None:
    db = tmp_path / "db.sqlite3"
    nyxmon_db(db)
    checks = echoport.nyxmon_checks(echoport.NyxmonCheck())

    assert run_nyxmon(db, checks, apply=False) == "changed=true"
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT count(*) FROM service").fetchone() == (0,)
    assert run_nyxmon(db, checks, apply=True) == "changed=true"
    assert conn.execute("SELECT name FROM service").fetchall() == [("echoport",)]
    [(url, interval, status, data)] = conn.execute("SELECT url, check_interval, status, data FROM health_check")
    assert (url, interval, status) == ("http://127.0.0.1:10018/api/health/", 300, "idle")
    assert json.loads(data) == checks[0]["data"]

    assert run_nyxmon(db, checks, apply=False) == "changed=false"
    assert run_nyxmon(db, checks, apply=True) == "changed=false"
    changed = [{**checks[0], "check_interval": 60}]
    assert run_nyxmon(db, changed, apply=False) == "changed=true"
    assert run_nyxmon(db, changed, apply=True) == "changed=true"
    assert conn.execute("SELECT count(*), max(check_interval) FROM health_check").fetchone() == (1, 60)
    conn.close()


def test_mc_alias_probe_prints_only_a_digest() -> None:
    stored = {"status": "success", "alias": "minio", "URL": "http://m:9001", "accessKey": "ak", "secretKey": "sk"}

    missing = {"status": "error", "error": {"message": "No such alias `minio` found."}}

    def probe(text: str, status: int = 0) -> subprocess.CompletedProcess[str]:
        argv = [sys.executable, "-I", "-c", echoport.MC_ALIAS_PROBE, str(status)]
        return subprocess.run(argv, input=text, capture_output=True, text=True)

    assert probe(json.dumps(stored)).stdout.strip() == hashlib.sha256(b"http://m:9001\nak\nsk").hexdigest()
    assert probe(json.dumps(missing), 1).stdout.strip() == "none"
    # Anything else is an error for the strict probe, not "no alias".
    for text, status in (("", 0), ("", 2), ("not json", 1), (json.dumps({"status": "error"}), 1)):
        result = probe(text, status)
        assert result.returncode != 0
        assert result.stdout == ""
