"""The SQLite backups of work_app and nyxmon run against a real ``sqlite3``.

The scripts run locally: ``sh`` for the work_app step (pyinfra's shell, dash
on Ubuntu), ``bash`` for nyxmon's ``backup.sh``. ``systemctl`` is a recording
stub, ``chown``/``stat`` are stubs for the non-root run, and where a case needs
an exact integrity output or a failing ``.backup`` a ``sqlite3`` wrapper hands
everything else to the real one. A second process holds the database's
exclusive lock to stand in for a committing writer.
"""

from __future__ import annotations

import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ops_deploy.services._lifecycle import script
from ops_deploy.services.nyxmon.lifecycle import FILES, SQLITE_BACKUP_SETTINGS, START_ORDER, STOP_ORDER
from ops_deploy.services.work_app.backup import WorkAppBackupConfig, _sqlite_script

SQLITE3 = shutil.which("sqlite3")
pytestmark = pytest.mark.skipif(SQLITE3 is None, reason="needs the sqlite3 CLI")
LOCK_SECONDS = 3
HOLD_LOCK = """
import sqlite3, sys, time
conn = sqlite3.connect(sys.argv[1], isolation_level=None)
conn.execute("BEGIN EXCLUSIVE")
conn.execute("INSERT INTO t(v) VALUES ('written-under-the-lock')")
print("locked", flush=True)
time.sleep(float(sys.argv[2]))
conn.execute("COMMIT")
"""


def make_db(path: Path) -> Path:
    conn = sqlite3.connect(path)
    conn.executescript("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); CREATE INDEX tv ON t(v);")
    conn.executemany("INSERT INTO t(v) VALUES (?)", [(f"value-{i:04d}",) for i in range(300)])
    conn.commit()
    conn.close()
    return path


def corrupt(path: Path) -> Path:
    """Point the index at the table's pages: ``.backup`` still copies it, the check reports errors."""

    conn = sqlite3.connect(path)
    table_root = conn.execute("SELECT rootpage FROM sqlite_master WHERE name = 't'").fetchone()[0]
    conn.execute("PRAGMA writable_schema = ON")
    conn.execute("UPDATE sqlite_master SET rootpage = ? WHERE name = 'tv'", (table_root,))
    conn.commit()
    conn.close()
    return path


def rows(path: Path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return [v for (v,) in conn.execute("SELECT v FROM t ORDER BY id")]
    finally:
        conn.close()


def integrity(path: Path) -> str:
    assert SQLITE3 is not None
    return subprocess.run([SQLITE3, str(path), "PRAGMA integrity_check;"], capture_output=True, text=True).stdout


def stubs(
    tmp_path: Path,
    *,
    integrity_output: str | None = None,
    failing_backups: int = 0,
    failing_from: int | None = None,
    partial: Path | None = None,
) -> dict[str, str]:
    """PATH with the stubs first.

    The first ``failing_backups`` ``.backup`` calls, and every call from the
    ``failing_from``-th on, fail as locked; such a call leaves an empty
    ``partial`` file behind, as a real sqlite3 can.
    """

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "systemctl.log"
    stub = {
        "systemctl": f'echo "$*" >> {calls}\n',
        "chown": "exit 0\n",
        "stat": "echo stub\n",
    }
    if integrity_output is not None or failing_backups or failing_from:
        counter = tmp_path / "backup-calls"
        lines = ['case "$*" in']
        if integrity_output is not None:
            lines.append(f"  *integrity_check*) printf '%s\\n' {shlex.quote(integrity_output)}; exit 0 ;;")
        lines += [
            f"  *.backup*) n=$(( $(cat {counter} 2>/dev/null || echo 0) + 1 )); echo $n > {counter}",
            f"    if [ $n -le {failing_backups} ] || [ $n -ge {failing_from or 1_000_000} ]; then",
            f"      {f': > {partial}; ' if partial else ''}echo 'Error: database is locked' >&2; exit 5",
            "    fi ;;",
            "esac",
            f'exec {SQLITE3} "$@"',
        ]
        stub["sqlite3"] = "\n".join(lines) + "\n"
    for name, body in stub.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}")
        path.chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


def systemctl_calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "systemctl.log"
    return log.read_text().splitlines() if log.exists() else []


class LockHolder:
    """Another process in an exclusive transaction that commits after ``seconds``."""

    def __init__(self, db: Path, seconds: float) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-c", HOLD_LOCK, str(db), str(seconds)], stdout=subprocess.PIPE, text=True
        )
        assert self.process.stdout is not None
        assert self.process.stdout.readline().strip() == "locked"

    def __enter__(self) -> LockHolder:
        return self

    def __exit__(self, *exc: object) -> None:
        assert self.process.wait(timeout=60) == 0


def assert_really_locked(db: Path, tmp_path: Path) -> None:
    """Control: without ``.timeout`` the same backup fails at once."""

    assert SQLITE3 is not None
    control = subprocess.run([SQLITE3, str(db), f".backup '{tmp_path / 'control.db'}'"], capture_output=True, text=True)
    assert control.returncode != 0
    assert "locked" in (control.stderr + control.stdout)


# work_app -----------------------------------------------------------------


def work_app(
    tmp_path: Path, env: dict[str, str], *, sqlite_retries: int = 3, force_stop: bool = False
) -> subprocess.CompletedProcess[str]:
    cfg = WorkAppBackupConfig(
        database_path=str(tmp_path / "db.sqlite3"), sqlite_retries=sqlite_retries, force_stop=force_stop
    )
    command = _sqlite_script(cfg, str(tmp_path / "copy.sqlite3"), str(tmp_path / ".mode"))
    return subprocess.run(["sh", "-c", command], capture_output=True, text=True, env=env, timeout=120)


def mode(tmp_path: Path) -> str | None:
    marker = tmp_path / ".mode"
    return marker.read_text().strip() if marker.exists() else None


def test_work_app_waits_for_a_writer_instead_of_stopping_the_service(tmp_path: Path) -> None:
    db = make_db(tmp_path / "db.sqlite3")
    env = stubs(tmp_path)

    with LockHolder(db, LOCK_SECONDS):
        assert_really_locked(db, tmp_path)
        started = time.monotonic()
        result = work_app(tmp_path, env)
        waited = time.monotonic() - started

    assert result.returncode == 0, result.stderr
    assert waited >= LOCK_SECONDS - 1  # the busy handler waited for the commit
    assert "attempt" not in result.stderr  # first attempt, no retry
    assert mode(tmp_path) == "hot"
    assert systemctl_calls(tmp_path) == []  # no service interruption
    assert rows(tmp_path / "copy.sqlite3")[-1] == "written-under-the-lock"
    assert integrity(tmp_path / "copy.sqlite3").strip() == "ok"


def test_work_app_corrupt_hot_copy_fails_without_an_offline_copy(tmp_path: Path) -> None:
    corrupt(make_db(tmp_path / "db.sqlite3"))

    result = work_app(tmp_path, stubs(tmp_path), sqlite_retries=2)

    assert result.returncode != 0
    assert "integrity check of" in result.stderr
    assert "attempt 2/2 failed" in result.stderr
    assert "no offline copy" in result.stderr
    assert systemctl_calls(tmp_path) == []  # the service is not stopped for a hopeless copy
    assert not (tmp_path / "copy.sqlite3").exists()
    assert mode(tmp_path) is None


def test_work_app_failed_check_then_failed_backup_leaves_no_partial_copy(tmp_path: Path) -> None:
    corrupt(make_db(tmp_path / "db.sqlite3"))
    env = stubs(tmp_path, failing_from=2, partial=tmp_path / "copy.sqlite3")

    result = work_app(tmp_path, env, sqlite_retries=2)

    assert result.returncode != 0
    assert "integrity check of" in result.stderr  # attempt 1: the copy fails its check
    assert "database is locked" in result.stderr  # attempt 2: the backup fails, leaving a partial file
    assert "no offline copy" in result.stderr
    assert systemctl_calls(tmp_path) == []
    assert not (tmp_path / "copy.sqlite3").exists()
    assert mode(tmp_path) is None


@pytest.mark.parametrize("printed", ["broken", "ok ok", "not ok", "OK", ""])
def test_work_app_integrity_output_must_be_exactly_ok(tmp_path: Path, printed: str) -> None:
    make_db(tmp_path / "db.sqlite3")

    result = work_app(tmp_path, stubs(tmp_path, integrity_output=printed), sqlite_retries=1)

    assert result.returncode != 0
    assert not (tmp_path / "copy.sqlite3").exists()
    assert mode(tmp_path) is None
    assert systemctl_calls(tmp_path) == []


def test_work_app_falls_back_to_the_offline_copy_and_checks_it(tmp_path: Path) -> None:
    make_db(tmp_path / "db.sqlite3")

    result = work_app(tmp_path, stubs(tmp_path, failing_backups=99), sqlite_retries=1)

    assert result.returncode == 0, result.stderr
    assert "attempt 1/1 failed" in result.stderr
    assert systemctl_calls(tmp_path) == ["stop work-app.service", "start work-app.service"]
    assert mode(tmp_path) == "offline"
    assert integrity(tmp_path / "copy.sqlite3").strip() == "ok"


def test_work_app_offline_copy_that_fails_its_check_fails_after_the_start(tmp_path: Path) -> None:
    corrupt(make_db(tmp_path / "db.sqlite3"))

    result = work_app(tmp_path, stubs(tmp_path), force_stop=True)

    assert result.returncode != 0
    assert "integrity check of" in result.stderr
    assert systemctl_calls(tmp_path) == ["stop work-app.service", "start work-app.service"]
    assert not (tmp_path / "copy.sqlite3").exists()
    assert mode(tmp_path) is None


# nyxmon -------------------------------------------------------------------


def nyxmon(
    tmp_path: Path, env: dict[str, str], *, stop: bool = False, delay: str = "0"
) -> subprocess.CompletedProcess[str]:
    values = {
        "REQUIRED_MOUNT": "",
        "RECORD": "0",
        "ROOT": str(tmp_path / "backups"),
        "DIR": str(tmp_path / "backups" / "manual"),
        "DB": str(tmp_path / "db.sqlite3"),
        "STOP": "1" if stop else "0",
        "SQLITE_BACKUP": "1",
        "DELETE": "0",
        **SQLITE_BACKUP_SETTINGS,
        "SQLITE_RETRY_DELAY": delay,
        "STOP_ORDER": STOP_ORDER,
        "START_ORDER": START_ORDER,
        "DIRS": ("0:/nonexistent:media",),
        "COPIES": ("0600:/nonexistent:config/.env",),
    }
    command = script(FILES / "backup.sh", values)
    return subprocess.run(["bash", "-c", command], capture_output=True, text=True, env=env, timeout=120)


def nyxmon_copy(tmp_path: Path) -> Path:
    return tmp_path / "backups" / "manual" / "database" / "db.sqlite3"


def test_nyxmon_settings_follow_the_library() -> None:
    assert SQLITE_BACKUP_SETTINGS == {"SQLITE_TIMEOUT_MS": "30000", "SQLITE_ATTEMPTS": "3", "SQLITE_RETRY_DELAY": "5"}


def test_nyxmon_waits_for_a_writer(tmp_path: Path) -> None:
    db = make_db(tmp_path / "db.sqlite3")
    env = stubs(tmp_path)

    with LockHolder(db, LOCK_SECONDS):
        assert_really_locked(db, tmp_path)
        started = time.monotonic()
        result = nyxmon(tmp_path, env)
        waited = time.monotonic() - started

    assert result.returncode == 0, result.stderr
    assert waited >= LOCK_SECONDS - 1
    assert "attempt" not in result.stderr
    assert rows(nyxmon_copy(tmp_path))[-1] == "written-under-the-lock"
    assert integrity(nyxmon_copy(tmp_path)).strip() == "ok"


def test_nyxmon_retries_a_failed_backup(tmp_path: Path) -> None:
    make_db(tmp_path / "db.sqlite3")

    result = nyxmon(tmp_path, stubs(tmp_path, failing_backups=2))

    assert result.returncode == 0, result.stderr
    assert "attempt 1/3 failed" in result.stderr
    assert "attempt 2/3 failed" in result.stderr
    assert "attempt 3/3" not in result.stderr
    assert integrity(nyxmon_copy(tmp_path)).strip() == "ok"


def test_nyxmon_gives_up_after_three_attempts(tmp_path: Path) -> None:
    make_db(tmp_path / "db.sqlite3")

    env = stubs(tmp_path, failing_backups=99, partial=nyxmon_copy(tmp_path))

    result = nyxmon(tmp_path, env, stop=True)

    assert result.returncode != 0
    assert "attempt 3/3 failed" in result.stderr
    assert not nyxmon_copy(tmp_path).exists()
    # The services start again whatever failed (the role's ``always``).
    assert systemctl_calls(tmp_path)[-4:] == [
        "daemon-reload",
        "start nyxmon.service",
        "daemon-reload",
        "start nyxmon-monitor.service",
    ]


def test_nyxmon_corrupt_copy_fails_closed(tmp_path: Path) -> None:
    corrupt(make_db(tmp_path / "db.sqlite3"))

    result = nyxmon(tmp_path, stubs(tmp_path), stop=True)

    assert result.returncode != 0
    assert "integrity check:" in result.stderr
    assert "attempt 3/3 failed" in result.stderr
    assert not nyxmon_copy(tmp_path).exists()
    assert systemctl_calls(tmp_path) == [
        "daemon-reload",
        "stop nyxmon-monitor.service",
        "daemon-reload",
        "stop nyxmon.service",
        "daemon-reload",
        "start nyxmon.service",
        "daemon-reload",
        "start nyxmon-monitor.service",
    ]


@pytest.mark.parametrize("printed", ["broken", "ok ok", "not ok", "OK", ""])
def test_nyxmon_integrity_output_must_be_exactly_ok(tmp_path: Path, printed: str) -> None:
    make_db(tmp_path / "db.sqlite3")

    result = nyxmon(tmp_path, stubs(tmp_path, integrity_output=printed))

    assert result.returncode != 0
    assert "attempt 3/3 failed" in result.stderr
    assert not nyxmon_copy(tmp_path).exists()
