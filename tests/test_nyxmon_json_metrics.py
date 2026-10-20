"""``files/json_metrics_check.py``, the shared json-metrics upsert, run with ``python3 -I`` on real SQLite files."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services._nyxmon_json_metrics import SCRIPT, JsonMetricsCheck

PASSWORD = "fixture-monitor-password"
CHECK = JsonMetricsCheck(
    service_name="example-host",
    name="Example Thermal Freshness",
    check_interval=300,
    auth_username="nyxmon",
    data={
        "url": "http://host.example.invalid:9104/.well-known/thermal",
        "timeout": 10.0,
        "retries": 1,
        "retry_delay": 2.0,
        "checks": [
            {"path": "$.meta.age_seconds", "op": ">=", "value": 0, "severity": "warning"},
            {"path": "$.meta.age_seconds", "op": "<", "value": 600, "severity": "warning"},
        ],
    },
)
DATA_JSON = json.dumps(CHECK.desired_data(PASSWORD), sort_keys=True)
SCHEMA = """
CREATE TABLE service (id INTEGER PRIMARY KEY AUTOINCREMENT, name varchar(255) NOT NULL);
CREATE TABLE health_check (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name varchar(255) NOT NULL,
    service_id bigint NOT NULL REFERENCES service (id),
    check_type varchar(20) NOT NULL,
    url varchar(512) NOT NULL,
    check_interval integer NOT NULL,
    status varchar(10) NOT NULL,
    next_check_time integer unsigned NOT NULL,
    processing_started_at integer unsigned NOT NULL,
    disabled bool NOT NULL,
    data text NOT NULL
);
"""
COLUMNS = (
    "name, service_id, check_type, url, check_interval, status, next_check_time, processing_started_at, disabled, data"
)
INSERT = f"INSERT INTO health_check ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "db.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
    conn.close()
    path.chmod(0o600)
    return path


def script(
    db: Path, mode: str, stdin: str | None = None, check: JsonMetricsCheck = CHECK
) -> subprocess.CompletedProcess[str]:
    args = [str(db)] if mode == "guard" else [str(db), check.service_name, check.name]
    return subprocess.run(
        [sys.executable, "-I", "-c", SCRIPT, mode, *args],
        input=stdin if stdin is not None else "",
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def answer(db: Path, mode: str, check: JsonMetricsCheck = CHECK) -> str:
    stdin = check.stdin(PASSWORD if check.auth_username else None) if mode == "apply" else None
    result = script(db, mode, stdin, check)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def rows(db: Path) -> list[tuple[Any, ...]]:
    with sqlite3.connect(db) as conn:
        found = conn.execute(f"SELECT {COLUMNS} FROM health_check ORDER BY id").fetchall()
    conn.close()
    return found


def sql(db: Path, statement: str, *params: Any) -> None:
    with sqlite3.connect(db) as conn:
        conn.execute(statement, params)
    conn.close()
    db.chmod(0o600)


def current() -> str:
    return f"check {CHECK.digest(PASSWORD)}"


def test_fresh_database_probe_changes_nothing_then_apply_inserts_an_idle_row(db: Path) -> None:
    before = db.read_bytes()

    assert answer(db, "probe") == "service absent"
    assert db.read_bytes() == before

    assert answer(db, "apply") == "changed=true"
    assert rows(db) == [(CHECK.name, 1, "json-metrics", CHECK.url, 300, "idle", 0, 0, 0, DATA_JSON)]
    assert answer(db, "probe") == current()
    assert answer(db, "apply") == "changed=false"


def test_an_existing_service_without_the_check(db: Path) -> None:
    sql(db, "INSERT INTO service (name) VALUES ('example-host')")

    assert answer(db, "probe") == "check absent"
    assert answer(db, "apply") == "changed=true"
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM service").fetchone() == (1,)
    conn.close()


def test_a_converged_row_keeps_its_schedule_even_while_processing(db: Path) -> None:
    answer(db, "apply")
    sql(db, "UPDATE health_check SET status = 'processing', next_check_time = 42, processing_started_at = 41")
    before = rows(db)

    assert answer(db, "probe") == current()
    assert answer(db, "apply") == "changed=false"
    assert rows(db) == before


def test_key_order_and_spacing_of_stored_data_do_not_matter(db: Path) -> None:
    answer(db, "apply")
    sql(db, "UPDATE health_check SET data = ?", json.dumps(CHECK.desired_data(PASSWORD), indent=2))

    assert answer(db, "probe") == current()
    assert answer(db, "apply") == "changed=false"


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("url", "http://moved.example.invalid/"),
        ("check_type", "http"),
        ("check_interval", 60),
        ("data", json.dumps({**CHECK.desired_data(PASSWORD), "timeout": 10})),
        ("data", json.dumps({**CHECK.desired_data(PASSWORD), "auth": {"username": "nyxmon", "password": "old"}})),
        ("data", "not json"),
        ("disabled", 1),
    ],
)
def test_drift_is_repaired_and_resets_the_schedule(db: Path, column: str, value: Any) -> None:
    answer(db, "apply")
    sql(db, f"UPDATE health_check SET {column} = ?, next_check_time = 42", value)

    assert answer(db, "probe") != current()
    assert answer(db, "apply") == "changed=true"
    assert rows(db) == [(CHECK.name, 1, "json-metrics", CHECK.url, 300, "idle", 0, 0, 0, DATA_JSON)]
    assert answer(db, "probe") == current()


def test_a_processing_check_with_drift_is_refused_for_a_retry(db: Path) -> None:
    answer(db, "apply")
    sql(db, "UPDATE health_check SET check_interval = 60, status = 'processing', processing_started_at = 41")
    before = rows(db)

    result = script(db, "apply", CHECK.stdin(PASSWORD))

    assert result.returncode != 0
    assert "currently processing" in result.stderr
    assert rows(db) == before


def test_ambiguous_services_and_checks_are_refused(db: Path) -> None:
    answer(db, "apply")
    sql(db, INSERT, CHECK.name, 1, "json-metrics", CHECK.url, 300, "idle", 0, 0, 0, "{}")

    for mode in ("probe", "apply"):
        result = script(db, mode, CHECK.stdin(PASSWORD))
        assert result.returncode != 0
        assert "ambiguous Nyxmon check name" in result.stderr

    sql(db, "INSERT INTO service (name) VALUES ('example-host')")
    result = script(db, "probe")
    assert "ambiguous Nyxmon service name" in result.stderr


def test_other_services_and_checks_are_left_alone(db: Path) -> None:
    sql(db, "INSERT INTO service (name) VALUES ('other')")
    sql(db, INSERT, "Manual", 1, "http", "https://manual.example.invalid/", 60, "idle", 5, 0, 1, "{}")

    answer(db, "apply")

    assert rows(db)[0] == ("Manual", 1, "http", "https://manual.example.invalid/", 60, "idle", 5, 0, 1, "{}")
    assert rows(db)[1][:2] == (CHECK.name, 2)


def test_a_check_without_auth_stores_no_login(db: Path) -> None:
    check = CHECK.model_copy(update={"auth_username": None})

    answer(db, "apply", check)

    assert "auth" not in json.loads(rows(db)[0][-1])
    assert answer(db, "probe", check) == f"check {check.digest(None)}"


def test_missing_columns_are_refused_before_anything_is_written(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA.replace("    disabled bool NOT NULL,\n", ""))
    conn.close()
    path.chmod(0o600)

    result = script(path, "apply", CHECK.stdin(PASSWORD))

    assert result.returncode != 0
    assert "lacks required columns: ['disabled']" in result.stderr
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM service").fetchone() == (0,)
    conn.close()


def test_a_missing_database_is_never_created(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"

    for mode in ("guard", "probe", "apply"):
        result = script(path, mode, CHECK.stdin(PASSWORD))
        assert result.returncode != 0
        assert "not found" in result.stderr
    assert not path.exists()


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o400])
def test_a_database_that_is_not_private_is_refused(db: Path, mode: int) -> None:
    db.chmod(mode)

    for step in ("guard", "probe", "apply"):
        result = script(db, step, CHECK.stdin(PASSWORD))
        assert result.returncode != 0
        assert "mode 0600" in result.stderr
    db.chmod(0o600)
    assert rows(db) == []


def test_a_symlinked_database_is_refused(db: Path, tmp_path: Path) -> None:
    link = tmp_path / "link.sqlite3"
    link.symlink_to(db)

    result = script(link, "guard")

    assert result.returncode != 0
    assert "regular file" in result.stderr


def test_a_sidecar_that_is_not_private_is_refused(db: Path, tmp_path: Path) -> None:
    sidecar = tmp_path / "db.sqlite3-wal"
    sidecar.write_bytes(b"")
    sidecar.chmod(0o644)
    # Other names, directories and symlinks next to the database are not sidecars.
    (tmp_path / "other.sqlite3").write_bytes(b"")
    (tmp_path / "db.sqlite3.d").mkdir()
    (tmp_path / "db.sqlite3-link").symlink_to(tmp_path / "other.sqlite3")

    result = script(db, "guard")
    assert result.returncode != 0
    assert "db.sqlite3-wal" in result.stderr

    sidecar.chmod(0o600)
    assert script(db, "guard").returncode == 0


@pytest.mark.parametrize("argv", [[], ["probe"], ["guard"], ["apply", "db"], ["drop", "db", "s", "c"]])
def test_bad_usage_is_refused(argv: list[str]) -> None:
    result = subprocess.run([sys.executable, "-I", "-c", SCRIPT, *argv], capture_output=True, text=True, check=False)

    assert result.returncode != 0
    assert "usage" in result.stderr


def test_the_script_never_prints_the_login(db: Path) -> None:
    sql(db, "INSERT INTO service (name) VALUES ('example-host')")
    outputs = [script(db, "apply", CHECK.stdin(PASSWORD)), script(db, "probe")]
    sql(db, "UPDATE health_check SET check_interval = 1, status = 'processing'")
    outputs.append(script(db, "apply", CHECK.stdin(PASSWORD)))

    for result in outputs:
        assert PASSWORD not in result.stdout + result.stderr


def test_the_script_is_fish_safe_on_a_command_line() -> None:
    # It travels inside a single-quoted ``sh -c`` argument (see ops_deploy.testing.fish_unsafe).
    assert "\\" not in SCRIPT
