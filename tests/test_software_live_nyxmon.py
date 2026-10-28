"""Actual owned SQLite rows through the shipped probe and original upsert helper."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.software_live.common import RESOURCE
from ops_deploy.services.software_live.nyxmon import (
    SoftwareLiveNyxmonConfig,
    SoftwareLiveTarget,
    checks,
    current,
    deploy_software_live_nyxmon,
)
from ops_deploy.testing import run_deploy_fake
from tests.test_software_live import SECRETS, VALUE


@pytest.fixture
def database(tmp_path: Path) -> Path:
    path = tmp_path / "owned.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE service(id INTEGER PRIMARY KEY, name TEXT UNIQUE);
            CREATE TABLE health_check(
                id INTEGER PRIMARY KEY, name TEXT, service_id INTEGER, check_type TEXT,
                url TEXT, check_interval INTEGER, data TEXT, status TEXT,
                next_check_time INTEGER, processing_started_at INTEGER, disabled INTEGER
            );
        """)
    return path


def configuration(db: Path) -> SoftwareLiveNyxmonConfig:
    return SoftwareLiveNyxmonConfig(
        db_path=str(db),
        secrets="secrets/fixture.yml",
        targets=(SoftwareLiveTarget(host_id="fixture", url="http://100.64.0.7:9110/.well-known/software-live"),),
    )


def helper(db: Path, **payload: Any) -> str:
    return subprocess.run(
        [sys.executable, str(RESOURCE.joinpath("files/nyxmon_checks.py"))],
        input=json.dumps({"db": str(db), **payload}),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def probe(db: Path, mode: str = "upsert", names: list[str] | None = None) -> str:
    return subprocess.run(
        [
            sys.executable,
            str(RESOURCE.joinpath("files/nyxmon_probe.py")),
            mode,
            str(db),
            *(names or ["Live software health", "Software health (fixture)"]),
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def row(db: Path) -> tuple[Any, ...]:
    with sqlite3.connect(db) as connection:
        result = connection.execute("SELECT * FROM health_check WHERE name='Software health (fixture)'").fetchone()
        assert result is not None
        return tuple(result)


def test_insert_then_readonly_repeat_preserves_existing_evaluation(database: Path) -> None:
    cfg = configuration(database)
    desired = checks(cfg, VALUE)
    assert not current(probe(database), desired)
    assert helper(database, checks=desired) == "changed=true"
    assert row(database)[7:] == ("idle", 0, 0, 0)
    with sqlite3.connect(database) as db:
        db.execute("UPDATE health_check SET status='warning',next_check_time=123,processing_started_at=456")
    before = database.read_bytes()
    found = probe(database)
    assert current(found, desired)
    result = run_deploy_fake(
        deploy_software_live_nyxmon, cfg, SECRETS, responses={"'upsert'": [found], " upsert ": [found]}
    )
    assert result.succeeded
    assert result.mutating_changed_ops == []
    assert database.read_bytes() == before
    assert helper(database, checks=desired) == "changed=false"
    assert row(database)[7:] == ("warning", 123, 456, 0)


@pytest.mark.parametrize("disabled", [0, 1])
@pytest.mark.parametrize("changed_url", [False, True])
def test_exact_owned_delta_and_disabled_reenable_semantics(database: Path, disabled: int, changed_url: bool) -> None:
    desired = checks(configuration(database), VALUE)
    helper(database, checks=desired)
    with sqlite3.connect(database) as db:
        db.execute(
            "UPDATE health_check SET status='critical',next_check_time=123,processing_started_at=456,disabled=?",
            (disabled,),
        )
        db.execute("INSERT INTO service(name) VALUES ('Unrelated fixture service')")
        db.execute(
            "INSERT INTO health_check VALUES (2,'Unrelated fixture row',2,'other','fixture',999,"
            "'{}','critical',321,654,1)"
        )
        unrelated = db.execute("SELECT * FROM health_check WHERE id=2").fetchone()
    if changed_url:
        desired[0]["url"] = "http://100.64.0.8:9110/.well-known/software-live"
    expected_change = bool(disabled or changed_url)
    assert current(probe(database), desired) is not expected_change
    assert helper(database, checks=desired) == f"changed={str(expected_change).lower()}"
    assert row(database)[7:] == ("critical", 0 if expected_change else 123, 456, 0)
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT * FROM health_check WHERE id=2").fetchone() == unrelated
    assert current(probe(database), desired)


def test_disable_only_declared_service_row_then_repeat(database: Path) -> None:
    desired = checks(configuration(database), VALUE)
    helper(database, checks=desired)
    with sqlite3.connect(database) as db:
        db.execute("UPDATE health_check SET status='critical',next_check_time=123,processing_started_at=456")
        db.execute("INSERT INTO service VALUES (2,'Other')")
        db.execute(
            "INSERT INTO health_check VALUES (2,'Software health (fixture)',2,'other','fixture',999,"
            "'{}','ok',321,654,0)"
        )
        unrelated = db.execute("SELECT * FROM health_check WHERE id=2").fetchone()
    names = ["Software health (fixture)"]
    assert probe(database, "disable", names) == "enabled 1"
    assert helper(database, disable_names=names) == "changed=true"
    assert row(database)[7:] == ("critical", 123, 456, 1)
    assert probe(database, "disable", names) == "enabled 0"
    assert helper(database, disable_names=names) == "changed=false"
    cfg = configuration(database).model_copy(update={"disable_names": tuple(names)})
    result = run_deploy_fake(deploy_software_live_nyxmon, cfg, None, responses={" disable ": ["enabled 0"]})
    assert result.succeeded
    assert result.mutating_changed_ops == []
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT * FROM health_check WHERE id=2").fetchone() == unrelated


def test_missing_database_is_not_created(tmp_path: Path) -> None:
    missing = tmp_path / "absent.sqlite3"
    result = subprocess.run(
        [sys.executable, str(RESOURCE.joinpath("files/nyxmon_probe.py")), "upsert", str(missing)], capture_output=True
    )
    assert result.returncode != 0
    assert not missing.exists()
