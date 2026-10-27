"""Mail task privacy, identity and processing-lease semantics remain opt-in."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.nyxmon_site_checks import SiteCheck
from ops_deploy.services.nyxmon_site_checks.deploy import SCRIPT
from tests.test_nyxmon_site_checks import CHECKS, SCHEMA


def run(db: Path, mode: str, checks: list[dict[str, Any]] = CHECKS) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", SCRIPT, mode, "--managed-safety"],
        env={**os.environ, "NYXMON_DB_PATH": str(db), "NYXMON_SERVICE_NAME": "mail"},
        input=json.dumps(checks),
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "db.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
    path.chmod(0o600)
    return path


def test_privacy_fails_before_rows(db: Path) -> None:
    db.chmod(0o644)
    assert run(db, "apply").returncode != 0
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM service").fetchone() == (0,)


def test_repeat_preserves_processing_lease_and_runtime(db: Path) -> None:
    assert run(db, "apply").returncode == 0
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE health_check SET status='processing', next_check_time=100, processing_started_at=99")
    before = db.read_bytes()
    result = run(db, "apply")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "changed=false"
    assert db.read_bytes() == before
    changed = [{**CHECKS[0], "check_interval": 301}]
    assert run(db, "apply", changed).returncode != 0
    assert db.read_bytes() == before


def test_duplicate_identity_rolls_back(db: Path) -> None:
    assert run(db, "apply").returncode == 0
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO service(name) VALUES ('mail')")
    before = db.read_bytes()
    assert run(db, "apply").returncode != 0
    assert db.read_bytes() == before


def test_sidecar_privacy_is_checked(db: Path) -> None:
    sidecar = db.with_name(db.name + "-fixture")
    sidecar.write_text("fixture")
    sidecar.chmod(0o644)
    assert run(db, "apply").returncode != 0


def test_imap_hostname_and_data() -> None:
    check = SiteCheck(
        name="delivery",
        check_type="imap",
        url="imap.example.test",
        check_interval=900,
        data={"port": 993, "tls_mode": "implicit", "delete_after_check": False},
    )
    assert check.as_json()["check_type"] == "imap"
    with pytest.raises(ValueError, match="host name"):
        SiteCheck(name="delivery", check_type="imap", url="https://imap.example.test", check_interval=900, data={})


def test_symlink_database_is_not_regular(db: Path) -> None:
    link = db.with_name("alias.sqlite3")
    link.symlink_to(db)
    assert run(link, "apply").returncode != 0
