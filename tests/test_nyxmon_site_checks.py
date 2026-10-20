"""nyxmon_site_checks: config validation, the deploy's plan, and the host script against a real SQLite file."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.nyxmon_site_checks import (
    NyxmonSiteChecksConfig,
    SiteCheck,
    deploy_nyxmon_site_checks,
)
from ops_deploy.services.nyxmon_site_checks.deploy import SCRIPT, checks_json, site_checks_command
from ops_deploy.testing import FakeRun, run_deploy_fake

DB = "/home/nyxmon/site/db.sqlite3"
SOURCE = "/home/nyxmon/site/src/nyxmon/domain/http_config.py"
PROBE = f"if test -e {DB}; then"
GREP = "grep -Fq -e expected_location --"
DB_GUARD = f"test -e {DB} ||"
SUPPRESSION = {
    "url": "http://127.0.0.1:9999/api/health/",
    "timeout": 3.0,
    "status_path": "$.targets_by_name.site.status",
    "active_statuses": [],
    "active_if": [{"path": "$.targets_by_name.site.overdue_hours", "op": "<=", "value": 0.5}],
    "reason": "backup_window_active",
}
CHECKS: list[dict[str, Any]] = [
    {
        "name": "Example Public Site",
        "check_type": "http",
        "url": "https://site.example.invalid/",
        "check_interval": 300,
        "data": {"timeout": 10.0, "retries": 3, "retry_delay": 10.0, "retry_status_codes": [502, 503, 504]},
    },
    {
        "name": "Example www Canonical Redirect",
        "check_type": "http",
        "url": "https://www.site.example.invalid/__probe__/path?source=example",
        "check_interval": 300,
        "data": {
            "timeout": 10.0,
            "retries": 3,
            "retry_delay": 10.0,
            "retry_status_codes": [502, 503, 504],
            "follow_redirects": False,
            "expected_status": 301,
            "expected_location": "https://site.example.invalid/__probe__/path?source=example",
        },
    },
    {
        "name": "Example Backup Freshness",
        "check_type": "json-metrics",
        "url": "http://127.0.0.1:9999/api/health/",
        "check_interval": 300,
        "data": {
            "url": "http://127.0.0.1:9999/api/health/",
            "timeout": 10.0,
            "retries": 1,
            "retry_delay": 2.0,
            "checks": [
                {"path": "$.targets_by_name.site.status", "op": "==", "value": "ok", "severity": "critical"},
                {"path": "$.targets_by_name.site.next_scheduled", "op": "!=", "value": None, "severity": "critical"},
            ],
            "notification_suppression": SUPPRESSION,
        },
    },
    {
        "name": "Example TLS Certificate",
        "check_type": "tcp",
        "url": "site.example.invalid",
        "check_interval": 3600,
        "data": {
            "host": "site.example.invalid",
            "port": 443,
            "tls_mode": "implicit",
            "connect_timeout": 10.0,
            "check_cert_expiry": True,
            "min_cert_days": 21,
            "verify": True,
        },
    },
]


def make_cfg(checks: list[dict[str, Any]] | None = None, **changes: Any) -> NyxmonSiteChecksConfig:
    fields: dict[str, Any] = {"service_name": "example-site", "checks": CHECKS if checks is None else checks}
    return NyxmonSiteChecksConfig.model_validate({**fields, **changes})


@pytest.fixture
def cfg() -> NyxmonSiteChecksConfig:
    return make_cfg(require_literal={"path": SOURCE, "literal": "expected_location"})


def deploy(cfg: NyxmonSiteChecksConfig, responses: dict[Any, Any] | None = None) -> FakeRun:
    return run_deploy_fake(deploy_nyxmon_site_checks, cfg, responses=responses)


# -- config ------------------------------------------------------------------------


def test_defaults_are_the_nyxmon_site() -> None:
    cfg = make_cfg()

    assert cfg.user == "nyxmon"
    assert str(cfg.db_path) == DB
    assert cfg.require_literal is None
    assert cfg.secrets is None


def test_checks_json_keeps_every_json_type() -> None:
    # 10.0 and 10 are different JSON to the upsert's comparison, so types must survive.
    assert json.loads(checks_json(make_cfg())) == CHECKS
    rendered = json.dumps(json.loads(checks_json(make_cfg())), sort_keys=True)
    assert rendered == json.dumps(CHECKS, sort_keys=True)
    assert '"timeout": 10.0' in rendered
    assert '"retries": 3,' in rendered
    assert '"value": 0.5' in rendered
    assert '"follow_redirects": false' in rendered
    assert '"value": null' in rendered


def test_tuples_in_data_become_lists() -> None:
    check = SiteCheck(
        name="x", check_type="http", url="https://a.example.invalid/", check_interval=60, data={"codes": (502, 503)}
    )

    assert check.as_json()["data"] == {"codes": [502, 503]}


def test_data_is_copied_from_the_input() -> None:
    data: dict[str, Any] = {"codes": [502]}
    check = SiteCheck(name="x", check_type="http", url="https://a.example.invalid/", check_interval=60, data=data)
    data["codes"].append(503)

    assert check.as_json()["data"] == {"codes": [502]}


def _check(**changes: Any) -> dict[str, Any]:
    return {**CHECKS[0], **changes}


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"name": ""}, "name"),
        ({"name": "   "}, "name"),
        ({"name": "a\nb"}, "name"),
        ({"name": "a\\b"}, "name"),
        ({"name": "x" * 256}, "name"),
        ({"check_type": "ping"}, "check_type"),
        ({"url": "ftp://site.example.invalid/"}, "http"),
        ({"url": "site.example.invalid"}, "http"),
        ({"url": "https://site.example.invalid/a b"}, "http"),
        ({"url": "https://site.example.invalid/\x07"}, "http"),
        ({"check_type": "tcp", "url": "https://site.example.invalid/"}, "host name"),
        ({"check_type": "tcp", "url": "-bad.example.invalid"}, "host name"),
        ({"check_type": "tcp", "url": "site.example.invalid\n"}, "host name"),
        ({"url": "https://site.example.invalid/\n"}, "http"),
        ({"name": b"Example"}, "name"),
        ({"url": b"https://site.example.invalid/"}, "url"),
        ({"check_type": b"http"}, "check_type"),
        ({"check_interval": 0}, "check_interval"),
        ({"check_interval": True}, "check_interval"),
        ({"check_interval": "300"}, "check_interval"),
        ({"check_interval": 300.0}, "check_interval"),
        ({"data": {"timeout": float("nan")}}, "NaN"),
        ({"data": {"timeout": float("inf")}}, "NaN"),
        ({"data": {"value": {1, 2}}}, "JSON values"),
        ({"data": {"value": b"bytes"}}, "JSON values"),
        ({"data": {"value": "a\\b"}}, "backslashes"),
        ({"data": {"value": "line\nbreak"}}, "control characters"),
        ({"data": {"nested": {"": 1}}}, "keys"),
        ({"data": {"nested": {1: 1}}}, "keys"),
        ({"data": "not a mapping"}, "mapping"),
        ({"data": [("timeout", 1)]}, "mapping"),
        ({"data": {b"timeout": 10.0, "timeout": 2.0}}, "keys"),
        ({"data": {b"timeout": 10.0}}, "keys"),
        ({"extra": 1}, "extra"),
    ],
)
def test_bad_checks_are_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        make_cfg([_check(**changes)])


def test_deep_data_is_refused() -> None:
    data: dict[str, Any] = {}
    inner = data
    for _ in range(20):
        inner["n"] = {}
        inner = inner["n"]

    with pytest.raises(ConfigValidationError, match="nest"):
        make_cfg([_check(data=data)])


def test_duplicate_and_missing_checks_are_refused() -> None:
    with pytest.raises(ConfigValidationError, match="unique"):
        make_cfg([CHECKS[0], CHECKS[0]])
    with pytest.raises(ConfigValidationError, match="checks"):
        make_cfg([])


@pytest.mark.parametrize(
    "path", ["db.sqlite3", "/home/nyxmon/../db.sqlite3", "/home/nyx mon/db", "/", "/home/nyxmon/site/db.sqlite3\n"]
)
def test_bad_database_paths_are_refused(path: str) -> None:
    with pytest.raises(ConfigValidationError, match="db_path"):
        make_cfg(db_path=path)


@pytest.mark.parametrize(
    "required",
    [
        {"path": "relative.py", "literal": "x"},
        {"path": f"{SOURCE}\n", "literal": "x"},
        {"path": SOURCE, "literal": ""},
        {"path": SOURCE, "literal": "a\nb"},
        {"path": SOURCE, "literal": "x\n"},
        {"path": SOURCE, "literal": b"expected_location"},
    ],
)
def test_bad_source_literals_are_refused(required: dict[str, str]) -> None:
    with pytest.raises(ConfigValidationError, match="require_literal"):
        make_cfg(require_literal=required)


def test_placeholders_are_refused() -> None:
    with pytest.raises(ConfigValidationError):
        make_cfg([_check(data={"reason": "CHANGEME"})])


def test_errors_never_echo_the_input() -> None:
    with pytest.raises(ConfigValidationError) as caught:
        make_cfg([_check(url="ftp://secret-looking.example.invalid/")])

    assert "secret-looking" not in str(caught.value)


def test_service_names_follow_the_service_name_rule() -> None:
    with pytest.raises(ConfigValidationError, match="service_name"):
        make_cfg(service_name="Example Site")


# -- the deploy's plan --------------------------------------------------------------


def test_converged_database_plans_only_read_only_checks(cfg: NyxmonSiteChecksConfig) -> None:
    run = deploy(cfg, {PROBE: ["changed=false"]})

    assert run.succeeded
    assert run.mutating_changed_ops == []
    assert [op.name for op in run.ops] == [
        f"Provision Nyxmon site checks | Require expected_location in {SOURCE}",
        "Provision Nyxmon site checks | Require the Nyxmon database",
    ]
    assert all(op.read_only for op in run.ops)
    assert not any(" apply" in command for command in run.executed_commands)


@pytest.mark.parametrize("state", ["changed=true", "missing"])
def test_drift_or_a_new_database_is_upserted(cfg: NyxmonSiteChecksConfig, state: str) -> None:
    run = deploy(cfg, {PROBE: [state]})

    assert run.succeeded
    assert run.mutating_changed_ops == ["Provision Nyxmon site checks | Upsert Nyxmon checks for example-site"]
    upsert = run.executed_commands[-1]
    assert upsert == site_checks_command(cfg, "apply")
    assert upsert.startswith("runuser -u nyxmon -- env NYXMON_DB_PATH=/home/nyxmon/site/db.sqlite3 ")
    assert " python3 -I -c " in upsert
    assert upsert.endswith(" apply")
    assert run.stdin[-1] == (upsert, checks_json(cfg) + "\n")


def test_the_checks_travel_on_stdin_only() -> None:
    # Command lines are world-readable while they run; check data can carry a login.
    checks = [{**CHECKS[0], "data": {"auth": {"password": "site-check-sentinel"}}}]
    sentinel_cfg = make_cfg(checks=checks)
    run = deploy(sentinel_cfg, {PROBE: [FAILED]})

    assert run.succeeded
    assert "site-check-sentinel" not in run.all_text()
    assert "NYXMON_CHECKS_JSON" not in run.all_text()
    probes = [text for command, text in run.stdin if PROBE in command or command.endswith(" apply")]
    assert len(probes) == 3  # the planning probe, the upsert and the probe again
    assert all(json.loads(text) == checks for text in probes)


def test_the_requirements_run_before_the_upsert(cfg: NyxmonSiteChecksConfig) -> None:
    run = deploy(cfg, {PROBE: ["changed=true"]})

    commands = run.executed_commands
    grep = next(i for i, c in enumerate(commands) if GREP in c)
    guard = next(i for i, c in enumerate(commands) if DB_GUARD in c)
    upsert = next(i for i, c in enumerate(commands) if c.endswith(" apply"))
    assert grep < guard < upsert
    assert f"{GREP} {SOURCE} ||" in commands[grep]


def test_a_nyxmon_without_the_literal_is_refused_before_any_write(cfg: NyxmonSiteChecksConfig) -> None:
    run = deploy(cfg, {GREP: {"success": False}, PROBE: ["changed=true"]})

    assert not run.succeeded
    assert not any(c.endswith(" apply") for c in run.executed_commands)


def test_a_converged_database_is_still_refused_without_the_literal(cfg: NyxmonSiteChecksConfig) -> None:
    # The playbook's assert runs before its upsert, whatever the rows hold.
    run = deploy(cfg, {GREP: {"success": False}, PROBE: ["changed=false"]})

    assert not run.succeeded


def test_a_missing_database_fails_the_run_before_any_write(cfg: NyxmonSiteChecksConfig) -> None:
    run = deploy(cfg, {DB_GUARD: {"success": False}, PROBE: ["missing"]})

    assert not run.succeeded
    assert not any(c.endswith(" apply") for c in run.executed_commands)


def test_no_literal_requirement_means_no_grep() -> None:
    run = deploy(make_cfg(), {PROBE: ["changed=false"]})

    assert run.succeeded
    assert not any("grep" in c for c in run.executed_commands + run.fact_commands)
    assert [op.name for op in run.ops] == ["Provision Nyxmon site checks | Require the Nyxmon database"]


def test_a_failing_probe_upserts_and_probes_again(cfg: NyxmonSiteChecksConfig) -> None:
    run = deploy(cfg, {PROBE: [FAILED]})

    assert run.succeeded
    assert run.mutating_changed_ops == ["Provision Nyxmon site checks | Upsert Nyxmon checks for example-site"]
    assert run.ops[-1].name == "Provision Nyxmon site checks | Probe again: Nyxmon checks for example-site"
    assert run.ops[-1].read_only


def test_the_checks_are_redacted_in_pyinfra_logs(caplog: pytest.LogCaptureFixture) -> None:
    # pyinfra logs a fact's arguments, _stdin included ("Loaded fact ...").
    caplog.set_level(logging.DEBUG)
    checks = [{**CHECKS[0], "data": {"auth": {"password": "site-check-sentinel"}}}]
    run = deploy(make_cfg(checks=checks), {PROBE: [FAILED]})

    assert run.succeeded
    assert "_stdin=<stdin redacted>" in caplog.text
    assert "site-check-sentinel" not in caplog.text


def test_the_probe_runs_the_check_mode_as_the_nyxmon_user(cfg: NyxmonSiteChecksConfig) -> None:
    run = deploy(cfg, {PROBE: ["changed=false"]})

    probes = [c for c in run.fact_commands if PROBE in c]
    assert probes
    assert site_checks_command(cfg, "check") in probes[0]
    assert [text for command, text in run.stdin if command == probes[0]] == [checks_json(cfg) + "\n"]


def test_commands_are_valid_shell(cfg: NyxmonSiteChecksConfig) -> None:
    run = deploy(cfg, {PROBE: [FAILED]})

    for command in run.executed_commands + [c for c in run.fact_commands if PROBE in c]:
        checked = subprocess.run(["sh", "-n", "-c", command], capture_output=True, text=True, check=False)
        assert checked.returncode == 0, checked.stderr


# -- the host script on a real database ------------------------------------------------

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
COLUMNS = "name, check_type, url, check_interval, status, next_check_time, processing_started_at, disabled, data"


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "db.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
    conn.close()
    return path


def script(db: Path, mode: str, checks: list[dict[str, Any]] | None = None) -> subprocess.CompletedProcess[str]:
    env = {"PATH": os.environ.get("PATH", ""), "NYXMON_DB_PATH": str(db), "NYXMON_SERVICE_NAME": "example-site"}
    # As pyinfra writes it: the JSON line, newline-terminated.
    payload = json.dumps(CHECKS if checks is None else checks) + "\n"
    return subprocess.run(
        [sys.executable, "-I", "-c", SCRIPT, mode],
        env=env,
        input=payload,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def answer(db: Path, mode: str, checks: list[dict[str, Any]] | None = None) -> str:
    result = script(db, mode, checks)
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


def test_fresh_database_check_changes_nothing_then_apply_inserts_idle_rows(db: Path) -> None:
    before = db.read_bytes()

    assert answer(db, "check") == "changed=true"
    assert db.read_bytes() == before

    assert answer(db, "apply") == "changed=true"
    with sqlite3.connect(db) as conn:
        services = conn.execute("SELECT id, name FROM service").fetchall()
    conn.close()
    assert [name for _, name in services] == ["example-site"]
    stored = rows(db)
    assert [row[0] for row in stored] == [check["name"] for check in CHECKS]
    for row, check in zip(stored, CHECKS, strict=True):
        assert row[1:8] == (check["check_type"], check["url"], check["check_interval"], "idle", 0, 0, 0)
        assert row[8] == json.dumps(check["data"], sort_keys=True)


def test_converged_database_is_a_no_op_in_both_modes(db: Path) -> None:
    answer(db, "apply")
    sql(db, "UPDATE health_check SET status = 'processing', next_check_time = 42, processing_started_at = 41")
    before = rows(db)

    assert answer(db, "check") == "changed=false"
    assert answer(db, "apply") == "changed=false"
    assert rows(db) == before


def test_an_existing_service_row_is_reused(db: Path) -> None:
    sql(db, "INSERT INTO service (name) VALUES ('example-site')")

    answer(db, "apply")

    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM service").fetchone() == (1,)
    conn.close()


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("url", "https://moved.example.invalid/"),
        ("check_type", "tcp"),
        ("check_interval", 60),
        ("data", json.dumps({**CHECKS[0]["data"], "timeout": 10})),
        ("data", "not json"),
    ],
)
def test_single_field_drift_is_repaired_and_resets_the_schedule(db: Path, column: str, value: Any) -> None:
    answer(db, "apply")
    sql(db, f"UPDATE health_check SET {column} = ? WHERE name = ?", value, CHECKS[0]["name"])
    sql(db, "UPDATE health_check SET status = 'processing', next_check_time = 42, processing_started_at = 41")
    others = rows(db)[1:]

    assert answer(db, "check") == "changed=true"
    assert answer(db, "apply") == "changed=true"

    first = rows(db)[0]
    assert first[1:8] == ("http", CHECKS[0]["url"], 300, "idle", 0, 0, 0)
    assert first[8] == json.dumps(CHECKS[0]["data"], sort_keys=True)
    assert rows(db)[1:] == others
    assert answer(db, "check") == "changed=false"


def test_a_disabled_check_is_re_enabled(db: Path) -> None:
    answer(db, "apply")
    sql(db, "UPDATE health_check SET disabled = 1, next_check_time = 42 WHERE name = ?", CHECKS[3]["name"])

    assert answer(db, "check") == "changed=true"
    assert answer(db, "apply") == "changed=true"

    last = rows(db)[3]
    assert last[4:8] == ("idle", 0, 0, 0)


def test_stored_data_is_compared_as_sorted_json(db: Path) -> None:
    answer(db, "apply")
    reordered = json.dumps(dict(reversed(list(CHECKS[0]["data"].items()))), indent=2)
    sql(db, "UPDATE health_check SET data = ? WHERE name = ?", reordered, CHECKS[0]["name"])

    assert answer(db, "check") == "changed=false"
    assert answer(db, "apply") == "changed=false"


def test_unlisted_checks_and_other_services_are_left_alone(db: Path) -> None:
    answer(db, "apply")
    sql(db, "INSERT INTO service (name) VALUES ('other')")
    sql(
        db,
        "INSERT INTO health_check (name, service_id, check_type, url, check_interval, status,"
        " next_check_time, processing_started_at, disabled, data)"
        " VALUES ('Example Public Site', 2, 'http', 'https://o.example.invalid/', 5, 'idle', 0, 0, 1, '{}')",
    )
    sql(
        db,
        "INSERT INTO health_check (name, service_id, check_type, url, check_interval, status,"
        " next_check_time, processing_started_at, disabled, data)"
        " VALUES ('Manual', 1, 'http', 'https://m.example.invalid/', 5, 'idle', 0, 0, 1, '{}')",
    )
    before = rows(db)

    assert answer(db, "apply", CHECKS[:1]) == "changed=false"
    assert rows(db) == before


def test_a_missing_database_is_an_error_and_never_created(tmp_path: Path) -> None:
    missing = tmp_path / "missing.sqlite3"

    for mode in ("check", "apply"):
        assert script(missing, mode).returncode != 0
    assert not missing.exists()


def test_a_failed_apply_writes_nothing(db: Path) -> None:
    broken = [*CHECKS[:1], {**CHECKS[1], "check_interval": "not a number"}]

    assert script(db, "apply", broken).returncode != 0
    assert rows(db) == []
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM service").fetchone() == (0,)
    conn.close()


def test_unknown_modes_are_refused(db: Path) -> None:
    assert script(db, "probe").returncode != 0


def test_the_script_is_fish_safe_and_keeps_new_files_private() -> None:
    assert "\\" not in SCRIPT
    assert "os.umask(0o077)" in SCRIPT
    assert 'cur.execute("BEGIN IMMEDIATE")' in SCRIPT
