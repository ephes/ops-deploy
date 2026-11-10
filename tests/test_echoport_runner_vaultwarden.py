"""``_echoport_runner``: vaultwarden-backup's own target and Nyxmon scripts (class B).

``register-vaultwarden-backup.yml`` converges its Echoport target with a
script of its own (schema check, declaration state, reactivation refusal),
stores a newly issued token in a second step and upserts its Nyxmon check
with a script that refuses a disabled check of a present target; it requires
the Nyxmon database. ops-deploy keeps both scripts
(``files/targets/vaultwarden.py``: the converge script, then the token step
under ``if SERVICE_TOKEN:``; ``files/nyxmon/vaultwarden.py``). Here they run
through the check-mode wrappers against the stand-in ``BackupTarget`` and a
real SQLite database; ops-control's tests compare them with the playbook.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.services._echoport_runner.nyxmon import NO_DATABASE, NyxmonScript, nyxmon_script, upsert_nyxmon_script
from ops_deploy.services._echoport_runner.registration import install_registration
from ops_deploy.services._echoport_runner.target import RunnerTarget, ServiceToken, target_code, target_script
from ops_deploy.testing import run_deploy_fake
from tests import test_echoport_runner_registration as a1
from tests.test_echoport_runner_classb import (
    ECHOPORT,
    SCHEMA,
    USER,
    Introspection,
    check_key,
    echoport,  # noqa: F401 - the stand-in Echoport, autouse
    nyxmon_key,
    oracle,
    row,
    run,
    run_nyxmon,
    store,
    table,
)
from tests.test_echoport_runner_target import DB, jwt

# The playbook's values (ops-control resolves them from its vars).
VALUES: dict[str, Any] = {
    "declaration_state": "present",
    "target_name": "vaultwarden",
    "allow_reactivation": False,
    "target_description": "Vaultwarden daily backup via service-owned same-host FastDeploy runner",
    "service_name_fd": "vaultwarden-backup",
    "service_name": "vaultwarden",
    "target_schedule": "5 1 * * *",
    "target_retention_days": 30,
    "target_timeout_seconds": 1200,
    "default_bucket": "backups",
}
# The row on macmini (read-only check 2026-11-10), its token aside.
LIVE = {
    "name": "vaultwarden",
    "description": "Vaultwarden daily backup via service-owned same-host FastDeploy runner",
    "icon": "",
    "fastdeploy_service": "vaultwarden-backup",
    "fastdeploy_endpoint_key": "",
    "service_name": "vaultwarden",
    "restore_owner": "",
    "target_mode": "service_owned",
    "db_path": "",
    "backup_files": [],
    "schedule": "5 1 * * *",
    "schedule_required": True,
    "status": "active",
    "retention_days": 30,
    "timeout_seconds": 1200,
    "storage_bucket": "backups",
    "storage_alias": "minio",
}


def good_token(days: int = 63) -> str:
    return jwt(type="service", service="vaultwarden-backup", jti="abc", exp=int(time.time()) + days * 86400)


def kept(**changes: Any) -> RunnerTarget:
    values = {**VALUES, **changes}
    token = None
    if values["declaration_state"] == "present":
        token = ServiceToken(targets=("vaultwarden",), service="vaultwarden-backup")
    return RunnerTarget(name="vaultwarden", script=target_script("vaultwarden"), values=values, token=token)


# -- the target script --------------------------------------------------------------------------


def test_the_live_row_is_unchanged_and_nothing_is_written() -> None:
    store(**LIVE, service_token=good_token())
    before = DB.snapshot()

    assert run(kept(), "check") == "unchanged"
    assert DB.rows == before
    assert run(kept(), "apply") == "applied"
    assert DB.rows == before


def test_a_new_target_is_created_scheduled_and_required_with_its_token() -> None:
    fresh = good_token(90)

    assert run(kept(), "check") == "pending"
    assert DB.rows == {}
    assert run(kept(), "apply") == "need-token"
    assert DB.rows == {}
    assert run(kept(), "apply", f"{fresh}\n") == "applied"
    stored = row("vaultwarden")
    assert {key: stored[key] for key in LIVE if key != "storage_alias"} == {
        key: value for key, value in LIVE.items() if key != "storage_alias"
    }
    assert stored["service_token"] == fresh
    assert run(kept(), "check") == "unchanged"


@pytest.mark.parametrize(
    "drift",
    [
        {"description": "old"},
        {"icon": "x"},
        {"fastdeploy_service": "other"},
        {"fastdeploy_endpoint_key": "k"},
        {"service_name": "other"},
        {"restore_owner": "a:b"},
        {"target_mode": "generic_paths"},
        {"db_path": "/x"},
        {"backup_files": ["/x"]},
        {"schedule": "0 1 * * *"},
        {"schedule_required": False},
        {"retention_days": 7},
        {"timeout_seconds": 900},
        {"storage_bucket": "other"},
    ],
)
def test_each_owned_field_that_drifts_is_pending_without_a_write(drift: dict[str, Any]) -> None:
    store(**{**LIVE, **drift}, service_token=good_token())
    before = DB.snapshot()

    assert run(kept(), "check") == "pending"
    assert DB.rows == before
    assert run(kept(), "apply") == "applied"
    assert run(kept(), "check") == "unchanged"
    assert row("vaultwarden")["storage_alias"] == "minio"


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-jwt",
        jwt(type="service", service="other-backup", jti="abc", exp=int(time.time()) + 60 * 86400),
        jwt(type="service", service="vaultwarden-backup", exp=int(time.time()) + 60 * 86400),
        good_token(29),
    ],
)
def test_a_due_token_is_pending_and_stored_by_apply(token: str) -> None:
    store(**LIVE, service_token=token)
    before = DB.snapshot()
    fresh = good_token(90)

    assert run(kept(), "check") == "pending"
    assert DB.rows == before
    assert run(kept(), "apply") == "need-token"
    assert run(kept(), "apply", f"{fresh}\n") == "applied"
    assert row("vaultwarden")["service_token"] == fresh
    assert run(kept(), "check") == "unchanged"


@pytest.mark.parametrize("status", ["paused", "disabled"])
def test_a_paused_or_disabled_target_is_refused_unless_allowed(status: str) -> None:
    store(**{**LIVE, "status": status}, service_token=good_token())
    before = DB.snapshot()

    assert run(kept(), "check") == f"refused: RuntimeError: Refusing implicit reactivation from status={status}"
    assert DB.rows == before
    assert run(kept(allow_reactivation=True), "check") == "pending"


def test_an_echoport_without_schedule_required_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    store(**LIVE, service_token=good_token())
    monkeypatch.setattr(Introspection, "columns", [c for c in Introspection.columns if c != "schedule_required"])

    assert "lacks schedule_required; deploy migration 0008 first" in run(kept(), "check")


def test_the_retired_declaration_disables_and_clears_the_target() -> None:
    store(**LIVE, service_token=good_token())

    assert run(kept(declaration_state="retired"), "check") == "pending"
    assert run(kept(declaration_state="retired"), "apply") == "applied"
    stored = row("vaultwarden")
    assert (stored["status"], stored["schedule"], stored["schedule_required"]) == ("disabled", "", False)
    assert stored["service_token"] == ""
    assert run(kept(declaration_state="retired"), "check") == "unchanged"


def test_a_retired_declaration_with_a_token_is_refused() -> None:
    with pytest.raises(ValueError, match="declared 'retired' gets no service token"):
        RunnerTarget(
            name="vaultwarden",
            script=target_script("vaultwarden"),
            values={**VALUES, "declaration_state": "retired"},
            token=ServiceToken(targets=("vaultwarden",), service="vaultwarden-backup"),
        )


def test_the_retired_declaration_without_a_target_writes_nothing() -> None:
    assert run(kept(declaration_state="retired"), "check") == "unchanged"
    assert DB.rows == {}


@pytest.mark.skipif(not ECHOPORT, reason="ECHOPORT_PATH (an Echoport checkout with its .venv) not set")
def test_the_kept_script_against_echoports_own_models(tmp_path: Path) -> None:
    fresh = good_token(90)
    paused = {**LIVE, "status": "paused", "service_token": fresh}
    cases: list[dict[str, Any]] = [
        {"row": None, "name": "vaultwarden", "code": target_code(kept(), "check")},
        {"name": "vaultwarden", "code": target_code(kept(), "apply"), "stdin": f"{fresh}\n"},
        {"name": "vaultwarden", "code": target_code(kept(), "check")},
        {"name": "vaultwarden", "code": target_code(kept(target_schedule="5 5 * * *"), "check")},
        {"row": paused, "name": "vaultwarden", "code": target_code(kept(), "check")},
    ]
    (new, _), (applied, stored), (converged, after), (drift, _), (on_paused, _) = oracle(cases, tmp_path)

    assert (new, applied, converged, drift) == ("pending", "applied", "unchanged", "pending")
    assert after == stored
    assert {key: stored[key] for key in LIVE} == LIVE
    assert stored["service_token"] == fresh
    assert on_paused == "refused: RuntimeError: Refusing implicit reactivation from status=paused"


# -- the Nyxmon script --------------------------------------------------------------------------

SERVICE = "Vaultwarden (macmini)"
CHECK_NAME = "Vaultwarden Backup Freshness (Echoport)"
URL = "http://127.0.0.1:10018/api/health/"
DATA = {
    "url": URL,
    "timeout": 10.0,
    "retries": 1,
    "retry_delay": 2.0,
    "checks": [
        {"path": "$.targets_by_name.vaultwarden.status", "op": "==", "value": "ok", "severity": "critical"},
        {"path": "$.targets_by_name.vaultwarden.next_scheduled", "op": "!=", "value": None, "severity": "critical"},
        {"path": "$.targets_by_name.vaultwarden.schedule_required", "op": "==", "value": True, "severity": "critical"},
        {"path": "$.targets_by_name.vaultwarden.schedule", "op": "==", "value": "5 1 * * *", "severity": "critical"},
    ],
    "notification_suppression": {
        "url": URL,
        "timeout": 3.0,
        "status_path": "$.targets_by_name.vaultwarden.status",
        "active_statuses": [],
        "active_if": [{"path": "$.targets_by_name.vaultwarden.overdue_hours", "op": "<=", "value": 0.5}],
        "reason": "echoport_backup_window_active",
    },
}
CHECKS = [{"name": CHECK_NAME, "check_type": "json-metrics", "url": URL, "check_interval": 300, "data": DATA}]


def nyxmon(db: Path, *, state: str = "present", reenable: bool = False) -> NyxmonScript:
    return NyxmonScript(
        name=CHECK_NAME,
        script=nyxmon_script("vaultwarden"),
        values={"_nyxmon_checks_json": json.dumps(CHECKS)},
        service_name=SERVICE,
        db_path=db,
        extra_environment={"DECLARATION_STATE": state, "ALLOW_REENABLE": json.dumps(reenable)},
        require_database=True,
    )


@pytest.fixture
def nyxmon_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "db.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.executescript(SCHEMA)
    monkeypatch.setenv("NYXMON_DB_PATH", str(db))
    monkeypatch.setenv("NYXMON_SERVICE_NAME", SERVICE)
    monkeypatch.setenv("DECLARATION_STATE", "present")
    monkeypatch.setenv("ALLOW_REENABLE", "false")
    return db


def test_the_nyxmon_check_writes_nothing_and_apply_converges(nyxmon_db: Path) -> None:
    script = nyxmon(nyxmon_db)

    assert run_nyxmon(script, "check") == ["pending"]
    assert table(nyxmon_db) == []
    assert run_nyxmon(script, "apply") == ["changed=true", "applied"]
    assert run_nyxmon(script, "check") == ["unchanged"]
    (stored,) = table(nyxmon_db)
    assert stored[0] == CHECK_NAME
    assert stored[2:6] == ("json-metrics", URL, 300, 0)
    assert json.loads(stored[6]) == DATA


def test_a_disabled_check_of_a_present_target_is_refused(nyxmon_db: Path) -> None:
    run_nyxmon(nyxmon(nyxmon_db), "apply")
    with sqlite3.connect(nyxmon_db) as conn:
        conn.execute("update health_check set disabled = 1")
    before = table(nyxmon_db)

    (answer,) = run_nyxmon(nyxmon(nyxmon_db), "check")
    assert answer.startswith("refused: RuntimeError: Vaultwarden backup target is present but its named Nyxmon check")
    assert table(nyxmon_db) == before


def test_a_drifted_check_is_pending_and_keeps_its_enabled_state(nyxmon_db: Path) -> None:
    run_nyxmon(nyxmon(nyxmon_db), "apply")
    with sqlite3.connect(nyxmon_db) as conn:
        conn.execute("update health_check set check_interval = 60")

    assert run_nyxmon(nyxmon(nyxmon_db), "check") == ["pending"]
    run_nyxmon(nyxmon(nyxmon_db), "apply")
    assert table(nyxmon_db)[0][4:6] == (300, 0)


def test_the_retired_declaration_disables_the_check(nyxmon_db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_nyxmon(nyxmon(nyxmon_db), "apply")
    monkeypatch.setenv("DECLARATION_STATE", "retired")

    assert run_nyxmon(nyxmon(nyxmon_db, state="retired"), "check") == ["pending"]
    run_nyxmon(nyxmon(nyxmon_db, state="retired"), "apply")
    assert table(nyxmon_db)[0][5] == 1


def test_a_nyxmon_table_without_a_required_column_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "db.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.executescript(SCHEMA.replace("disabled INTEGER, ", ""))
    monkeypatch.setenv("NYXMON_DB_PATH", str(db))
    monkeypatch.setenv("NYXMON_SERVICE_NAME", SERVICE)
    monkeypatch.setenv("DECLARATION_STATE", "present")
    monkeypatch.setenv("ALLOW_REENABLE", "false")

    (answer,) = run_nyxmon(nyxmon(db), "check")
    assert answer == "refused: RuntimeError: Nyxmon table health_check lacks required columns: ['disabled']"


def test_a_missing_nyxmon_database_stops_while_planning() -> None:
    script = nyxmon(Path("/home/nyxmon/site/db.sqlite3"))
    fake = run_deploy_fake(lambda: upsert_nyxmon_script(script), responses={nyxmon_key(script): [NO_DATABASE]})

    assert isinstance(fake.error, DeployError)
    assert "Nyxmon DB is missing at /home/nyxmon/site/db.sqlite3" in str(fake.error)
    assert fake.executed_commands == []


def test_the_declaration_controls_are_in_the_playbooks_environment() -> None:
    script = nyxmon(Path("/home/nyxmon/site/db.sqlite3"))
    fake = run_deploy_fake(lambda: upsert_nyxmon_script(script), responses={nyxmon_key(script): ["pending"]})

    assert fake.succeeded, fake.error
    apply = fake.executed_commands[0]
    assert "DECLARATION_STATE=present ALLOW_REENABLE=false python3 -I -c" in apply


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({"NYXMON_DB_PATH": "/x"}, "not an extra environment variable"),
        ({"lower": "x"}, "not an extra environment variable"),
        ({"MONITOR_PASSWORD": "x"}, "must not hold a secret"),
        ({"STATE": "a\nb"}, "must be one line"),
    ],
)
def test_extra_environment_that_could_mislead_is_refused(environment: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        NyxmonScript(
            name="x",
            script=nyxmon_script("vaultwarden"),
            values={},
            service_name="x",
            extra_environment=environment,
        )


# -- the registration ---------------------------------------------------------------------------


def test_a_converged_vaultwarden_host_gets_no_mutating_operation() -> None:
    target = kept()
    script = nyxmon(Path("/home/nyxmon/site/db.sqlite3"))
    cfg = a1.registration("vaultwarden-backup", target=target, nyxmon=script)
    responses = {**a1.converged(cfg), check_key(target): ["unchanged"], nyxmon_key(script): ["unchanged"]}
    fake = run_deploy_fake(
        lambda: install_registration(cfg, secret_key=a1.SECRET, token_user=USER), responses=responses
    )

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == []
    assert USER not in fake.all_text()


def test_a_nyxmon_refusal_stops_the_registration_before_any_write() -> None:
    target = kept()
    script = nyxmon(Path("/home/nyxmon/site/db.sqlite3"))
    cfg = a1.registration("vaultwarden-backup", target=target, nyxmon=script)
    responses = {**a1.converged(cfg), check_key(target): ["pending"], nyxmon_key(script): [NO_DATABASE]}
    fake = run_deploy_fake(
        lambda: install_registration(cfg, secret_key=a1.SECRET, token_user=USER), responses=responses
    )

    assert "Nyxmon DB is missing" in a1.refused(fake)
