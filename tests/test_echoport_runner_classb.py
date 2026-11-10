"""``_echoport_runner``: the class B parts of a register playbook (target script, token, credential file, Nyxmon).

The same-host root runners of class B (mail-db-backup, postfixadmin-backup,
graphyard-backup) are A1 registrations plus their playbook's own steps. Here:

- the kept target scripts (``files/targets``) run through the check-mode
  wrapper against a stand-in for Echoport's ``BackupTarget`` with all of its
  fields, and (with ``ECHOPORT_PATH``) against Echoport's own models;
- graphyard's kept Nyxmon script runs through its check-mode wrapper against
  a real SQLite database with Nyxmon's two tables;
- the registration plans those steps in the playbook's order on the fake host,
  with the credential file written as Ansible's ``copy`` writes it and no
  secret on a command line.

ops-control's tests compare each kept script with its playbook's text.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import time
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pyinfra.api import DeployError

from ops_deploy.services._echoport_runner.nyxmon import (
    CODE,
    NO_DATABASE,
    NyxmonScript,
    nyxmon_script,
    nyxmon_scripts,
    nyxmon_stdin,
    upsert_nyxmon_script,
)
from ops_deploy.services._echoport_runner.registration import CredentialFile, RunnerRegistration, install_registration
from ops_deploy.services._echoport_runner.render import render_text
from ops_deploy.services._echoport_runner.target import (
    RunnerTarget,
    ServiceToken,
    target_code,
    target_script,
    target_scripts,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests import test_echoport_runner_registration as a1
from tests.test_echoport_runner_target import DB, Field, Manager, Model, QuerySet, Transactions, jwt

# -- a stand-in for Echoport's BackupTarget with every field the scripts write ----------------


class BackupTargetMode:
    GENERIC_PATHS = "generic_paths"
    SERVICE_OWNED = "service_owned"


FIELDS = {
    "name": "",
    "description": "",
    "icon": "",
    "fastdeploy_service": "",
    "fastdeploy_endpoint_key": "",
    "service_token": "",
    "service_name": "",
    "restore_owner": "",
    "target_mode": "generic_paths",
    "db_path": "",
    "backup_files": [],
    "schedule": "",
    "schedule_required": False,
    "status": "active",
    "retention_days": 30,
    "timeout_seconds": 900,
    "storage_bucket": "backups",
    "storage_alias": "",
}
INTS = {"retention_days", "timeout_seconds"}


class BackupTarget(Model):
    fields: ClassVar[list[Field]] = [
        *(Field(name, kind=int if name in INTS else str) for name in FIELDS),
        Field("updated_at", auto_now=True),
    ]
    defaults: ClassVar[dict[str, Any]] = {**FIELDS, "updated_at": 0.0}

    def full_clean(self) -> None:
        schedule: str = getattr(self, "schedule")  # noqa: B009 - set from ``fields``
        if schedule and len(schedule.split()) != 5:
            raise ValueError("{'schedule': ['Invalid cron expression']}")


BackupTarget._meta = types.SimpleNamespace(  # type: ignore[attr-defined]
    concrete_fields=BackupTarget.fields,
    db_table="backups_backuptarget",
    get_fields=lambda: BackupTarget.fields,
)
BackupTarget.objects = Manager(BackupTarget)  # type: ignore[attr-defined]
BackupTarget._base_manager = BackupTarget.objects  # type: ignore[attr-defined]


class Introspection:
    columns: ClassVar[list[str]] = [*FIELDS, "updated_at"]

    def get_table_description(self, cursor: Any, table: str) -> list[Any]:
        return [types.SimpleNamespace(name=name) for name in self.columns]


class Connection:
    introspection = Introspection()

    @contextlib.contextmanager
    def cursor(self) -> Iterator[None]:
        yield None


@pytest.fixture(autouse=True)
def echoport(monkeypatch: pytest.MonkeyPatch) -> None:
    DB.rows, DB.writes = {}, 0
    db = types.ModuleType("django.db")
    db.models = types.SimpleNamespace(Model=Model, QuerySet=QuerySet)  # type: ignore[attr-defined]
    db.transaction = Transactions()  # type: ignore[attr-defined]
    db.connection = Connection()  # type: ignore[attr-defined]
    django = types.ModuleType("django")
    django.db = db  # type: ignore[attr-defined]
    backups_models = types.ModuleType("backups.models")
    backups_models.BackupTarget = BackupTarget  # type: ignore[attr-defined]
    backups_models.BackupTargetMode = BackupTargetMode  # type: ignore[attr-defined]
    for name, module in {
        "django": django,
        "django.db": db,
        "backups": types.ModuleType("backups"),
        "backups.models": backups_models,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)


# Values as ops-control resolves them from the playbooks (mail-db, postfixadmin, graphyard).
SERVICE_OWNED = {
    "target_name": "mail-db",
    "allow_reactivation": False,
    "target_description": "Mail PostgreSQL database",
    "service_name_fd": "mail-db-backup",
    "target_service_name": "postgresql",
    "target_schedule": "15 5 * * *",
    "target_status": "active",
    "target_retention_days": 30,
    "target_timeout_seconds": 1800,
    "default_bucket": "backups",
}
POSTFIXADMIN = {
    "target_name": "postfixadmin",
    "service_name_fd": "postfixadmin-backup",
    "allow_reactivation": False,
    "target_schedule": "45 4 * * *",
    "target_retention_days": 30,
    "target_timeout_seconds": 1800,
}
GRAPHYARD = {
    "target_name": "graphyard",
    "target_description": "Graphyard backup",
    "service_name_fd": "graphyard-backup",
    "target_service_name": "graphyard-web",
    "target_restore_owner": "graphyard:graphyard",
    "db_path": "/opt/apps/graphyard/site/src/django/db.sqlite3",
    "target_schedule": "30 4 * * *",
    "target_status": "active",
    "target_retention_days": 14,
    "target_timeout_seconds": 3600,
    "default_bucket": "backups",
}
# heis-production's (villakunterbunt-staging's script is the same text).
REMOTE_SQLITE_SITE = {
    "target_name": "heis-production",
    "target_description": "Heis production backup via service-owned remote FastDeploy runner",
    "service_name_fd": "heis-production-backup",
    "target_schedule": "35 3 * * *",
    "target_retention_days": 30,
    "target_timeout_seconds": 1800,
    "default_bucket": "backups",
}
GOOD = jwt(type="service", service="mail-db-backup", jti="abc", exp=int(time.time()) + 60 * 86400)


def token(service: str) -> ServiceToken:
    return ServiceToken(targets=(service.removesuffix("-backup"),), service=service)


def kept(script: str, values: dict[str, Any], *, with_token: bool = True) -> RunnerTarget:
    service = str(values["service_name_fd"])
    return RunnerTarget(
        name=str(values["target_name"]),
        script=target_script(script),
        values=values,
        token=token(service) if with_token else None,
    )


def run(cfg: RunnerTarget, mode: str, stdin: str = "") -> str:
    """The prelude as ``manage.py shell -c`` runs it; its last stdout line."""

    out, old_in = io.StringIO(), sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out):
            exec(compile(target_code(cfg, mode), "<shell>", "exec"), {"__name__": "__main__"})  # type: ignore[arg-type]
    finally:
        sys.stdin = old_in
    return out.getvalue().strip().splitlines()[-1]


def row(name: str) -> dict[str, Any]:
    (found,) = [r for r in DB.rows.values() if r["name"] == name]
    return found


def store(**values: Any) -> None:
    pk = max(DB.rows, default=0) + 1
    DB.rows[pk] = {"id": pk, **FIELDS, "updated_at": 1.0, **values}


def token_for(service: str) -> str:
    return jwt(type="service", service=service, jti="abc", exp=int(time.time()) + 60 * 86400)


# -- the kept target scripts ---------------------------------------------------------------


def test_the_kept_scripts() -> None:
    assert target_scripts() == (
        "gotosocial",
        "graphyard",
        "marina_production",
        "mastodon_production_db",
        "postfixadmin",
        "remote_sqlite_site",
        "service_owned",
    )
    for name in target_scripts():
        text = target_script(name)
        assert "{{" not in text
        assert "storage_alias" not in text
    with pytest.raises(ValueError, match="not a kept target script"):
        target_script("../runner_target")


@pytest.mark.parametrize(
    ("script", "values"),
    [("service_owned", SERVICE_OWNED), ("graphyard", GRAPHYARD), ("remote_sqlite_site", REMOTE_SQLITE_SITE)],
)
def test_a_new_row_is_created_by_apply_and_then_unchanged(script: str, values: dict[str, Any]) -> None:
    cfg = kept(script, values)
    fresh = token_for(str(values["service_name_fd"]))

    assert run(cfg, "check") == "pending"
    assert DB.rows == {}
    assert run(cfg, "apply") == "need-token"
    assert run(cfg, "apply", f"{fresh}\n") == "applied"
    stored = row(str(values["target_name"]))
    assert stored["service_token"] == fresh
    assert stored["target_mode"] == "service_owned"
    assert stored["storage_bucket"] == "backups"
    assert stored["storage_alias"] == ""
    # The check a converged row gets: nothing to write, no updated_at bump.
    before = DB.snapshot()
    assert run(cfg, "check") == "unchanged"
    assert DB.rows == before


@pytest.mark.parametrize(
    ("script", "values", "drift"),
    [
        *(
            ("service_owned", SERVICE_OWNED, {field: value})
            for field, value in {
                "description": "old",
                "icon": "x",
                "fastdeploy_service": "other",
                "fastdeploy_endpoint_key": "k",
                "service_name": "other",
                "restore_owner": "a:b",
                "target_mode": "generic_paths",
                "db_path": "/x",
                "backup_files": ["/x"],
                "schedule": "0 1 * * *",
                "schedule_required": False,
                "retention_days": 7,
                "timeout_seconds": 900,
                "storage_bucket": "other",
            }.items()
        ),
        ("graphyard", GRAPHYARD, {"restore_owner": ""}),
        ("graphyard", GRAPHYARD, {"db_path": ""}),
        ("graphyard", GRAPHYARD, {"timeout_seconds": 900}),
    ],
)
def test_each_owned_field_that_drifts_is_pending(script: str, values: dict[str, Any], drift: dict[str, Any]) -> None:
    cfg = kept(script, values)
    service = str(values["service_name_fd"])
    assert run(cfg, "apply", f"{token_for(service)}\n") == "applied"
    row(str(values["target_name"])).update(drift)
    before = DB.snapshot()

    assert run(cfg, "check") == "pending"
    assert DB.rows == before


def test_storage_alias_and_unowned_fields_are_left_alone() -> None:
    cfg = kept("service_owned", SERVICE_OWNED)
    assert run(cfg, "apply", f"{token_for('mail-db-backup')}\n") == "applied"
    row("mail-db")["storage_alias"] = "rustfs"

    assert run(cfg, "check") == "unchanged"
    assert run(cfg, "apply") == "applied"
    assert row("mail-db")["storage_alias"] == "rustfs"


def test_a_paused_target_refuses_unless_allowed() -> None:
    store(name="mail-db", status="paused", service_token=token_for("mail-db-backup"))
    before = DB.snapshot()

    assert run(kept("service_owned", SERVICE_OWNED), "check") == (
        "refused: RuntimeError: Refusing implicit reactivation from status=paused"
    )
    assert DB.rows == before
    allowed = kept("service_owned", {**SERVICE_OWNED, "allow_reactivation": True})
    assert run(allowed, "check") == "pending"


def test_graphyard_has_no_reactivation_guard_and_reactivates_as_today() -> None:
    cfg = kept("graphyard", GRAPHYARD)
    assert run(cfg, "apply", f"{token_for('graphyard-backup')}\n") == "applied"
    row("graphyard")["status"] = "paused"

    assert run(cfg, "check") == "pending"
    assert run(cfg, "apply") == "applied"
    assert row("graphyard")["status"] == "active"
    # It never sets schedule_required.
    assert row("graphyard")["schedule_required"] is False


def test_heis_and_villakunterbunt_reactivate_and_clear_the_service_fields_as_today() -> None:
    cfg = kept("remote_sqlite_site", REMOTE_SQLITE_SITE)
    assert run(cfg, "apply", f"{token_for('heis-production-backup')}\n") == "applied"
    row("heis-production").update(status="paused", service_name="heis", restore_owner="heis:heis")

    assert run(cfg, "check") == "pending"
    assert run(cfg, "apply") == "applied"
    stored = row("heis-production")
    assert (stored["status"], stored["service_name"], stored["restore_owner"]) == ("active", "", "")
    assert stored["schedule_required"] is False


def test_postfixadmin_converges_an_existing_row_only() -> None:
    cfg = kept("postfixadmin", POSTFIXADMIN, with_token=False)

    assert run(cfg, "check").startswith("refused: RuntimeError: BackupTarget 'postfixadmin' does not exist.")
    store(name="postfixadmin", target_mode="service_owned", fastdeploy_service="postfixadmin-backup", description="x")
    assert run(cfg, "check") == "pending"
    assert run(cfg, "apply") == "applied"
    stored = row("postfixadmin")
    assert (stored["schedule"], stored["schedule_required"], stored["retention_days"]) == ("45 4 * * *", True, 30)
    assert stored["timeout_seconds"] == 1800
    assert stored["description"] == "x"
    assert run(cfg, "check") == "unchanged"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"target_mode": "generic_paths"}, "Unexpected BackupTarget wiring"),
        ({"fastdeploy_service": "other"}, "Unexpected BackupTarget wiring"),
        ({"status": "paused"}, "Refusing implicit reactivation from status=paused"),
    ],
)
def test_postfixadmins_refusals(changes: dict[str, Any], message: str) -> None:
    store(
        **{
            "name": "postfixadmin",
            "target_mode": "service_owned",
            "fastdeploy_service": "postfixadmin-backup",
            **changes,
        }
    )
    before = DB.snapshot()

    assert message in run(kept("postfixadmin", POSTFIXADMIN, with_token=False), "check")
    assert DB.rows == before


def test_postfixadmin_refuses_an_echoport_without_schedule_required(monkeypatch: pytest.MonkeyPatch) -> None:
    store(name="postfixadmin", target_mode="service_owned", fastdeploy_service="postfixadmin-backup")
    monkeypatch.setattr(Introspection, "columns", [c for c in Introspection.columns if c != "schedule_required"])

    assert "lacks schedule_required" in run(kept("postfixadmin", POSTFIXADMIN, with_token=False), "check")


# -- graphyard's Nyxmon script ----------------------------------------------------------------

CHECK_NAME = "Graphyard Backup Freshness (Echoport)"
CHECKS = [
    {
        "name": CHECK_NAME,
        "check_type": "json-metrics",
        "url": "http://127.0.0.1:10018/api/health/",
        "check_interval": 300,
        "data": {"url": "http://127.0.0.1:10018/api/health/", "timeout": 10.0, "checks": [{"path": "$.x"}]},
    }
]
SCHEMA = """
CREATE TABLE service (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE);
CREATE TABLE health_check (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, service_id INTEGER, check_type TEXT, url TEXT,
    check_interval INTEGER, status TEXT, next_check_time INTEGER, processing_started_at INTEGER,
    disabled INTEGER, data TEXT
);
"""


def nyxmon(db: Path, checks: list[dict[str, Any]] = CHECKS) -> NyxmonScript:
    return NyxmonScript(
        name=CHECK_NAME,
        script=nyxmon_script("graphyard"),
        values={"_nyxmon_checks_json": json.dumps(checks)},
        service_name="Graphyard (macmini)",
        db_path=db,
    )


@pytest.fixture
def nyxmon_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "db.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.executescript(SCHEMA)
    monkeypatch.setenv("NYXMON_DB_PATH", str(db))
    monkeypatch.setenv("NYXMON_SERVICE_NAME", "Graphyard (macmini)")
    return db


def run_nyxmon(script: NyxmonScript, mode: str) -> list[str]:
    """``CODE`` as ``python3 -I -c`` runs it, ``PARAMS`` on stdin; its stdout lines."""

    out, old_in = io.StringIO(), sys.stdin
    sys.stdin = io.StringIO(nyxmon_stdin(script, mode))  # type: ignore[arg-type]
    try:
        with contextlib.redirect_stdout(out):
            exec(compile(CODE, "<nyxmon>", "exec"), {"__name__": "__main__"})
    finally:
        sys.stdin = old_in
    return out.getvalue().strip().splitlines()


def table(db: Path) -> list[Any]:
    with contextlib.closing(sqlite3.connect(db)) as conn:
        return conn.execute(
            "select name, service_id, check_type, url, check_interval, disabled, data from health_check"
        ).fetchall()


def test_nyxmon_scripts() -> None:
    assert nyxmon_scripts() == ("graphyard",)
    assert "{{" not in nyxmon_script("graphyard")


def test_the_nyxmon_check_writes_nothing_and_apply_converges(nyxmon_db: Path) -> None:
    script = nyxmon(nyxmon_db)

    assert run_nyxmon(script, "check") == ["pending"]
    assert table(nyxmon_db) == []
    assert run_nyxmon(script, "apply") == ["changed=true", "applied"]
    assert run_nyxmon(script, "check") == ["unchanged"]
    assert run_nyxmon(script, "apply") == ["changed=false", "applied"]
    (stored,) = table(nyxmon_db)
    assert stored[0] == CHECK_NAME
    assert json.loads(stored[6]) == CHECKS[0]["data"]


def test_a_drifted_nyxmon_check_is_pending_and_reenabled(nyxmon_db: Path) -> None:
    script = nyxmon(nyxmon_db)
    run_nyxmon(script, "apply")
    with sqlite3.connect(nyxmon_db) as conn:
        conn.execute("update health_check set check_interval = 60, disabled = 1")
    before = table(nyxmon_db)

    assert run_nyxmon(script, "check") == ["pending"]
    assert table(nyxmon_db) == before
    run_nyxmon(script, "apply")
    assert table(nyxmon_db)[0][4:6] == (300, 0)


def test_a_disabled_but_current_nyxmon_check_stays_disabled_as_today(nyxmon_db: Path) -> None:
    script = nyxmon(nyxmon_db)
    run_nyxmon(script, "apply")
    with sqlite3.connect(nyxmon_db) as conn:
        conn.execute("update health_check set disabled = 1")

    assert run_nyxmon(script, "check") == ["unchanged"]


def test_a_broken_nyxmon_database_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "empty.sqlite3"
    sqlite3.connect(db).close()
    monkeypatch.setenv("NYXMON_DB_PATH", str(db))
    monkeypatch.setenv("NYXMON_SERVICE_NAME", "Graphyard (macmini)")

    (answer,) = run_nyxmon(nyxmon(db), "check")
    assert answer.startswith("refused: OperationalError: no such table: service")


def test_nyxmon_values_that_look_like_a_secret_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must not hold a secret"):
        NyxmonScript(name="x", script="x", values={"monitor_password": "x"}, service_name="x")


def nyxmon_key(script: NyxmonScript) -> str:
    """A text only the Nyxmon check command carries (its environment)."""

    return f"NYXMON_DB_PATH={script.db_path}"


@pytest.mark.parametrize(("answer", "ops"), [(NO_DATABASE, []), ("unchanged", [])])
def test_without_a_database_or_unchanged_nothing_is_planned(answer: str, ops: list[str]) -> None:
    script = nyxmon(Path("/home/nyxmon/site/db.sqlite3"))
    fake = run_deploy_fake(lambda: upsert_nyxmon_script(script), responses={nyxmon_key(script): [answer]})

    assert fake.succeeded, fake.error
    assert [op.name for op in fake.ops] == ops


def test_a_pending_nyxmon_check_applies_once_and_probes_again() -> None:
    script = nyxmon(Path("/home/nyxmon/site/db.sqlite3"))
    fake = run_deploy_fake(lambda: upsert_nyxmon_script(script), responses={nyxmon_key(script): ["pending"]})

    assert fake.succeeded, fake.error
    assert [op.name for op in fake.ops] == [
        f"Upsert Nyxmon check {CHECK_NAME}",
        f"Probe again: Nyxmon check {CHECK_NAME}",
    ]
    apply = fake.executed_commands[0]
    assert "runuser -u nyxmon -- env HOME=/home/nyxmon NYXMON_DB_PATH=/home/nyxmon/site/db.sqlite3" in apply
    assert "'NYXMON_SERVICE_NAME=Graphyard (macmini)' python3 -I -c" in apply
    # The check data travels on stdin only: the apply's and the probes'.
    assert [stdin for command, stdin in fake.stdin if command == apply] == [nyxmon_stdin(script, "apply")]
    assert nyxmon_stdin(script, "check") in [stdin for _command, stdin in fake.stdin]
    assert nyxmon_stdin(script, "check").strip() not in " ".join(fake.executed_commands)


def test_a_refused_nyxmon_check_stops_while_planning() -> None:
    script = nyxmon(Path("/home/nyxmon/site/db.sqlite3"))
    fake = run_deploy_fake(lambda: upsert_nyxmon_script(script), responses={nyxmon_key(script): ["refused: x"]})

    assert isinstance(fake.error, DeployError)
    assert fake.executed_commands == []


# -- the credential file ------------------------------------------------------------------------

# postfixadmin's `copy: content:`, unchanged.
POSTFIXADMIN_CONTENT = """{
  "host": {{ postfixadmin_echoport_backup_db_host | to_json }},
  "port": {{ postfixadmin_echoport_backup_db_port | int }},
  "database": {{ postfixadmin_echoport_backup_db_name | to_json }},
  "username": {{ postfixadmin_echoport_backup_db_user | to_json }},
  "password": {{ postfixadmin_echoport_backup_db_password | to_json }}
}
"""
DB_PASSWORD = 'fixture-pä"ss-0123456789'  # pragma: allowlist secret
# What ansible-core 2.21's copy wrote for these values (ASCII escapes, the final newline kept).
ANSIBLE_WROTE = (
    '{\n  "host": "127.0.0.1",\n  "port": 5432,\n  "database": "mail",\n  "username": "mail",\n'
    '  "password": "fixture-p\\u00e4\\"ss-0123456789"\n}\n'
)


def credential_file(**changes: Any) -> CredentialFile:
    values: dict[str, Any] = {
        "path": "/etc/echoport-backups/postfixadmin-db.json",
        "template": POSTFIXADMIN_CONTENT,
        "variables": {
            "postfixadmin_echoport_backup_db_host": "127.0.0.1",
            "postfixadmin_echoport_backup_db_port": 5432,
            "postfixadmin_echoport_backup_db_name": "mail",
            "postfixadmin_echoport_backup_db_user": "mail",
        },
        "secrets": ("postfixadmin_echoport_backup_db_password",),
        **changes,
    }
    return CredentialFile(**values)


def test_the_credential_file_is_what_ansibles_copy_wrote() -> None:
    content = credential_file().content({"postfixadmin_echoport_backup_db_password": DB_PASSWORD})

    assert content == ANSIBLE_WROTE
    assert render_text("{{ x }}\n", {"x": 1}) == "1\n"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"secrets": ("other",)}, "the template reads"),
        ({"variables": {}}, "the template reads"),
        ({"path": "/x.json"}, "plain absolute path"),
        ({"path": "/etc/../x.json"}, "plain absolute path"),
    ],
)
def test_a_credential_file_with_other_names_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        credential_file(**changes)


def test_a_credential_file_needs_exactly_its_secrets() -> None:
    with pytest.raises(DeployError, match="needs exactly the secrets"):
        credential_file().content({})


# -- the registration ----------------------------------------------------------------------------

USER = "fixture-fastdeploy-user"


def registration(name: str, **changes: Any) -> RunnerRegistration:
    return a1.registration(name, **changes)


def check_key(cfg: RunnerTarget) -> str:
    return target_code(cfg, "check").splitlines()[1]


def test_a_converged_class_b_host_gets_no_mutating_operation(tmp_path: Path) -> None:
    target = kept("graphyard", GRAPHYARD)
    script = nyxmon(Path("/home/nyxmon/site/db.sqlite3"))
    cfg = registration("graphyard-backup", target=target, nyxmon=script)
    responses = {**a1.converged(cfg), check_key(target): ["unchanged"], nyxmon_key(script): ["unchanged"]}
    fake = run_deploy_fake(
        lambda: install_registration(cfg, secret_key=a1.SECRET, token_user=USER), responses=responses
    )

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == []
    assert USER not in fake.all_text()


def test_a_converged_postfixadmin_host_gets_no_mutating_operation() -> None:
    target = kept("postfixadmin", POSTFIXADMIN, with_token=False)
    cfg = registration("postfixadmin-backup", target=target, credential_files=(credential_file(),))
    path = "/etc/echoport-backups/postfixadmin-db.json"
    responses = {
        **a1.converged(cfg),
        check_key(target): ["unchanged"],
        **fakehost.directory("/etc/echoport-backups", mode="drwx------"),
        **fakehost.file(path, ANSIBLE_WROTE, mode="-rw-------"),
    }
    secrets = {"postfixadmin_echoport_backup_db_password": DB_PASSWORD}
    fake = run_deploy_fake(
        lambda: install_registration(cfg, secret_key=a1.SECRET, credentials=secrets), responses=responses
    )

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == []
    for leaked in (DB_PASSWORD, json.dumps(DB_PASSWORD), "0123456789"):
        assert leaked not in fake.all_text()


def test_a_nyxmon_script_that_does_not_connect_through_the_module_is_refused() -> None:
    for script in ("print('changed=false')\n", "from sqlite3 import connect\nconn = sqlite3.connect(x)\n"):
        with pytest.raises(ValueError, match=r"sqlite3\.connect"):
            NyxmonScript(name="x", script=script, values={}, service_name="x")


def test_the_class_b_steps_follow_the_runner_in_the_playbooks_order() -> None:
    target = kept("graphyard", GRAPHYARD)
    script = nyxmon(Path("/home/nyxmon/site/db.sqlite3"))
    cfg = registration("graphyard-backup", target=target, nyxmon=script)
    responses = {**a1.converged(cfg), check_key(target): ["pending"], nyxmon_key(script): ["pending"]}
    fake = run_deploy_fake(
        lambda: install_registration(cfg, secret_key=a1.SECRET, token_user=USER), responses=responses
    )

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == [
        "Issue or reuse the FastDeploy token and upsert the Echoport backup target graphyard",
        f"Upsert Nyxmon check {CHECK_NAME}",
    ]
    assert [stdin for command, stdin in fake.stdin if "issueservicetoken" in command] == [f"{USER}\n"]
    assert USER not in fake.all_text()


def test_a_target_refusal_stops_before_any_write() -> None:
    target = kept("service_owned", SERVICE_OWNED)
    cfg = registration("mail-db-backup", target=target)
    responses = {**a1.converged(cfg), check_key(target): ["refused: RuntimeError: Refusing implicit reactivation"]}
    fake = run_deploy_fake(
        lambda: install_registration(cfg, secret_key=a1.SECRET, token_user=USER), responses=responses
    )

    assert "Refusing implicit reactivation" in a1.refused(fake)


def test_a_token_target_needs_the_token_user() -> None:
    cfg = registration("mail-db-backup", target=kept("service_owned", SERVICE_OWNED))
    fake = run_deploy_fake(lambda: install_registration(cfg, secret_key=a1.SECRET), responses=a1.converged(cfg))

    assert "needs the token user" in a1.refused(fake)


def test_postfixadmins_credential_file_and_target_without_token() -> None:
    target = kept("postfixadmin", POSTFIXADMIN, with_token=False)
    cfg = registration("postfixadmin-backup", target=target, credential_files=(credential_file(),))
    secrets = {"postfixadmin_echoport_backup_db_password": DB_PASSWORD}
    responses = {**a1.converged(cfg), check_key(target): ["pending"]}
    fake = run_deploy_fake(
        lambda: install_registration(cfg, secret_key=a1.SECRET, credentials=secrets), responses=responses
    )

    assert fake.succeeded, fake.error
    names = fake.mutating_changed_ops
    assert names[:2] == ["Ensure directory /etc/echoport-backups", "Write /etc/echoport-backups/postfixadmin-db.json"]
    assert names[-1] == "Upsert Echoport backup target postfixadmin"
    payload = next(stdin for command, stdin in fake.stdin if "postfixadmin-db.json" in command)
    assert base64.b64decode(payload).decode() == ANSIBLE_WROTE
    for leaked in (DB_PASSWORD, json.dumps(DB_PASSWORD), "0123456789"):
        assert leaked not in fake.all_text()
    assert "0600" in next(command for command, _ in fake.stdin if "postfixadmin-db.json" in command)


def test_missing_or_extra_credentials_refuse_before_any_write() -> None:
    cfg = registration("postfixadmin-backup", credential_files=(credential_file(),))
    for given in ({}, {"postfixadmin_echoport_backup_db_password": "x", "other": "y"}):
        fake = run_deploy_fake(
            lambda given=given: install_registration(cfg, secret_key=a1.SECRET, credentials=given),
            responses=a1.converged(cfg),
        )
        assert "needs exactly the credentials" in a1.refused(fake)


def test_a_target_bucket_other_than_the_access_is_refused() -> None:
    other = kept("service_owned", {**SERVICE_OWNED, "default_bucket": "other"})
    with pytest.raises(ValueError, match="the target's default_bucket must be the access's bucket"):
        registration("mail-db-backup", target=other)


def test_a_template_marker_the_runner_lacks_is_refused() -> None:
    assert registration("mail-db-backup", template_markers=("def dump_row_counts",)).template_markers
    with pytest.raises(ValueError, match="lacks 'not in the runner'"):
        registration("mail-db-backup", template_markers=("not in the runner",))


# -- against Echoport's own models (optional) -------------------------------------------------

ECHOPORT = os.environ.get("ECHOPORT_PATH")
ORACLE = """\
import io, json, os, sys
sys.path[:0] = [os.path.join(sys.argv[1], "src/django"), os.path.join(sys.argv[1], "src")]
os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings.test"
import django
django.setup()
from django.core.management import call_command
call_command("migrate", verbosity=0)
from backups.models import BackupTarget
fields = [f.name for f in BackupTarget._meta.concrete_fields if f.name not in ("id", "created_at", "updated_at")]
answers = []
for case in json.loads(sys.stdin.read()):
    if "row" in case:
        BackupTarget.objects.all().delete()
        if case["row"]:
            BackupTarget(**case["row"]).save()
    out, old_out, old_in = io.StringIO(), sys.stdout, sys.stdin
    sys.stdout, sys.stdin = out, io.StringIO(case.get("stdin", ""))
    try:
        exec(compile(case["code"], "<shell>", "exec"), {"__name__": "__main__"})
    finally:
        sys.stdout, sys.stdin = old_out, old_in
    stored = BackupTarget.objects.filter(name=case["name"]).values(*fields, "updated_at").first()
    stored = stored and {**stored, "updated_at": str(stored["updated_at"])}
    answers.append([out.getvalue().strip().splitlines()[-1], stored])
print(json.dumps(answers))
"""


def oracle(cases: list[dict[str, Any]], tmp_path: Path) -> list[Any]:
    assert ECHOPORT is not None
    result = subprocess.run(
        [str(Path(ECHOPORT) / ".venv/bin/python"), "-c", ORACLE, ECHOPORT],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-3000:]
    answers: list[Any] = json.loads(result.stdout.strip().splitlines()[-1])
    return answers


@pytest.mark.skipif(not ECHOPORT, reason="ECHOPORT_PATH (an Echoport checkout with its .venv) not set")
@pytest.mark.parametrize(("script", "values"), [("service_owned", SERVICE_OWNED), ("graphyard", GRAPHYARD)])
def test_the_kept_scripts_against_echoports_own_models(script: str, values: dict[str, Any], tmp_path: Path) -> None:
    cfg = kept(script, values)
    name = str(values["target_name"])
    fresh = token_for(str(values["service_name_fd"]))
    paused = {
        "name": name,
        "status": "paused",
        "service_token": fresh,
        "fastdeploy_service": values["service_name_fd"],
        "target_mode": "service_owned",
        "service_name": values["target_service_name"],
        "schedule": "0 1 * * *",
    }
    cases: list[dict[str, Any]] = [
        {"row": None, "name": name, "code": target_code(cfg, "check")},
        {"name": name, "code": target_code(cfg, "apply"), "stdin": f"{fresh}\n"},
        {"name": name, "code": target_code(cfg, "check")},
        {"name": name, "code": target_code(kept(script, {**values, "target_schedule": "5 5 * * *"}), "check")},
        {"row": paused, "name": name, "code": target_code(cfg, "check")},
    ]
    (new, _), (applied, stored), (converged, after), (drift, _), (on_paused, _) = oracle(cases, tmp_path)

    assert (new, applied, converged, drift) == ("pending", "applied", "unchanged", "pending")
    # The check wrote nothing: not even updated_at moved.
    assert after == stored
    assert stored["service_token"] == fresh
    assert stored["target_mode"] == "service_owned"
    # Echoport's default; no registration writes it.
    assert stored["storage_alias"] == "minio"
    if script == "graphyard":
        assert on_paused == "pending"
    else:
        assert on_paused == "refused: RuntimeError: Refusing implicit reactivation from status=paused"


@pytest.mark.skipif(not ECHOPORT, reason="ECHOPORT_PATH (an Echoport checkout with its .venv) not set")
def test_postfixadmin_against_echoports_own_models(tmp_path: Path) -> None:
    cfg = kept("postfixadmin", POSTFIXADMIN, with_token=False)
    existing = {
        "name": "postfixadmin",
        "target_mode": "service_owned",
        "fastdeploy_service": "postfixadmin-backup",
        "service_name": "nginx",
        "schedule": "",
        "retention_days": 14,
    }
    cases: list[dict[str, Any]] = [
        {"row": None, "name": "postfixadmin", "code": target_code(cfg, "check")},
        {"row": existing, "name": "postfixadmin", "code": target_code(cfg, "check")},
        {"name": "postfixadmin", "code": target_code(cfg, "apply")},
        {"name": "postfixadmin", "code": target_code(cfg, "check")},
    ]
    (missing, _), (pending, _), (applied, stored), (converged, after) = oracle(cases, tmp_path)

    assert missing.startswith("refused: RuntimeError: BackupTarget 'postfixadmin' does not exist.")
    assert (pending, applied, converged) == ("pending", "applied", "unchanged")
    assert (stored["schedule"], stored["schedule_required"], stored["retention_days"]) == ("45 4 * * *", True, 30)
    assert after == stored


# -- class B part 2: the remote runners (deploy user) ---------------------------------------

MASTODON = {
    **SERVICE_OWNED,
    "target_name": "mastodon-production-db",
    "service_name_fd": "mastodon-production-db-backup",
    "target_service_name": "mastodon",
    "target_schedule": "50 5 * * *",
}
MARINA = {
    "target_name": "marina-production",
    "allow_reactivation": False,
    "target_description": "Marina production",
    "service_name_fd": "marina-production-backup",
    "service_name": "marina.service",
    "restore_owner": "marina:marina",
    "default_db_path": "/home/marina/site/db.sqlite3",
    "files": ["/home/marina/site/media"],
    "target_schedule": "35 3 * * *",
    "target_status": "active",
    "target_retention_days": 30,
    "target_timeout_seconds": 3600,
    "default_bucket": "backups",
}
GOTOSOCIAL = {
    "target_name": "gotosocial",
    "allow_reactivation": False,
    "target_description": "GoToSocial",
    "service_name_fd": "gotosocial-backup",
    "target_service_name": "gotosocial",
    "target_schedule": "25 1 * * *",
    "target_status": "active",
    "target_retention_days": 30,
    "target_timeout_seconds": 1800,
    "echoport_backup_default_bucket": "backups",
}
REMOTE = (("mastodon_production_db", MASTODON), ("marina_production", MARINA), ("gotosocial", GOTOSOCIAL))


@pytest.fixture
def exclude(monkeypatch: pytest.MonkeyPatch) -> None:
    """``QuerySet.exclude`` and ``Manager.exclude`` (gotosocial's schedule check reads the other targets)."""

    def queryset_exclude(self: QuerySet, **lookup: Any) -> QuerySet:
        keep = [pk for pk in self.pks if not all(DB.rows[pk].get(k) == v for k, v in lookup.items())]
        return QuerySet(self.model, keep)

    def manager_exclude(self: Manager, **lookup: Any) -> QuerySet:
        return queryset_exclude(QuerySet(self.model, sorted(DB.rows)), **lookup)

    def iterate(self: QuerySet) -> Iterator[Model]:
        return iter([self.model.load(pk) for pk in self.pks])

    monkeypatch.setattr(QuerySet, "exclude", queryset_exclude, raising=False)
    monkeypatch.setattr(QuerySet, "__iter__", iterate, raising=False)
    monkeypatch.setattr(Manager, "exclude", manager_exclude, raising=False)


def test_the_kept_scripts_of_part_2() -> None:
    assert set(target_scripts()) >= {"mastodon_production_db", "marina_production", "gotosocial"}


@pytest.mark.usefixtures("exclude")
@pytest.mark.parametrize(("script", "values"), REMOTE)
def test_a_remote_target_is_created_by_apply_and_then_unchanged(script: str, values: dict[str, Any]) -> None:
    cfg = kept(script, values)
    fresh = token_for(str(values["service_name_fd"]))

    assert run(cfg, "check") == "pending"
    assert run(cfg, "apply", f"{fresh}\n") == "applied"
    stored = row(str(values["target_name"]))
    assert (stored["service_token"], stored["target_mode"], stored["storage_alias"]) == (fresh, "service_owned", "")
    before = DB.snapshot()
    assert run(cfg, "check") == "unchanged"
    assert run(cfg, "apply") == "applied"
    # mastodon's and marina's scripts save only on a change; gotosocial's always, the check none.
    if script != "gotosocial":
        assert DB.rows == before
    row(str(values["target_name"]))["schedule"] = "0 0 * * *"
    assert run(cfg, "check") == "pending"


@pytest.mark.usefixtures("exclude")
@pytest.mark.parametrize(("script", "values"), REMOTE)
def test_a_paused_remote_target_is_refused(script: str, values: dict[str, Any]) -> None:
    store(name=values["target_name"], status="paused", fastdeploy_service=values["service_name_fd"])

    assert run(kept(script, values), "check") == (
        "refused: RuntimeError: Refusing implicit reactivation from status=paused"
    )


@pytest.mark.usefixtures("exclude")
def test_gotosocials_schedule_and_wiring_refusals() -> None:
    cfg = kept("gotosocial", GOTOSOCIAL)
    store(name="vaultwarden", status="active", schedule="20 1 * * *")
    before = DB.snapshot()

    assert "is within 10 minutes of: vaultwarden (20 1 * * *)" in run(cfg, "check")
    DB.rows[1]["status"] = "paused"
    store(name="gotosocial", fastdeploy_service="other-backup", service_token=token_for("gotosocial-backup"))
    assert "existing target is wired to 'other-backup'" in run(cfg, "check")
    hourly = kept("gotosocial", {**GOTOSOCIAL, "target_schedule": "25 * * * *"})
    assert "is not a plain daily" in run(hourly, "check")
    assert {pk: r for pk, r in DB.rows.items() if pk == 1}[1]["name"] == before[1]["name"]


# Their deploy-user registrations, with the class B parts on the fake host.
REMOTE_TASKS: dict[str, tuple[str, ...]] = {
    "django-chat-staging-db-backup": (
        "packages",
        "mc",
        "ssh_key",
        "known_hosts",
        "access",
        "work_dir",
        "runner",
        "target",
    ),
    "mastodon-production-db-backup": (
        "packages",
        "pg_restore",
        "mc",
        "ssh_key",
        "known_hosts",
        "access",
        "work_dir",
        "runner",
        "target",
    ),
    "marina-production-backup": ("packages", "mc", "access", "work_dir", "runner", "known_hosts", "target"),
    "gotosocial-backup": ("mc", "packages", "access", "work_dir", "runner", "known_hosts", "target"),
}
REMOTE_VALUES = {
    "django-chat-staging-db-backup": (
        "service_owned",
        {**SERVICE_OWNED, "target_name": "django-chat-staging-db", "service_name_fd": "django-chat-staging-db-backup"},
    ),
    "mastodon-production-db-backup": ("mastodon_production_db", MASTODON),
    "marina-production-backup": ("marina_production", MARINA),
    "gotosocial-backup": ("gotosocial", GOTOSOCIAL),
}
REMOTE_HOSTS = {"production.example.invalid", "staging.example.invalid"}


def remote(name: str, **changes: Any) -> Any:
    from ops_deploy.services._echoport_runner import RunnerConfig
    from ops_deploy.services._echoport_runner.access import KnownHost, MinioAccess, WorkDir
    from ops_deploy.services._echoport_runner.registration import DeployRunnerRegistration

    inputs = dict(json.loads((a1.PARITY / "inputs.json").read_text())["runners"][name]["inputs"])
    work = next(v for k, v in inputs.items() if k.endswith("_work_dir"))
    script, values = REMOTE_VALUES[name]
    tasks = REMOTE_TASKS[name]
    host = (
        "production.example.invalid"
        if "production" in name or name == "gotosocial-backup"
        else "staging.example.invalid"
    )
    fields: dict[str, Any] = {
        "runner": RunnerConfig(
            service=name,
            description=f"{name} runner",
            steps=("init", "upload", "result"),
            template=json.loads((a1.PARITY / "inputs.json").read_text())["runners"][name]["template"],
        ),
        "access": MinioAccess(
            target=name.removesuffix("-backup"),
            os_user="deploy",
            alias=f"backup-{name.removesuffix('-backup')}",
            url="http://127.0.0.1:9001",
            scoped=True,
            retired_aliases=("minio",),
        ),
        "packages": ("postgresql-client",),
        "variables": {**inputs, "echoport_backup_minio_alias": f"backup-{name.removesuffix('-backup')}"},
        "work_dir": WorkDir(path=work, owner="deploy"),
        "tasks": tasks,
        "known_hosts": (KnownHost(name=host),),
        "ssh_key": "ssh_key" in tasks,
        "ssh_key_public": "ssh_key" not in tasks,
        "min_pg_restore_major": 17 if "pg_restore" in tasks else None,
        "target": kept(script, values),
        **changes,
    }
    return DeployRunnerRegistration(**fields)


def remote_deploy(cfg: Any, **kwargs: Any) -> Any:
    from ops_deploy.services._echoport_runner.registration import DeployKey, install_deploy_registration
    from tests.test_echoport_runner_deploy_registration import PRIVATE, SECRET, scan

    values: dict[str, Any] = {
        "secret_key": SECRET,
        "ssh_key": DeployKey(private=PRIVATE) if cfg.ssh_key else None,
        "keyscan": scan,
        "token_user": USER,
        **kwargs,
    }
    return lambda: install_deploy_registration(cfg, **values)


@pytest.mark.parametrize("name", REMOTE_TASKS)
def test_a_converged_remote_class_b_host_gets_no_mutating_operation(name: str) -> None:
    from tests.test_echoport_runner_deploy_registration import converged as remote_converged

    cfg = remote(name)
    fake = run_deploy_fake(
        remote_deploy(cfg), responses={**remote_converged(cfg), check_key(cfg.target): ["unchanged"]}
    )

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == []
    assert USER not in fake.all_text()
    assert "/home/deploy/.ssh/id_ed25519.pub" not in fake.all_text()


def test_the_remote_target_step_is_last_and_the_token_user_on_stdin() -> None:
    from tests.test_echoport_runner_deploy_registration import converged as remote_converged

    cfg = remote("mastodon-production-db-backup")
    fake = run_deploy_fake(remote_deploy(cfg), responses={**remote_converged(cfg), check_key(cfg.target): ["pending"]})

    assert fake.succeeded, fake.error
    names = [op.name.removeprefix("Echoport backup runner registration | ") for op in fake.ops]
    token = "Issue or reuse the FastDeploy token and upsert the Echoport backup target mastodon-production-db"
    assert names[-2:] == [token, "Probe again: Echoport backup target mastodon-production-db"]
    pg = "Require a pg_restore that reads PostgreSQL 17 dumps"
    assert names.index(pg) > names.index("Install the packages of mastodon-production-db-backup")
    assert pg not in fake.mutating_changed_ops
    check = next(command for command in fake.executed_commands if "pg_restore --version" in command)
    assert "-ge 17 ]" in check
    assert [stdin for command, stdin in fake.stdin if "issueservicetoken" in command] == [f"{USER}\n"]


def test_an_installed_pg_restore_that_is_too_old_refuses_while_planning() -> None:
    from tests.test_echoport_runner_deploy_registration import converged as remote_converged

    cfg = remote("mastodon-production-db-backup")
    probe = "(pg_restore --version 2>/dev/null || true) | grep -o"
    old = {**remote_converged(cfg), check_key(cfg.target): ["unchanged"], probe: ["15"]}
    assert "cannot read a PostgreSQL 17 dump" in a1.refused(run_deploy_fake(remote_deploy(cfg), responses=old))
    for found in (["17"], [""]):
        fake = run_deploy_fake(
            remote_deploy(cfg), responses={**remote_converged(cfg), check_key(cfg.target): ["unchanged"], probe: found}
        )
        assert fake.succeeded, fake.error
    # Without the package installed, its install may bring a newer pg_restore: the runtime check decides.
    missing = {**old, "dpkg -l": ["ii  sqlite3  1.0  all  sqlite3"]}
    fake = run_deploy_fake(remote_deploy(cfg), responses=missing)
    assert fake.succeeded, fake.error
    assert "Require a pg_restore that reads PostgreSQL 17 dumps" in [op.name for op in fake.ops]
    early = ("target", *[t for t in cfg.tasks if t != "target"])
    with pytest.raises(ValueError, match="the target task comes after the runner task"):
        remote("mastodon-production-db-backup", tasks=early)
    with pytest.raises(ValueError, match="the pg_restore task comes after the packages task"):
        remote("mastodon-production-db-backup", tasks=("pg_restore", *[t for t in cfg.tasks if t != "pg_restore"]))


def test_a_remote_class_b_registration_refuses_while_planning() -> None:
    from ops_deploy.services._echoport_runner.registration import DeployKey
    from tests.test_echoport_runner_deploy_registration import PRIVATE, PUBLIC
    from tests.test_echoport_runner_deploy_registration import converged as remote_converged

    cfg = remote("django-chat-staging-db-backup")
    responses = {**remote_converged(cfg), check_key(cfg.target): ["pending"]}
    for kwargs, message in (
        ({"token_user": None}, "needs the token user"),
        ({"ssh_key": DeployKey(private=PRIVATE, public=PUBLIC)}, "public deploy key is needed exactly"),
    ):
        fake = run_deploy_fake(remote_deploy(cfg, **kwargs), responses=responses)
        assert message in a1.refused(fake)
    refusal = {
        **remote_converged(cfg),
        check_key(cfg.target): ["refused: RuntimeError: Refusing implicit reactivation"],
    }
    assert "Refusing implicit reactivation" in a1.refused(run_deploy_fake(remote_deploy(cfg), responses=refusal))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"tasks": REMOTE_TASKS["django-chat-staging-db-backup"][:-1]}, "tasks must name each part exactly once"),
        ({"template_markers": ("not in the runner",)}, "lacks 'not in the runner'"),
        ({"ssh_key": False, "ssh_key_public": False}, "ssh_key_public is about"),
    ],
)
def test_a_remote_class_b_config_the_playbook_refuses_is_refused(changes: dict[str, Any], message: str) -> None:
    if changes.get("ssh_key") is False:
        changes["tasks"] = tuple(t for t in REMOTE_TASKS["django-chat-staging-db-backup"] if t != "ssh_key")
    with pytest.raises(ValueError, match=message):
        remote("django-chat-staging-db-backup", **changes)
    other = kept("service_owned", {**REMOTE_VALUES["django-chat-staging-db-backup"][1], "default_bucket": "x"})
    with pytest.raises(ValueError, match="the target's default_bucket must be the access's bucket"):
        remote("django-chat-staging-db-backup", target=other)


@pytest.mark.skipif(not ECHOPORT, reason="ECHOPORT_PATH (an Echoport checkout with its .venv) not set")
@pytest.mark.parametrize(("script", "values"), REMOTE)
def test_the_remote_kept_scripts_against_echoports_own_models(
    script: str, values: dict[str, Any], tmp_path: Path
) -> None:
    cfg = kept(script, values)
    name = str(values["target_name"])
    fresh = token_for(str(values["service_name_fd"]))
    cases: list[dict[str, Any]] = [
        {"row": None, "name": name, "code": target_code(cfg, "check")},
        {"name": name, "code": target_code(cfg, "apply"), "stdin": f"{fresh}\n"},
        {"name": name, "code": target_code(cfg, "check")},
    ]
    (new, _), (applied, stored), (converged, after) = oracle(cases, tmp_path)

    assert (new, applied, converged) == ("pending", "applied", "unchanged")
    assert after == stored
    assert stored["storage_alias"] == "minio"
