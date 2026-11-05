"""``_echoport_runner.target``: a playbook's own target script with a check mode, and its token step.

``files/runner_target.py`` runs here in-process against a small stand-in for
Django and Echoport's ``BackupTarget`` (an in-memory table with ``save``,
``full_clean``, ``save_base``, querysets and transactions), with the kind of
script a class B register playbook carries.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import io
import json
import os
import re
import sys
import time
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pyinfra.api import DeployError

from ops_deploy.services._echoport_runner.target import (
    PRELUDE,
    RunnerTarget,
    ServiceToken,
    target_code,
    token_and_target,
    upsert_runner_target,
)
from ops_deploy.testing import run_deploy_fake

# -- a stand-in for Django and Echoport ----------------------------------------------


class Field:
    def __init__(self, name: str, *, kind: type = str, auto_now: bool = False) -> None:
        self.name = self.attname = name
        self.kind, self.auto_now, self.auto_now_add = kind, auto_now, False

    def value_from_object(self, obj: Any) -> Any:
        return getattr(obj, self.attname)

    def to_python(self, value: Any) -> Any:
        return int(value) if self.kind is int and value is not None else value


class Database:
    def __init__(self) -> None:
        self.rows: dict[int, dict[str, Any]] = {}
        self.writes = 0

    def snapshot(self) -> dict[int, dict[str, Any]]:
        return copy.deepcopy(self.rows)


DB = Database()


class State:
    def __init__(self, adding: bool) -> None:
        self.adding = adding


class QuerySet:
    def __init__(self, model: type[Model], pks: list[int]) -> None:
        self.model, self.pks = model, pks

    def filter(self, **lookup: Any) -> QuerySet:
        if "pk" in lookup:
            lookup["id"] = lookup.pop("pk")
        pks = [pk for pk in self.pks if all(DB.rows[pk].get(k) == v for k, v in lookup.items())]
        return QuerySet(self.model, pks)

    def first(self) -> Model | None:
        return self.model.load(self.pks[0]) if self.pks else None

    def update(self, **values: Any) -> int:
        for pk in self.pks:
            DB.rows[pk].update(values)
            DB.writes += 1
        return len(self.pks)

    def delete(self) -> int:
        for pk in self.pks:
            del DB.rows[pk]
        return len(self.pks)

    def bulk_create(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("not used")

    bulk_update = bulk_create


class Manager:
    def __init__(self, model: type[Model]) -> None:
        self.model = model

    def filter(self, **lookup: Any) -> QuerySet:
        return QuerySet(self.model, sorted(DB.rows)).filter(**lookup)


class Model:
    fields: ClassVar[list[Field]] = []
    defaults: ClassVar[dict[str, Any]] = {}

    def __init__(self, **values: Any) -> None:
        self.pk: int | None = None
        self.id: int | None = None
        self._state = State(adding=True)
        for field in self.fields:
            setattr(self, field.attname, copy.deepcopy(values.get(field.name, self.defaults.get(field.name))))

    @classmethod
    def load(cls, pk: int) -> Model:
        obj = cls(**DB.rows[pk])
        obj.pk = obj.id = pk
        obj._state.adding = False
        return obj

    def full_clean(self) -> None:
        pass

    def save(self, *args: Any, update_fields: Any = None, **kwargs: Any) -> None:
        self.full_clean()
        self.save_base(update_fields=update_fields)

    def save_base(self, *args: Any, update_fields: Any = None, **kwargs: Any) -> None:
        DB.writes += 1
        if self.pk is None:
            self.pk = self.id = max(DB.rows, default=0) + 1
            DB.rows[self.pk] = {"id": self.pk}
            self._state.adding = False
        names = update_fields or [field.name for field in self.fields]
        for field in self.fields:
            if field.name in names:
                DB.rows[self.pk][field.name] = copy.deepcopy(getattr(self, field.attname))
        DB.rows[self.pk]["updated_at"] = time.time()

    def delete(self) -> None:
        assert self.pk is not None
        del DB.rows[self.pk]


class BackupTarget(Model):
    fields: ClassVar[list[Field]] = [
        Field("name"),
        Field("description"),
        Field("fastdeploy_service"),
        Field("service_token"),
        Field("status"),
        Field("schedule"),
        Field("retention_days", kind=int),
        Field("updated_at", auto_now=True),
    ]
    defaults: ClassVar[dict[str, Any]] = {
        "description": "",
        "fastdeploy_service": "",
        "service_token": "",
        "status": "active",
        "schedule": "",
        "retention_days": 30,
        "updated_at": 0.0,
    }

    def full_clean(self) -> None:
        # Like Echoport's clean(): trims the token, rejects a bad schedule.
        token: str = getattr(self, "service_token")  # noqa: B009 - set from ``fields``
        schedule: str = getattr(self, "schedule")  # noqa: B009
        setattr(self, "service_token", token.strip())  # noqa: B010
        if schedule and len(schedule.split()) != 5:
            raise ValueError("{'schedule': ['Invalid cron expression']}")


BackupTarget._meta = types.SimpleNamespace(concrete_fields=BackupTarget.fields)  # type: ignore[attr-defined]
BackupTarget.objects = Manager(BackupTarget)  # type: ignore[attr-defined]
BackupTarget._base_manager = BackupTarget.objects  # type: ignore[attr-defined]


class Transactions:
    def __init__(self) -> None:
        self.rollback = False

    @contextlib.contextmanager
    def atomic(self) -> Iterator[None]:
        saved, self.rollback = DB.snapshot(), False
        try:
            yield
        finally:
            if self.rollback:
                DB.rows = saved

    def set_rollback(self, value: bool) -> None:
        self.rollback = value


@pytest.fixture(autouse=True)
def echoport(monkeypatch: pytest.MonkeyPatch) -> None:
    DB.rows, DB.writes = {}, 0
    transaction = Transactions()
    models = types.SimpleNamespace(Model=Model, QuerySet=QuerySet)
    db = types.ModuleType("django.db")
    db.models = models  # type: ignore[attr-defined]
    db.transaction = transaction  # type: ignore[attr-defined]
    django = types.ModuleType("django")
    django.db = db  # type: ignore[attr-defined]
    backups = types.ModuleType("backups")
    backups_models = types.ModuleType("backups.models")
    backups_models.BackupTarget = BackupTarget  # type: ignore[attr-defined]
    for name, module in {
        "django": django,
        "django.db": db,
        "backups": backups,
        "backups.models": backups_models,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)


# The kind of script a class B playbook carries (mail-db's), reading VALUES and SERVICE_TOKEN.
SCRIPT = """\
import json
import os
from backups.models import BackupTarget

target = BackupTarget.objects.filter(name=VALUES["name"]).first()
created = target is None
if target is None:
    target = BackupTarget(name=VALUES["name"])
elif target.status != "active" and not VALUES["allow_reactivation"]:
    # A paused or disabled target is not re-enabled by a re-run.
    raise RuntimeError(f"Refusing implicit reactivation from status={target.status}")

target.description = VALUES["description"]
target.fastdeploy_service = VALUES["service"]
issued_token = SERVICE_TOKEN
if issued_token:
    target.service_token = issued_token
elif not target.service_token:
    raise RuntimeError("no FastDeploy service token to store")
target.schedule = VALUES["schedule"]
target.status = "active"
target.retention_days = VALUES["retention_days"]
target.save()
print(json.dumps({"created": created, "name": target.name}))
"""
VALUES = {
    "name": "mail-db",
    "description": "Mail database",
    "service": "mail-db-backup",
    "schedule": "15 3 * * *",
    "retention_days": 30,
    "allow_reactivation": False,
}
TOKEN = ServiceToken(targets=("mail-db",), service="mail-db-backup", days=90, renewal_days=30)


def jwt(**claims: Any) -> str:
    def part(data: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{part({'alg': 'HS256'})}.{part(claims)}.signature"


GOOD = jwt(type="service", service="mail-db-backup", jti="abc", exp=int(time.time()) + 60 * 86400)


def stored_row(**changes: Any) -> dict[str, Any]:
    row = {
        "name": "mail-db",
        "description": "Mail database",
        "fastdeploy_service": "mail-db-backup",
        "service_token": GOOD,
        "status": "active",
        "schedule": "15 3 * * *",
        "retention_days": 30,
        "updated_at": 1.0,
        **changes,
    }
    DB.rows[1] = {"id": 1, **row}
    return row


def target(**changes: Any) -> RunnerTarget:
    values: dict[str, Any] = {"name": "mail-db", "script": SCRIPT, "values": VALUES, "token": TOKEN, **changes}
    return RunnerTarget(**values)


def run(cfg: RunnerTarget, mode: str, *, stdin: str = "", capsys: pytest.CaptureFixture[str]) -> str:
    """The prelude as ``manage.py shell -c`` runs it; its last stdout line."""

    code = target_code(cfg, mode)  # type: ignore[arg-type]
    old = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        exec(compile(code, "<shell>", "exec"), {"__name__": "__main__"})
    finally:
        sys.stdin = old
    out = capsys.readouterr().out
    return out.strip().splitlines()[-1]


# -- check mode --------------------------------------------------------------------------


def test_a_converged_row_is_unchanged_and_nothing_is_written(capsys: pytest.CaptureFixture[str]) -> None:
    stored_row()
    before = DB.snapshot()

    assert run(target(), "check", capsys=capsys) == "unchanged"
    assert DB.rows == before


@pytest.mark.parametrize(
    "drift",
    [
        {"description": "old"},
        {"fastdeploy_service": "other"},
        {"schedule": "0 1 * * *"},
        {"retention_days": 7},
    ],
)
def test_each_owned_field_that_drifts_is_pending_without_a_write(
    drift: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    stored_row(**drift)
    before = DB.snapshot()

    assert run(target(), "check", capsys=capsys) == "pending"
    assert DB.rows == before


@pytest.mark.parametrize(
    ("token", "reason"),
    [
        ("", "missing"),
        ("not-a-jwt", "undecodable"),
        (jwt(type="service", service="other", jti="a", exp=int(time.time()) + 90 * 86400), "wrong_scope"),
        (jwt(type="service", service="mail-db-backup", exp=int(time.time()) + 90 * 86400), "legacy_without_jti"),
        (jwt(type="service", service="mail-db-backup", jti="a"), "no_expiry"),
        (jwt(type="service", service="mail-db-backup", jti="a", exp=int(time.time()) + 10 * 86400), "expiring"),
    ],
)
def test_each_rotation_reason_is_pending(token: str, reason: str, capsys: pytest.CaptureFixture[str]) -> None:
    stored_row(service_token=token)

    assert run(target(), "check", capsys=capsys) == "pending", reason


def test_force_rotate_is_pending(capsys: pytest.CaptureFixture[str]) -> None:
    stored_row()
    token = TOKEN.model_copy(update={"force_rotate": True})

    assert run(target(token=token), "check", capsys=capsys) == "pending"


def test_a_paused_target_refuses_and_an_override_makes_it_pending(capsys: pytest.CaptureFixture[str]) -> None:
    stored_row(status="paused")

    assert run(target(), "check", capsys=capsys) == (
        "refused: RuntimeError: Refusing implicit reactivation from status=paused"
    )
    allowed = target(values={**VALUES, "allow_reactivation": True})
    assert run(allowed, "check", capsys=capsys) == "pending"
    assert DB.rows[1]["status"] == "paused"


def test_a_validation_error_refuses(capsys: pytest.CaptureFixture[str]) -> None:
    stored_row()

    answer = run(target(values={**VALUES, "schedule": "daily"}), "check", capsys=capsys)

    assert answer.startswith("refused: ValueError:")


def test_a_missing_row_is_pending_and_created_only_by_apply(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(target(), "check", capsys=capsys) == "pending"
    assert DB.rows == {}

    assert run(target(), "apply", stdin=f"{GOOD}\n", capsys=capsys) == "applied"
    assert DB.rows[1]["service_token"] == GOOD
    assert run(target(), "check", capsys=capsys) == "unchanged"


def test_a_converge_only_script_refuses_a_missing_row(capsys: pytest.CaptureFixture[str]) -> None:
    script = (
        "from backups.models import BackupTarget\n"
        "target = BackupTarget.objects.filter(name=VALUES['name']).first()\n"
        "if target is None:\n"
        "    raise RuntimeError('postfixadmin target is missing; register it first')\n"
        "target.schedule = VALUES['schedule']\n"
        "target.retention_days = VALUES['retention_days']\n"
        "target.save(update_fields=['schedule', 'retention_days'])\n"
    )
    cfg = target(script=script, token=None)

    assert run(cfg, "check", capsys=capsys).startswith("refused: RuntimeError: postfixadmin target is missing")
    stored_row(description="kept by hand", retention_days=7)
    assert run(cfg, "check", capsys=capsys) == "pending"
    assert run(cfg, "apply", capsys=capsys) == "applied"
    assert DB.rows[1]["retention_days"] == 30
    assert DB.rows[1]["description"] == "kept by hand"
    # Only the saved fields count: the hand-kept description is not drift.
    assert run(cfg, "check", capsys=capsys) == "unchanged"


def test_other_writes_are_pending_and_skipped(capsys: pytest.CaptureFixture[str]) -> None:
    stored_row()
    script = "from backups.models import BackupTarget\nBackupTarget.objects.filter(name='mail-db').update(status='x')\n"
    before = DB.snapshot()

    assert run(target(script=script, token=None), "check", capsys=capsys) == "pending"
    assert DB.rows == before


def test_a_string_number_equal_to_the_stored_one_is_unchanged(capsys: pytest.CaptureFixture[str]) -> None:
    stored_row()

    assert run(target(values={**VALUES, "retention_days": "30"}), "check", capsys=capsys) == "unchanged"


# -- apply mode --------------------------------------------------------------------------


def test_apply_without_a_due_token_on_stdin_needs_one_and_writes_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    stored_row(service_token="", description="old")
    before = DB.snapshot()

    assert run(target(), "apply", capsys=capsys) == "need-token"
    assert DB.rows == before


def test_apply_keeps_a_good_token_and_updates_the_row(capsys: pytest.CaptureFixture[str]) -> None:
    stored_row(description="old")

    assert run(target(), "apply", stdin="ignored\n", capsys=capsys) == "applied"
    assert DB.rows[1]["description"] == "Mail database"
    assert DB.rows[1]["service_token"] == GOOD


def test_the_scripts_own_output_and_the_token_are_withheld(capsys: pytest.CaptureFixture[str]) -> None:
    stored_row(service_token="")
    fresh = jwt(type="service", service="mail-db-backup", jti="new", exp=int(time.time()) + 90 * 86400)
    code = target_code(target(), "apply")
    old = sys.stdin
    sys.stdin = io.StringIO(fresh + "\n")
    try:
        exec(compile(code, "<shell>", "exec"), {"__name__": "__main__"})
    finally:
        sys.stdin = old
    out = capsys.readouterr().out

    assert out == "applied\n"
    assert DB.rows[1]["service_token"] == fresh


def test_the_token_decision_is_the_shared_upserts() -> None:
    shared = (Path(__file__).parents[1] / "src/ops_deploy/services/_echoport/files/echoport_target.py").read_text()

    def function(text: str, name: str) -> str:
        match = re.search(rf"^def {name}\(.*?(?=^\S)", text, re.MULTILINE | re.DOTALL)
        assert match, name
        return match.group(0)

    for name in ("token_claims", "rotation_reason"):
        assert function(PRELUDE, name) == function(shared, name)


# -- settings ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "values",
    [
        {"service_token": "x"},
        {"nested": {"db_password": "x"}},
        {"list": [{"secret_key": "x"}]},
        {"fd_service_token_value": ""},
    ],
)
def test_values_that_look_like_a_secret_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="must not hold a secret"):
        target(values=values)


@pytest.mark.parametrize(
    "changes",
    [{"targets": ()}, {"days": 91}, {"days": 0}, {"renewal_days": 90}, {"renewal_days": 0}, {"service": "a b"}],
)
def test_token_settings_the_include_refuses_are_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="validation error"):
        ServiceToken(**{"targets": ("mail-db",), "service": "mail-db-backup", **changes})


# -- the steps on the fake host ------------------------------------------------------------


def check_key(cfg: RunnerTarget) -> str:
    """The line of the check's code that carries its (base64) parameters; the probe command contains it."""

    return target_code(cfg, "check").splitlines()[1]


CHECK = check_key(target(token=None))
TOKEN_CHECK = check_key(target())


def test_unchanged_adds_no_operation() -> None:
    def deploy() -> None:
        upsert_runner_target(target(token=None))

    run_ = run_deploy_fake(deploy, responses={CHECK: ["unchanged"]})

    assert run_.succeeded, run_.error
    assert run_.ops == []


def test_a_refusal_stops_the_deploy_while_planning() -> None:
    def deploy() -> None:
        upsert_runner_target(target(token=None))

    run_ = run_deploy_fake(deploy, responses={CHECK: ["refused: RuntimeError: Refusing implicit reactivation"]})

    assert isinstance(run_.error, DeployError)
    assert "Refusing implicit reactivation" in str(run_.error)
    assert run_.executed_commands == []


def test_without_echoport_the_deploy_stops_while_planning() -> None:
    def deploy() -> None:
        upsert_runner_target(target(token=None))

    run_ = run_deploy_fake(deploy, responses={CHECK: ["missing"]})

    assert isinstance(run_.error, DeployError)
    assert run_.executed_commands == []


def test_pending_applies_once_and_probes_again() -> None:
    def deploy() -> None:
        upsert_runner_target(target(token=None))

    run_ = run_deploy_fake(deploy, responses={CHECK: ["pending"]})

    assert [op.name for op in run_.ops] == [
        "Upsert Echoport backup target mail-db",
        "Probe again: Echoport backup target mail-db",
    ]
    apply = run_.executed_commands[0]
    assert apply.startswith("out=$( (cd /home/echoport/site && runuser -u echoport -- env HOME=/home/echoport ")
    assert target_code(target(token=None), "apply").splitlines()[1] in apply
    assert "</dev/null" in apply


def test_a_token_target_needs_the_token_step() -> None:
    def deploy() -> None:
        upsert_runner_target(target())

    with pytest.raises(ValueError, match="token_and_target"):
        run_deploy_fake(deploy, responses={TOKEN_CHECK: ["pending"]})


def test_the_token_user_travels_on_stdin_only() -> None:
    user = "fixture-fastdeploy-user"

    def deploy() -> None:
        token_and_target(target(), user)

    run_ = run_deploy_fake(deploy, responses={TOKEN_CHECK: ["pending"]})

    assert run_.succeeded, run_.error
    assert [op.name for op in run_.ops] == [
        "Issue or reuse the FastDeploy token and upsert the Echoport backup target mail-db",
        "Probe again: Echoport backup target mail-db",
    ]
    (command, stdin), *_ = run_.stdin
    assert stdin == f"{user}\n"
    assert user not in run_.all_text()
    for word in ("issueservicetoken", "--days", "--origin"):
        assert word in command
    assert "runuser -u fastdeploy -- env HOME=/home/fastdeploy .venv/bin/python -c" in command


def test_the_token_step_is_skipped_when_unchanged() -> None:
    def deploy() -> None:
        token_and_target(target(), "fixture-fastdeploy-user")

    run_ = run_deploy_fake(deploy, responses={TOKEN_CHECK: ["unchanged"]})

    assert run_.ops == []


@pytest.mark.parametrize("user", ["", "two\nlines"])
def test_a_bad_token_user_refuses(user: str) -> None:
    def deploy() -> None:
        token_and_target(target(), user)

    run_ = run_deploy_fake(deploy, responses={TOKEN_CHECK: ["pending"]})

    assert isinstance(run_.error, DeployError)
    assert run_.executed_commands == []


# -- against Echoport's own models (optional) ---------------------------------------------

ECHOPORT = os.environ.get("ECHOPORT_PATH")
# Run with Echoport's interpreter: its test settings (SQLite in memory), migrations, then the cases.
ORACLE = """\
import io, json, os, sys
sys.path[:0] = [os.path.join(sys.argv[1], "src/django"), os.path.join(sys.argv[1], "src")]
os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings.test"
import django
django.setup()
from django.core.management import call_command
call_command("migrate", verbosity=0)
from backups.models import BackupTarget
cases = json.loads(sys.stdin.read())
answers = []
for case in cases:
    if case.get("row"):
        BackupTarget.objects.filter(name=case["row"]["name"]).delete()
        BackupTarget(**case["row"]).save()
    out, old_out, old_in = io.StringIO(), sys.stdout, sys.stdin
    sys.stdout, sys.stdin = out, io.StringIO(case.get("stdin", ""))
    try:
        exec(compile(case["code"], "<shell>", "exec"), {"__name__": "__main__"})
    finally:
        sys.stdout, sys.stdin = old_out, old_in
    row = BackupTarget.objects.filter(name="mail-db").values("description", "status", "updated_at").first()
    answers.append([out.getvalue().strip().splitlines()[-1], row and {**row, "updated_at": str(row["updated_at"])}])
print(json.dumps(answers))
"""


@pytest.mark.skipif(not ECHOPORT, reason="ECHOPORT_PATH (an Echoport checkout with its .venv) not set")
def test_the_check_mode_against_echoports_own_models(tmp_path: Path) -> None:
    import subprocess

    assert ECHOPORT is not None
    row = {
        "name": "mail-db",
        "description": "Mail database",
        "fastdeploy_service": "mail-db-backup",
        "service_token": GOOD,
        "service_name": "postgresql.service",
        "target_mode": "service_owned",
        "status": "active",
        "schedule": "15 3 * * *",
        "retention_days": 30,
    }
    script = SCRIPT.replace("target.save()", "target.service_name = 'postgresql.service'\ntarget.save()")
    cfg = target(script=script, values={**VALUES, "description": "Mail database"})
    drift = target(script=script, values={**VALUES, "description": "Mail DB"})
    cases = [
        {"row": row, "code": target_code(cfg, "check")},
        {"code": target_code(drift, "check")},
        {"code": target_code(drift, "apply")},
        {"code": target_code(drift, "check")},
        {"row": {**row, "status": "paused"}, "code": target_code(cfg, "check")},
        {"row": row, "code": target_code(target(script=script, values={**VALUES, "schedule": "daily"}), "check")},
    ]
    python = Path(ECHOPORT) / ".venv/bin/python"
    result = subprocess.run(
        [str(python), "-c", ORACLE, ECHOPORT],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-3000:]
    answers = json.loads(result.stdout.strip().splitlines()[-1])
    (converged, first), (pending, unchanged_row), (applied, updated), (after, _), (paused, _), (bad, _) = answers
    assert converged == "unchanged"
    assert pending == "pending"
    # The check wrote nothing: not even updated_at moved.
    assert unchanged_row == first
    assert applied == "applied"
    assert updated["description"] == "Mail DB"
    assert after == "unchanged"
    assert paused == "refused: RuntimeError: Refusing implicit reactivation from status=paused"
    assert bad.startswith("refused: ValidationError:")
