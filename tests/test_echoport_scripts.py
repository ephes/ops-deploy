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
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ops_deploy.services._echoport_runner.access import RunnerAccount, render_account_policy
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
        "NYXMON_APPLY": "1" if apply else "0",
    }
    result = subprocess.run(
        [sys.executable, "-I", "-c", echoport.NYXMON_CHECK],
        env=env,
        input=json.dumps(checks) + "\n",
        capture_output=True,
        text=True,
        check=True,
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


FAKE_MC = """#!/bin/sh
# mc admin {policy,user} info --json ALIAS NAME: the file $FAKE_MC_DIR/<policy|user>.json, else an error.
[ "$1 $3 $4 $5" = "admin info --json local" ] || { echo "unexpected: $*" >&2; exit 2; }
file="$FAKE_MC_DIR/$2.json"
[ -f "$file" ] || { echo '{"status": "error"}'; exit 1; }
cat "$file"
"""


@pytest.fixture
def fake_mc(tmp_path: Path) -> Path:
    binary = tmp_path / "mc"
    binary.write_text(FAKE_MC)
    binary.chmod(0o755)
    return tmp_path


def account(
    root: Path, mode: str, *, policy: Any = None, user: Any = None, document: str | None = None
) -> subprocess.CompletedProcess[str]:
    for name, value in (("policy", policy), ("user", user)):
        path = root / f"{name}.json"
        path.unlink(missing_ok=True)
        if value is not None:
            # mc indents its JSON.
            path.write_text(json.dumps(value, indent=1))
    spec = echoport.MinioAccount()
    argv = [str(root / "mc"), "local", spec.policy, spec.user, document or echoport.render_policy(spec)]
    env = {"PATH": os.environ["PATH"], "FAKE_MC_DIR": str(root)}
    return subprocess.run(
        [sys.executable, "-I", "-c", echoport.MINIO_ACCOUNT, mode, *argv], env=env, capture_output=True, text=True
    )


def stored_policy() -> dict[str, Any]:
    # How MinIO hands the document back: actions reordered, a lone resource as a string.
    document = json.loads(echoport.render_policy(echoport.MinioAccount()))
    for statement in document["Statement"]:
        statement["Action"] = sorted(statement["Action"], reverse=True)
    document["Statement"][0]["Resource"] = "arn:aws:s3:::backups"
    return {"status": "success", "policy": "backup-echoport-retention", "policyInfo": {"Policy": document}}


GOOD_USER = {"status": "success", "policyName": "backup-echoport-retention", "userStatus": "enabled"}


def iam_namespace(backend: str) -> dict[str, Any]:
    namespace: dict[str, Any] = {"__name__": f"{backend}_iam_host"}
    source = Path(f"src/ops_deploy/services/{backend}/files/iam_host.py").read_text()
    exec(compile(source, "iam_host", "exec"), namespace)
    return namespace


@pytest.fixture(params=["echoport-minio", "minio", "rustfs"])
def policy_matches(request: pytest.FixtureRequest, fake_mc: Path) -> Callable[[dict[str, Any], dict[str, Any]], bool]:
    def matches(declared: dict[str, Any], stored: dict[str, Any]) -> bool:
        if request.param == "echoport-minio":
            result = account(
                fake_mc,
                "probe",
                policy={"policyInfo": {"Policy": stored}},
                user=GOOD_USER,
                document=json.dumps(declared),
            )
            assert result.returncode == 0, result.stderr
            assert result.stdout.strip() in ("policy=ok user=attached", "policy=differs user=attached")
            return result.stdout.strip() == "policy=ok user=attached"
        normalized = iam_namespace(request.param)["normalized"]
        return bool(normalized(declared) == normalized(stored))

    return matches


@pytest.mark.parametrize(
    ("declared", "stored", "equal"),
    [
        ({"StringLike": {"s3:prefix": ["b/*", "a/*"]}}, {"StringLike": {"s3:prefix": ["a/*", "b/*"]}}, True),
        ({"StringLike": {"s3:prefix": "a/*"}}, {"StringLike": {"s3:prefix": ["a/*"]}}, True),
        ({"StringLike": {"s3:prefix": ["a/*"]}}, {"StringLike": {"s3:prefix": "a/*"}}, True),
        (
            {
                "StringLike": {"s3:prefix": ["b/*", "a/*"], "s3:delimiter": "/"},
                "ForAnyValue:StringEquals": {"aws:TagKeys": ["team", "app"]},
            },
            {
                "ForAnyValue:StringEquals": {"aws:TagKeys": ["app", "team"]},
                "StringLike": {"s3:delimiter": ["/"], "s3:prefix": ["a/*", "b/*"]},
            },
            True,
        ),
        ({"StringLike": {"s3:prefix": ["a/*"]}}, {"StringLike": {"s3:prefix": ["b/*"]}}, False),
        ({"StringLike": {"s3:prefix": ["a/*"]}}, {"StringLike": {"s3:prefix": ["a/*", "b/*"]}}, False),
        ({"StringLike": {"s3:prefix": ["a/*"]}}, {"StringLike": {"s3:prefix": ["a/*", "a/*"]}}, False),
        ({"StringLike": {"s3:prefix": ["a/*"]}}, {"StringEquals": {"s3:prefix": ["a/*"]}}, False),
        ({"StringLike": {"s3:prefix": ["a/*"]}}, {"StringLike": {"s3:other": ["a/*"]}}, False),
        ({"StringLike": {"s3:prefix": ["a/*"]}}, {}, False),
        ({"NumericEquals": {"s3:max-keys": 1}}, {"NumericEquals": {"s3:max-keys": "1"}}, False),
    ],
    ids=[
        "reordered",
        "string-list",
        "list-string",
        "operators-and-keys",
        "changed",
        "added",
        "duplicate",
        "operator-changed",
        "key-changed",
        "removed",
        "type-changed",
    ],
)
def test_policy_condition_comparison(
    policy_matches: Callable[[dict[str, Any], dict[str, Any]], bool],
    declared: dict[str, Any],
    stored: dict[str, Any],
    equal: bool,
) -> None:
    document = json.loads(echoport.render_policy(echoport.MinioAccount()))
    document["Statement"][0]["Condition"] = declared
    returned = json.loads(json.dumps(document))
    returned["Statement"][0]["Condition"] = stored
    before = json.dumps([document, returned])
    assert policy_matches(document, returned) is equal
    assert json.dumps([document, returned]) == before


def test_weeknotes_home_policy_round_trip(
    policy_matches: Callable[[dict[str, Any], dict[str, Any]], bool],
) -> None:
    spec = RunnerAccount(name="weeknotes_home", prefixes=("weeknotes_home", "weeknotes-home"))
    rendered = render_account_policy(spec)
    document = json.loads(rendered)
    listing = next(s for s in document["Statement"] if s["Action"] == ["s3:ListBucket"])
    assert listing["Condition"] == {"StringLike": {"s3:prefix": ["weeknotes_home/*", "weeknotes-home/*"]}}
    stored = json.loads(rendered)
    for statement in stored["Statement"]:
        if "Condition" in statement:
            statement["Condition"]["StringLike"]["s3:prefix"].sort()
    assert policy_matches(document, stored)
    assert render_account_policy(spec) == rendered


def test_account_probe_states(fake_mc: Path) -> None:
    def state(**files: Any) -> str:
        result = account(fake_mc, "probe", **files)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    assert state() == "policy=missing user=missing"
    assert state(policy=stored_policy(), user=GOOD_USER) == "policy=ok user=attached"
    other = stored_policy()
    other["policyInfo"]["Policy"]["Statement"][2]["Action"].append("s3:PutObject")
    assert state(policy=other, user=GOOD_USER) == "policy=differs user=attached"
    two = {**GOOD_USER, "policyName": "readwrite,backup-echoport-retention"}
    assert state(policy=stored_policy(), user=two) == "policy=ok user=attached"
    assert state(policy=stored_policy(), user={**GOOD_USER, "policyName": ""}) == "policy=ok user=unattached"


def test_account_verify_is_the_roles_last_assert(fake_mc: Path) -> None:
    assert account(fake_mc, "verify", policy=stored_policy(), user=GOOD_USER).returncode == 0
    for user, reason, hint in (
        (None, "is missing", False),
        ({**GOOD_USER, "policyName": "readwrite,backup-echoport-retention"}, "not exactly", True),
        ({**GOOD_USER, "memberOf": [{"name": "admins"}]}, "belongs to a group", True),
        ({**GOOD_USER, "userStatus": "disabled"}, "not enabled", False),
    ):
        result = account(fake_mc, "verify", policy=stored_policy(), user=user)
        assert result.returncode != 0
        assert reason in result.stderr
        assert ("Detach other policies or groups" in result.stderr) is hint
    result = account(fake_mc, "verify", user=GOOD_USER)
    assert result.returncode != 0
    assert "policy backup-echoport-retention is missing" in result.stderr
    assert "Detach" not in result.stderr
    other = stored_policy()
    other["policyInfo"]["Policy"]["Statement"][2]["Action"].append("s3:PutObject")
    result = account(fake_mc, "verify", policy=other, user=GOOD_USER)
    assert result.returncode != 0
    assert result.stderr.strip() == (
        "MinIO account: policy backup-echoport-retention differs from the installed document."
    )


@pytest.mark.parametrize(
    ("problem", "reason", "hint"),
    [
        ("policy-differs", "policy backup-echoport-retention differs from the installed document", False),
        ("policy-missing", "policy backup-echoport-retention is missing", False),
        ("user-missing", "is missing", False),
        ("extra-policy", "not exactly", True),
        ("group", "belongs to a group", True),
        ("disabled", "not enabled", False),
    ],
)
def test_rustfs_account_verify_messages(problem: str, reason: str, hint: bool) -> None:
    namespace = iam_namespace("rustfs")
    source = Path("src/ops_deploy/services/echoport/files/rustfs_account.py").read_text()
    exec(compile(source, "rustfs_account", "exec"), namespace)
    document = json.loads(echoport.render_policy(echoport.MinioAccount()))
    stored = json.loads(json.dumps(document))
    user: dict[str, Any] | None = {"status": "enabled"}
    attached = {"backup-echoport-retention"}
    if problem == "policy-differs":
        stored["Statement"][2]["Action"].append("s3:PutObject")
    elif problem == "user-missing":
        user = None
    elif problem == "extra-policy":
        attached.add("other")
    elif problem == "group":
        user = {"status": "enabled", "memberOf": ["admins"]}
    elif problem == "disabled":
        user = {"status": "disabled"}
    server = SimpleNamespace(
        policy=lambda _: None if problem == "policy-missing" else stored,
        user=lambda _: user,
        attached=lambda _: attached,
    )
    namespace["connect"] = lambda _: server
    with pytest.raises(namespace["Refused"]) as error:
        namespace["run"]("verify", "unused", ["backup-echoport-retention", "fixture-user", json.dumps(document)])
    assert reason in str(error.value)
    assert ("Detach other policies or groups" in str(error.value)) is hint
