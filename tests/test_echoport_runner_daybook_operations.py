"""``_echoport_runner.daybook_operations``: the Daybook operations backup bridge registration.

The files are compared with what ops-library's ``daybook_operations_api_backup``
role wrote on macmini (read 2026-11-10: the bridge's SHA-256, the policy,
``config.json``, the sudoers rule and FastDeploy's stored service data); the
kept target script runs through the check-mode wrapper against the stand-in
Echoport model of ``test_echoport_runner_classb``. ops-control's tests compare
the kept script with the role's text.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.services._echoport_runner.access import MinioAccess, alias_digest, render_account_policy
from ops_deploy.services._echoport_runner.daybook_operations import (
    BRIDGE,
    DaybookOperationsBackup,
    install_daybook_operations_backup,
    policy,
    register_daybook_operations_backup,
    registered_schedule,
    runner_target,
    service_config,
    sudoers_rule,
    upsert_service_sql,
)
from ops_deploy.services._echoport_runner.target import target_code, target_scripts
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.test_echoport_runner_classb import echoport, row, run, store, token_for  # noqa: F401 - echoport: fixture
from tests.test_echoport_runner_target import DB, Manager

SECRET = "fixture-account-secret-0123456789abcdef"  # pragma: allowlist secret
USER = "fixture-fastdeploy-user"
SERVICE = "daybook-operations-backup"
STORED = "select data::text from service where name"
SCHEDULE_PROBE = "t = BackupTarget.objects.filter(name="

# What the role wrote on macmini (no final newline: ``copy: content:`` of ``to_nice_json``).
LIVE_BRIDGE_SHA256 = "cdf20bff2e4dc62be0536f0fd6b03b78f255cb84c0e262954b1c3f915dfbc224"
LIVE_POLICY = """{
    "alias": "backup-daybook_operations_api",
    "backup_root": "/opt/backups/daybook_operations",
    "bucket": "backups",
    "config": "/etc/daybook-operations/lifecycle.json",
    "lifecycle": "/home/daybook-operations/site/services/operations_api/lifecycle.py",
    "lock": "/var/lib/daybook-operations-backup/bridge.lock",
    "mc": "/usr/local/bin/mc",
    "python": "/home/daybook-operations/venv/bin/python",
    "staging_root": "/var/lib/daybook-operations-backup",
    "target": "daybook_operations_api",
    "user": "daybook-operations"
}"""
LIVE_CONFIG = """{
    "deploy_script": "/usr/local/libexec/daybook-operations-backup",
    "description": "Daybook operations backup; attended restore only",
    "name": "daybook-operations-backup",
    "steps": [
        {
            "name": "backup"
        },
        {
            "name": "upload"
        },
        {
            "name": "verify"
        },
        {
            "name": "result"
        }
    ]
}"""
LIVE_SUDOERS = (
    "fastdeploy ALL=(deploy) NOPASSWD:NOSETENV: /usr/local/libexec/daybook-operations-backup --config *\n"
    "deploy ALL=(root) NOPASSWD:NOSETENV: /usr/local/libexec/daybook-operations-backup --config *\n"
)
LIVE_STORED = (
    '{"name": "daybook-operations-backup", "description": "Daybook operations backup; attended restore only", '
    '"deploy_script": "/usr/local/libexec/daybook-operations-backup", "steps": [{"name": "backup"}, '
    '{"name": "upload"}, {"name": "verify"}, {"name": "result"}]}'
)


def config(**changes: Any) -> DaybookOperationsBackup:
    values: dict[str, Any] = {
        "access": MinioAccess(
            target="daybook_operations_api",
            os_user="root",
            alias="backup-daybook_operations_api",
            url="http://127.0.0.1:9001",
            scoped=True,
            retired_aliases=("minio",),
        ),
        "schedule": "17 4 * * *",
        **changes,
    }
    return DaybookOperationsBackup(**values)


@pytest.fixture(autouse=True)
def get_or_create(monkeypatch: pytest.MonkeyPatch) -> None:
    def get_or_create(self: Manager, defaults: dict[str, Any] | None = None, **lookup: Any) -> tuple[Any, bool]:
        found = self.filter(**lookup).first()
        if found is not None:
            return found, False
        obj = self.model(**{**lookup, **(defaults or {})})
        obj.save()
        return obj, True

    monkeypatch.setattr(Manager, "get_or_create", get_or_create, raising=False)


def _file(path: str, content: str, *, mode: str) -> dict[str, Any]:
    return {
        f"sha1sum {path} ": [f"{hashlib.sha1(content.encode()).hexdigest()}  {path}"],
        f"sha256sum {path} ": [f"{hashlib.sha256(content.encode()).hexdigest()}  {path}"],
        **fakehost.stat(path, user="root", group="root", mode=mode),
    }


def converged(cfg: DaybookOperationsBackup) -> dict[Any, Any]:
    access = cfg.access
    return {
        "test -x /usr/local/bin/mc": ["present"],
        re.compile(rf"mc ls {access.alias}/backups/{access.target}/ >/dev/null && echo ok"): ["ok"],
        "def statements(doc)": ["policy=ok user=attached"],
        re.compile(rf"alias list {access.alias} \)"): [alias_digest(access.url, access.account.user, SECRET)],
        re.compile(r"alias list minio \)"): ["none"],
        **fakehost.directory("/etc/minio/policies", mode="drwxr-x---"),
        **fakehost.file(
            f"/etc/minio/policies/backup-{access.target}.json",
            render_account_policy(access.account),
            mode="-rw-r-----",
        ),
        **fakehost.directory("/usr/local/libexec"),
        **fakehost.directory(cfg.staging, mode="drwx------"),
        **fakehost.directory(cfg.service_dir),
        **fakehost.directory("/etc/sudoers.d"),
        **_file(cfg.runner, BRIDGE, mode="-rwxr-xr-x"),
        **_file(cfg.policy, LIVE_POLICY, mode="-rw-------"),
        **_file(f"{cfg.service_dir}/config.json", LIVE_CONFIG, mode="-rw-r--r--"),
        **_file("/etc/sudoers.d/daybook_operations_backup", LIVE_SUDOERS, mode="-r--r-----"),
        STORED: [LIVE_STORED],
        target_code(runner_target(cfg), "check").splitlines()[1]: ["unchanged"],
    }


def test_the_files_are_the_ones_the_role_wrote() -> None:
    cfg = config()
    assert hashlib.sha256(BRIDGE.encode()).hexdigest() == LIVE_BRIDGE_SHA256
    assert policy(cfg) == LIVE_POLICY
    assert service_config(cfg) == LIVE_CONFIG
    assert sudoers_rule(cfg) == LIVE_SUDOERS
    assert json.loads(LIVE_STORED) == json.loads(service_config(cfg))
    assert f"'{LIVE_STORED}'::json" in upsert_service_sql(cfg)
    assert "daybook_operations" in target_scripts()


def test_a_converged_host_gets_no_mutating_operation() -> None:
    cfg = config()
    fake = run_deploy_fake(
        lambda: install_daybook_operations_backup(cfg, secret_key=SECRET, token_user=USER), responses=converged(cfg)
    )

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == []
    assert SECRET not in fake.all_text()
    assert USER not in fake.all_text()


def test_a_first_run_writes_in_the_roles_order() -> None:
    cfg = config()
    responses = {
        "test -x /usr/local/bin/mc": ["present"],
        "def statements(doc)": ["policy=missing user=missing"],
        target_code(runner_target(cfg), "check").splitlines()[1]: ["pending"],
    }
    fake = run_deploy_fake(
        register_daybook_operations_backup, cfg, secret_key=SECRET, token_user=USER, responses=responses
    )

    assert fake.succeeded, fake.error
    names = [name.split(" | ", 1)[-1] for name in fake.changed_ops]
    order = [
        "Create or update MinIO user of daybook_operations_api",
        "Configure mc alias backup-daybook_operations_api of root",
        "Install the Daybook operations backup bridge",
        "Write the backup bridge policy",
        f"Write config.json of {SERVICE}",
        "Install sudoers rule daybook_operations_backup",
        f"Register the FastDeploy service {SERVICE}",
        "Issue or reuse the FastDeploy token and upsert the Echoport backup target daybook_operations_api",
    ]
    assert [n for n in names if n in order] == order
    assert [stdin for command, stdin in fake.stdin if "issueservicetoken" in command] == [f"{USER}\n"]
    assert SECRET not in fake.all_text()
    assert USER not in fake.all_text()


def test_a_target_refusal_stops_before_any_write() -> None:
    cfg = config()
    responses = {
        **converged(cfg),
        target_code(runner_target(cfg), "check").splitlines()[1]: ["refused: RuntimeError: x"],
    }
    fake = run_deploy_fake(
        lambda: install_daybook_operations_backup(cfg, secret_key=SECRET, token_user=USER), responses=responses
    )
    assert isinstance(fake.error, DeployError), fake.error
    assert fake.executed_commands == []


def test_the_role_asserts() -> None:
    with pytest.raises(ValueError, match="the runner must be"):
        config(runner="/usr/local/libexec/other")
    with pytest.raises(ValueError, match="object-store access"):
        config(target="other_target")
    upper = config().access.model_copy(update={"alias": "Backup-daybook_operations_api"})
    with pytest.raises(ValueError, match="the alias must match"):
        config(access=upper)
    dotted = config().access.model_copy(update={"bucket": "my.backups"})
    with pytest.raises(ValueError, match="the bucket must match"):
        config(access=dotted)
    with pytest.raises(ValueError, match="token_renewal_days"):
        config(token_renewal_days=90)


# -- the kept target script --------------------------------------------------------------------


def values(cfg: DaybookOperationsBackup) -> dict[str, Any]:
    return dict(runner_target(cfg).values)


def test_a_new_target_gets_the_default_schedule_and_stays_unchanged() -> None:
    target = runner_target(config())
    assert run(target, "check") == "pending"
    assert run(target, "apply", f"{token_for(SERVICE)}\n") == "applied"
    stored = row("daybook_operations_api")
    assert (stored["schedule"], stored["schedule_required"], stored["status"]) == ("17 4 * * *", True, "active")
    assert (stored["target_mode"], stored["retention_days"], stored["timeout_seconds"]) == ("service_owned", 30, 1800)
    assert stored["service_name"] == "daybook-operations"
    before = DB.snapshot()
    assert run(target, "check") == "unchanged"
    assert DB.rows == before


def live_row(**changes: Any) -> None:
    store(
        **{
            "name": "daybook_operations_api",
            "description": "Database and replay keyring; restore only through attended operations lifecycle",
            "fastdeploy_service": SERVICE,
            "service_token": token_for(SERVICE),
            "service_name": "daybook-operations",
            "target_mode": "service_owned",
            "schedule": "17 * * * *",
            "schedule_required": True,
            "status": "active",
            "retention_days": 30,
            "timeout_seconds": 1800,
            "storage_bucket": "backups",
            "storage_alias": "minio",
            **changes,
        }
    )


def test_an_existing_schedule_and_status_stay_without_an_override() -> None:
    live_row()
    before = DB.snapshot()
    assert run(runner_target(config()), "check") == "unchanged"
    live_row(name="other")  # unrelated rows stay too
    assert row("daybook_operations_api") == before[1]

    DB.rows[1]["status"] = "paused"
    assert run(runner_target(config()), "check") == "unchanged"


def test_an_override_sets_the_schedule_and_its_requirement() -> None:
    live_row()
    target = runner_target(config(schedule="17 4 * * *", update_schedule=True))
    assert run(target, "check") == "pending"
    assert run(target, "apply") == "applied"
    assert (row("daybook_operations_api")["schedule"], row("daybook_operations_api")["schedule_required"]) == (
        "17 4 * * *",
        True,
    )
    manual = runner_target(config(schedule="", update_schedule=True))
    assert run(manual, "apply") == "applied"
    assert (row("daybook_operations_api")["schedule"], row("daybook_operations_api")["schedule_required"]) == (
        "",
        False,
    )


def test_registered_schedule_follows_the_role() -> None:
    def plan(cfg: DaybookOperationsBackup, answer: list[str]) -> list[str]:
        found: list[str] = []
        fake = run_deploy_fake(lambda: found.append(registered_schedule(cfg)), responses={SCHEDULE_PROBE: answer})
        assert fake.succeeded, fake.error
        return found

    assert plan(config(), ['"17 * * * *"']) == ["17 * * * *"]
    assert plan(config(), ["null"]) == ["17 4 * * *"]
    assert plan(config(schedule="", update_schedule=True), ["boom"]) == [""]
    fake = run_deploy_fake(lambda: registered_schedule(config()), responses={SCHEDULE_PROBE: ["missing"]})
    assert isinstance(fake.error, DeployError)
