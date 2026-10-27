"""Core/web database boundary preserves ownership and fails closed on unknown state."""

from types import ModuleType
from typing import Any

import pytest
from pydantic import SecretStr
from pyinfra.api import DeployError

from ops_deploy.helpers.probes import probe_command
from ops_deploy.services._mail_database import (
    MailDatabaseConfig,
    MailDatabaseOperations,
    command,
    ensure_mail_database,
    require_mail_database,
)
from ops_deploy.testing import run_deploy_fake


def test_existing_foundation_has_no_managed_mutations() -> None:
    prepared: list[MailDatabaseOperations] = []

    def deploy() -> None:
        prepared.append(ensure_mail_database(MailDatabaseConfig(), role_password=SecretStr("fixture-password")))

    run = run_deploy_fake(
        deploy,
        responses={
            probe_command(command("role-check")): ["current"],
            probe_command(command("database-check")): ["current"],
        },
    )
    assert run.succeeded, run.error
    assert not run.changed_ops
    # Dependent fresh-install operations must be able to trust this metadata;
    # an always-command operation hidden behind _if would lie here.
    assert not prepared[0].role.will_change
    assert not prepared[0].database.will_change
    assert "fixture-password" not in run.all_text()


def test_missing_foundation_uses_protected_stdin() -> None:
    run = run_deploy_fake(
        lambda: ensure_mail_database(MailDatabaseConfig(), role_password=SecretStr("fixture-password")),
        responses={
            probe_command(command("role-check")): ["pending"],
            probe_command(command("database-check")): ["pending"],
        },
    )
    assert run.succeeded, run.error
    assert run.changed_ops == ["Ensure mail database role", "Ensure mail database database"]
    assert "fixture-password" not in run.all_text()
    assert sum(cmd.endswith("-apply") for cmd, _ in run.stdin) == 2


@pytest.mark.parametrize("state", ["", "ops-deploy-probe-failed", "unknown", "current\npending"])
def test_unknown_role_state_never_reconciles(state: str) -> None:
    run = run_deploy_fake(
        lambda: ensure_mail_database(MailDatabaseConfig(), role_password=SecretStr("fixture-password")),
        responses={probe_command(command("role-check")): [state]},
    )
    assert isinstance(run.error, DeployError)
    assert not run.executed_commands


def test_web_requirement_is_read_only() -> None:
    run = run_deploy_fake(lambda: require_mail_database(MailDatabaseConfig(), required_privileges=("CONNECT",)))
    assert run.succeeded, run.error
    assert not run.mutating_changed_ops
    assert run.changed_ops == ["Require existing mail database"]


@pytest.mark.parametrize("privilege", ["ALL", "SELECT", "CONNECT'); DROP DATABASE mail; --"])
def test_requirement_rejects_unsupported_privilege(privilege: str) -> None:
    with pytest.raises(ValueError, match="privileges"):
        require_mail_database(MailDatabaseConfig(), required_privileges=(privilege,))


@pytest.mark.parametrize("kwargs", [{"name": "bad name"}, {"role": "x';--"}, {"port": True}, {"port": 65536}])
def test_invalid_database_config_is_rejected(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="mail database"):
        MailDatabaseConfig(**kwargs)


def host_module() -> ModuleType:

    from ops_deploy.services._mail_database import SCRIPT

    module = ModuleType("owned_mail_database_test")
    exec(compile(SCRIPT, "mail_database_host.py", "exec"), module.__dict__)
    return module


@pytest.mark.parametrize("mode", ["role-check", "role-apply"])
@pytest.mark.parametrize(
    "malformation", ["null", "md5", "params", "salt", "short_keys", "bad_keys", "stored_key", "server_key"]
)
def test_host_unknown_credentials_refuse_without_sql_writes(
    monkeypatch: pytest.MonkeyPatch, mode: str, malformation: str
) -> None:
    import base64
    import io
    import json

    m = host_module()
    valid = m.verifier("synthetic-control", b"synthetic-salt")
    scheme, parameters, keys = valid.split("$")
    stored_key, server_key = keys.split(":")

    def corrupt(value: str) -> str:
        decoded = bytearray(base64.b64decode(value))
        decoded[0] ^= 1
        return base64.b64encode(decoded).decode()

    variants = {
        "null": None,
        "md5": "md5" + "0" * 32,
        "params": "SCRAM-SHA-256$bad$invalid",
        "salt": "SCRAM-SHA-256$4096:!!$" + keys,
        "short_keys": scheme + "$" + parameters + "$YQ==:Yg==",
        "bad_keys": scheme + "$" + parameters + "$!!:!!",
        "stored_key": scheme + "$" + parameters + "$" + corrupt(stored_key) + ":" + server_key,
        "server_key": scheme + "$" + parameters + "$" + stored_key + ":" + corrupt(server_key),
    }
    calls: list[str] = []

    def sql(query: str, database: str | None = None) -> str:
        calls.append(query)
        assert query.startswith("SELECT "), "Refusal must never issue SQL writes"
        return json.dumps([True, variants[malformation]])

    monkeypatch.setattr(m, "sql", sql)
    monkeypatch.setattr(m.sys, "argv", ["host", mode])
    monkeypatch.setattr(
        m.sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "name": "mail",
                    "role": "mail",
                    "admin_user": "postgres",
                    "port": 5432,
                    "password": "synthetic-control",
                }
            )
        ),
    )
    with pytest.raises(RuntimeError, match="credential"):
        m.main()
    assert len(calls) == 1


@pytest.mark.parametrize("login", [True, False])
def test_host_matching_password_and_login_repair_preserve_verifier(
    monkeypatch: pytest.MonkeyPatch, login: bool
) -> None:
    import io
    import json

    m = host_module()
    stored = m.verifier("synthetic-control", b"synthetic-salt")
    state = [login, stored]
    writes: list[str] = []

    def sql(query: str, database: str | None = None) -> str:
        if query.startswith("SELECT "):
            return json.dumps(state)
        writes.append(query)
        assert query == 'ALTER ROLE "mail" WITH LOGIN;'
        state[0] = True
        return ""

    monkeypatch.setattr(m, "sql", sql)
    monkeypatch.setattr(m.sys, "argv", ["host", "role-apply"])
    monkeypatch.setattr(
        m.sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "name": "mail",
                    "role": "mail",
                    "admin_user": "postgres",
                    "port": 5432,
                    "password": "synthetic-control",
                }
            )
        ),
    )
    m.main()
    assert state == [True, stored]
    assert len(writes) == (0 if login else 1)


def test_host_valid_wrong_password_is_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    m = host_module()
    m.__dict__["cfg"] = {"role": "mail", "password": "requested-other-value"}
    stored = m.verifier("original-value", b"synthetic-salt")
    monkeypatch.setattr(m, "sql", lambda _: json.dumps([True, stored]))
    assert m.role_state() == (True, True, False)


def test_database_requests_do_not_carry_role_password() -> None:
    import json

    run = run_deploy_fake(
        lambda: ensure_mail_database(MailDatabaseConfig(), role_password=SecretStr("synthetic-control")),
        responses={
            probe_command(command("role-check")): ["pending"],
            probe_command(command("database-check")): ["pending"],
        },
    )
    assert run.succeeded, run.error
    for cmd, data in run.stdin:
        if cmd.endswith("database-apply"):
            assert "password" not in json.loads(data)


@pytest.mark.parametrize("password", ["owned-café-control", "owned\u00a0space-control"])
def test_non_ascii_password_is_refused_before_operations(password: str) -> None:
    with pytest.raises(ValueError, match="ASCII"):
        ensure_mail_database(MailDatabaseConfig(), role_password=SecretStr(password))


def test_host_query_failure_is_unknown_not_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    m = host_module()
    m.__dict__["cfg"] = {"role": "mail", "password": "synthetic-control"}

    def unavailable(_: str) -> str:
        raise RuntimeError("fixture query unavailable")

    monkeypatch.setattr(m, "sql", unavailable)
    with pytest.raises(RuntimeError, match="query unavailable"):
        m.role_state()
