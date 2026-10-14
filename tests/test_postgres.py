"""``postgres_database`` and ``sudoers_file`` against the fake connector."""

import base64
import hashlib
from typing import Any

import pytest
from pydantic import SecretStr
from pyinfra.api import OperationValueError

from ops_deploy.helpers import postgres_database, sudoers_file
from ops_deploy.helpers.postgres import parse_state, password_matches, scram_verifier, state_command
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

PASSWORD = "postgres-fixture-password"
PROBE = state_command("app", "app", "postgres")


def stored(password: str) -> str:
    verifier = scram_verifier(password, salt=b"0123456789abcdef")
    return f"role|true|{verifier.split('$')[1]}|{hashlib.sha256(verifier.encode()).hexdigest()}"


def run_db(state: list[str], password: str = PASSWORD, **kwargs: Any) -> FakeRun:
    def deploy() -> None:
        postgres_database("app", owner="app", password=SecretStr(password), **kwargs)

    run = run_deploy_fake(deploy, responses={**fakehost.service("postgresql.service"), PROBE: state})
    assert run.succeeded, run.error
    return run


def test_verifier_format() -> None:
    verifier = scram_verifier("pencil", salt=b"salt-of-16-bytes", iterations=4096)

    scheme, rest = verifier.split("$", 1)
    params, keys = rest.split("$")
    iterations, salt = params.split(":")
    stored_key, server_key = keys.split(":")
    assert (scheme, iterations, base64.b64decode(salt)) == ("SCRAM-SHA-256", "4096", b"salt-of-16-bytes")
    assert len(base64.b64decode(stored_key)) == len(base64.b64decode(server_key)) == 32


def test_password_matches_only_the_same_password() -> None:
    verifier = scram_verifier(PASSWORD, salt=b"x" * 16)
    spec, digest = verifier.split("$")[1], hashlib.sha256(verifier.encode()).hexdigest()

    assert password_matches(PASSWORD, spec, digest)
    assert not password_matches("other", spec, digest)
    assert not password_matches(PASSWORD, "", digest)
    assert not password_matches(PASSWORD, "4096:not base64!", digest)


def test_parse_state() -> None:
    assert parse_state(None).role_exists is False
    state = parse_state(["role|false||", "db|postgres"])
    assert (state.role_exists, state.can_login, state.database_owner, state.schema_owner) == (
        True,
        False,
        "postgres",
        None,
    )


def test_probe_carries_no_secret_and_never_reads_the_raw_verifier() -> None:
    assert "rolpassword like 'SCRAM-SHA-256$%'" in PROBE.replace("'\"'\"'", "'")
    assert "sha256(convert_to(rolpassword" in PROBE


def test_up_to_date_role_and_database_change_nothing() -> None:
    run = run_db([stored(PASSWORD), "db|app", "schema|app"])

    assert run.changed_ops == []
    assert run.stdin == []


def test_new_role_and_database() -> None:
    run = run_db([])

    assert run.changed_ops == ["Ensure PostgreSQL role app", "Ensure PostgreSQL database app"]
    ((command, sql),) = run.stdin
    assert command == "runuser -u postgres -- psql -XAtq -v ON_ERROR_STOP=1 -p 5432"
    assert sql.startswith('CREATE ROLE "app" WITH LOGIN PASSWORD \'SCRAM-SHA-256$4096:')
    assert PASSWORD not in sql
    assert PASSWORD not in run.all_text()
    assert run.executed_commands[-2:] == [
        'runuser -u postgres -- psql -XAtq -v ON_ERROR_STOP=1 -p 5432 -c \'CREATE DATABASE "app" OWNER "app"\'',
        "runuser -u postgres -- psql -XAtq -v ON_ERROR_STOP=1 -p 5432 -d app -c 'ALTER SCHEMA public OWNER TO \"app\"'",
    ]


def test_changed_password_is_altered() -> None:
    run = run_db([stored("old-password"), "db|app", "schema|app"])

    assert run.changed_ops == ["Ensure PostgreSQL role app"]
    assert run.stdin[0][1].startswith('ALTER ROLE "app" WITH LOGIN PASSWORD')


@pytest.mark.parametrize(
    ("kwargs", "password"),
    [({"admin_user": "post gres"}, PASSWORD), ({}, ""), ({}, "pässword")],
)
def test_bad_input_is_refused(kwargs: dict[str, Any], password: str) -> None:
    def deploy() -> None:
        postgres_database("app", owner="app", password=SecretStr(password), **kwargs)

    assert isinstance(run_deploy_fake(deploy).error, OperationValueError)


def test_sudoers_up_to_date_is_a_noop() -> None:
    content = "app ALL=(deploy) NOPASSWD: /bin/true\n"

    def deploy() -> None:
        sudoers_file("app", content)

    run = run_deploy_fake(deploy, responses=fakehost.file("/etc/sudoers.d/app", content, mode="-r--r-----"))

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_sudoers_with_wrong_mode_is_replaced() -> None:
    content = "app ALL=(deploy) NOPASSWD: /bin/true\n"

    def deploy() -> None:
        sudoers_file("app", content)

    run = run_deploy_fake(deploy, responses=fakehost.file("/etc/sudoers.d/app", content, mode="-rw-r--r--"))

    assert run.changed_ops == ["Install sudoers rule app"]
    assert run.executed_commands[-1].startswith("visudo -cqf /etc/sudoers.d/.ops-deploy-app && mv -f")


@pytest.mark.parametrize("name", ["app.conf", "../app", "app rule"])
def test_sudoers_names_sudo_would_skip_or_escape_are_refused(name: str) -> None:
    def deploy() -> None:
        sudoers_file(name, "x\n")

    assert isinstance(run_deploy_fake(deploy).error, OperationValueError)
