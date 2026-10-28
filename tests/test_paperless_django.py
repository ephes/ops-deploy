"""Management admission, protected stdin and fresh execution decisions."""

from __future__ import annotations

import inspect
import json
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr
from pyinfra.api import DeployError

from ops_deploy.services.paperless import django
from ops_deploy.services.paperless.config import PaperlessConfig, PaperlessCredentials


def config(**kwargs: Any) -> PaperlessConfig:
    return PaperlessConfig(traefik_domain="home.example.test", **kwargs)


def test_manage_preserves_environment_cwd_and_exact_argv() -> None:
    command = shlex.split(django.manage(config(), "migrate", "--check", "--plan"))
    assert command[:8] == ["runuser", "-u", "paperless", "--", "env", "HOME=/home/paperless", "bash", "-euc"]
    assert command[8] == (
        "set -a; . /home/paperless/site/.env; set +a; cd /home/paperless/site/paperless-ngx/src; "
        "exec /home/paperless/site/.venv/bin/python -B manage.py migrate --check --plan"
    )
    quiet = shlex.split(django.manage(config(), "migrate", quiet=True))
    assert quiet[:2] == ["sh", "-c"]
    assert ">/dev/null 2>&1" in quiet[2]
    assert "exit 1" in quiet[2]


@pytest.mark.parametrize(("answer", "expected"), [("current", False), ("pending", True)])
def test_migration_probe_known_states(answer: str | None, expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(django, "probe", lambda *a, **k: answer)
    assert django.migrations_pending(config()) is expected


@pytest.mark.parametrize("answer", [None, "", "Traceback", "pending\ncurrent"])
def test_migration_errors_are_not_pending(answer: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(django, "probe", lambda *a, **k: answer)
    with pytest.raises(DeployError, match="unknown schema"):
        django.migrations_pending(config())


@pytest.mark.parametrize("answer", [None, "{}", '{"pending":1}', '{"pending":false,"extra":true}'])
def test_static_unknown_refuses(answer: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(django, "probe", lambda *a, **k: answer)
    with pytest.raises(DeployError, match="static program"):
        django.static_pending(config())


def test_admin_status_cannot_reference_undeclared_user(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = SecretStr("{}")
    for result in (
        {"create": False, "promote": [1], "missing": []},
        {"create": False, "promote": [True], "missing": []},
        {"create": False, "promote": [0, 0], "missing": []},
    ):
        monkeypatch.setattr(django, "probe", lambda *a, result=result, **k: json.dumps(result))
        with pytest.raises(DeployError, match="account inspection"):
            django.admin_pending(config(existing_superusers=("declared",)), payload)


def test_admin_password_only_protected_stdin_and_creation_not_forced(monkeypatch: pytest.MonkeyPatch) -> None:
    credentials = PaperlessCredentials(
        secret_key="s" * 50, postgres_password="synthetic-db", admin_password="synthetic-admin"
    )
    cfg = config()
    payload = django.admin_payload(cfg, credentials)
    monkeypatch.setattr(django, "state", SimpleNamespace(is_executing=True))
    monkeypatch.setattr(django, "admin_pending", lambda *a: True)
    commands = list(inspect.unwrap(django.ensure_admin)(cfg, payload))
    assert len(commands) == 1
    assert "synthetic-admin" not in repr(commands)
    assert "synthetic-admin" in "".join(commands[0].connector_arguments["_stdin"])
    assert commands[0].connector_arguments["_get_pty"] is False
    monkeypatch.setattr(django, "admin_pending", lambda *a: False)
    assert list(inspect.unwrap(django.ensure_admin)(cfg, payload)) == []


def test_static_preparation_and_execution_use_correct_dependency_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = config()
    monkeypatch.setattr(django, "static_pending", lambda *a: False)
    change = SimpleNamespace(will_change=True, did_change=lambda: False)
    operation = inspect.unwrap(django.collect_static)
    monkeypatch.setattr(django, "state", SimpleNamespace(is_executing=False))
    assert len(list(operation(cfg, changes=[change]))) == 1
    monkeypatch.setattr(django, "state", SimpleNamespace(is_executing=True))
    assert list(operation(cfg, changes=[change], deferred=True)) == []
    change.did_change = lambda: True
    assert len(list(operation(cfg, changes=[change]))) == 1


@pytest.mark.parametrize("shell", ["bash", "fish"])
@pytest.mark.parametrize(
    ("program", "expected"),
    [
        ("print('paperless-managed-step-complete')", 0),
        ("print('synthetic-private-value')", 1),
        ("raise RuntimeError('synthetic-private-value')", 1),
    ],
)
def test_apply_requires_completion_and_hides_output(
    shell: str, program: str, expected: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = shutil.which(shell)
    assert executable is not None, f"{shell} is required for the actual command oracle"

    def managed(cfg: PaperlessConfig, *args: str, **kwargs: Any) -> str:
        assert args[:6] == ("shell", "--no-startup", "--no-imports", "--interface", "python", "--command")
        return shlex.join([sys.executable, "-c", args[6]])

    monkeypatch.setattr(django, "manage", managed)
    result = subprocess.run(
        [executable, "-c", django.shell_command(config(), apply=True)],
        input=program,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == expected
    assert result.stdout == ""
    assert "synthetic-private-value" not in result.stderr
