"""Deploy-level scenarios for the toyweb service (all P1.4 helpers together)."""

from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers.traefik import hash_password, render_route
from ops_deploy.services.toyweb import ToywebConfig, deploy_toyweb
from ops_deploy.services.toyweb.deploy import TEMPLATE_PACKAGE, traefik_config
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

PASSWORD = "toyweb-fixture-password"
ROUTE = "/etc/traefik/dynamic/toyweb.yml"
UNIT = "/etc/systemd/system/toyweb.service"
UV_SYNC = (
    "cd /home/toyweb/site && runuser -u toyweb -- env HOME=/home/toyweb "
    "UV_PROJECT_ENVIRONMENT=/home/toyweb/site/.venv /usr/local/bin/uv sync --no-dev --python 3.12"
)


@pytest.fixture
def cfg() -> ToywebConfig:
    return ToywebConfig(secrets=SecretRef("secrets/toyweb.yml"))


@pytest.fixture
def secrets(cfg: ToywebConfig) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {"basic_auth_password": PASSWORD})


# Hashed once per test session: bcrypt is deliberately slow-ish.
_HASH = hash_password(PASSWORD)


def converged(cfg: ToywebConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where toyweb is fully deployed; ``drift`` overrides file content."""

    content = {
        "pyproject": render(TEMPLATE_PACKAGE, "pyproject.toml.j2", cfg=cfg),
        "env": render(TEMPLATE_PACKAGE, "toyweb.env.j2", cfg=cfg),
        "unit": render(TEMPLATE_PACKAGE, "toyweb.service.j2", cfg=cfg),
        "route": render_route(traefik_config(cfg, secrets), _HASH),
    }
    content.update(drift)
    responses: dict[str, Any] = {**fakehost.LINUX, **fakehost.system_account("toyweb", "/home/toyweb")}
    for path in ("/home/toyweb", "/home/toyweb/site", "/home/toyweb/site/app", "/home/toyweb/site/static"):
        responses.update(fakehost.directory(path, user="toyweb"))
    responses.update(fakehost.directory("/etc/systemd/system"))
    responses.update(fakehost.directory("/etc/traefik/dynamic"))
    responses.update(fakehost.file("/home/toyweb/site/pyproject.toml", content["pyproject"], user="toyweb"))
    responses.update(fakehost.file("/home/toyweb/site/.env", content["env"], user="toyweb", mode="-rw-------"))
    responses.update(fakehost.file(UNIT, content["unit"]))
    responses.update(fakehost.file(ROUTE, content["route"]))
    responses.update(fakehost.venv("/home/toyweb/site/.venv"))
    responses.update(fakehost.service("toyweb.service"))
    responses.update(fakehost.service("traefik.service"))
    return responses


def deploy(cfg: ToywebConfig, secrets: SecretValues, responses: dict[str, Any] | None = None) -> FakeRun:
    run = run_deploy_fake(deploy_toyweb, cfg, secrets, responses=responses or dict(fakehost.LINUX))
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything_and_starts_once(cfg: ToywebConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    commands = run.executed_commands
    assert "useradd -d /home/toyweb -s /bin/bash -g toyweb -r -M toyweb" in commands
    assert UV_SYNC in commands
    assert commands.index(UV_SYNC) < commands.index("systemctl start toyweb.service")
    assert commands.index("systemctl daemon-reload") < commands.index("systemctl start toyweb.service")
    assert "systemctl restart toyweb.service" not in commands
    assert run.uploaded_paths == [
        "/home/toyweb/site/pyproject.toml",
        "/home/toyweb/site/.env",
        UNIT,
        ROUTE,
    ]
    assert [op for op in run.ops if op.read_only] == [
        run.op("Deploy toyweb service | Wait for port 127.0.0.1:10098"),
        run.op("Deploy toyweb service | Check http://127.0.0.1:10098/"),
    ]


def test_second_run_changes_nothing_mutating(cfg: ToywebConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert run.changed_ops == [
        "Deploy toyweb service | Wait for port 127.0.0.1:10098",
        "Deploy toyweb service | Check http://127.0.0.1:10098/",
    ]
    assert not any(command.startswith(("systemctl", "cd ")) for command in run.executed_commands)


def test_dependency_change_syncs_migrates_and_restarts(cfg: ToywebConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, pyproject="[project]\nname = 'old'\n"))

    assert run.mutating_changed_ops == [
        "Deploy toyweb service | Write /home/toyweb/site/pyproject.toml",
        "Deploy toyweb service | uv sync /home/toyweb/site",
        "Deploy toyweb service | manage.py migrate --noinput",
        "Deploy toyweb service | manage.py collectstatic --noinput",
        "Deploy toyweb service | Restart toyweb.service",
    ]
    assert "systemctl daemon-reload" not in run.executed_commands


def test_env_change_restarts_without_sync(cfg: ToywebConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, env="STALE=1\n"))

    assert run.mutating_changed_ops == [
        "Deploy toyweb service | Write /home/toyweb/site/.env",
        "Deploy toyweb service | Restart toyweb.service",
    ]


def test_unit_change_reloads_before_restart(cfg: ToywebConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, unit="[Unit]\nDescription=old\n"))

    commands = run.executed_commands
    assert commands.index("systemctl daemon-reload") < commands.index("systemctl restart toyweb.service")
    assert UV_SYNC not in commands


def test_missing_venv_forces_sync_even_without_changes(cfg: ToywebConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets)
    del responses["test -x /home/toyweb/site/.venv/bin/python"]

    run = deploy(cfg, secrets, responses)

    assert UV_SYNC in run.executed_commands
    # The sync alone restarts; migrations only follow a changed sync.
    assert "systemctl restart toyweb.service" in run.executed_commands


def test_password_change_rewrites_route_and_restarts_traefik(cfg: ToywebConfig, secrets: SecretValues) -> None:
    assert cfg.secrets is not None
    rotated = SecretValues(cfg.secrets, {"basic_auth_password": "rotated-fixture-password"})

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy toyweb service | Write Traefik route toyweb",
        "Deploy toyweb service | Restart Traefik for toyweb",
    ]
    assert "systemctl restart traefik.service" in run.executed_commands
    assert _HASH.encode() not in run.upload(ROUTE)


@pytest.mark.parametrize("scenario", ["first", "converged"])
def test_password_never_recorded(cfg: ToywebConfig, secrets: SecretValues, scenario: str) -> None:
    responses = converged(cfg, secrets) if scenario == "converged" else None

    run = deploy(cfg, secrets, responses)

    assert PASSWORD not in run.all_text()
    assert PASSWORD not in repr([op for op in run.ops])


def test_missing_secret_key_fails_before_any_operation(cfg: ToywebConfig) -> None:
    assert cfg.secrets is not None
    with pytest.raises(KeyError, match="basic_auth_password"):
        run_deploy_fake(deploy_toyweb, cfg, SecretValues(cfg.secrets, {}))


def test_service_name_with_underscore_deploys() -> None:
    cfg = ToywebConfig(service_name="toy_web", secrets=SecretRef("secrets/toyweb.yml"))
    assert cfg.secrets is not None

    run = deploy(cfg, SecretValues(cfg.secrets, {"basic_auth_password": PASSWORD}))

    assert "/etc/traefik/dynamic/toy_web.yml" in run.uploaded_paths
