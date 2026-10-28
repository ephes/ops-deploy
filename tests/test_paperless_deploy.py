"""Dependency consistency is checked before planning any deployment operation."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr
from pyinfra.api import DeployError

from ops_deploy.infra.postgres_install import PostgresInstallConfig
from ops_deploy.infra.redis_install import RedisInstallConfig
from ops_deploy.services.paperless import PaperlessConfig, PaperlessCredentials, deploy_paperless
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

MODULE = importlib.import_module("ops_deploy.services.paperless.deploy")


def credentials(**kwargs: Any) -> PaperlessCredentials:
    return PaperlessCredentials(
        secret_key="s" * 50, postgres_password="synthetic-db", admin_password="synthetic-admin", **kwargs
    )


def test_shared_redis_mismatch_has_no_planned_or_executed_mutation() -> None:
    cfg = PaperlessConfig(traefik_domain="home.example.test", redis_requirepass_enabled=True)
    result = run_deploy_fake(
        deploy_paperless,
        cfg,
        credentials(redis_password="fixture-a"),
        shared_redis_password=SecretStr("fixture-b"),
        responses=fakehost.UBUNTU,
    )
    assert not result.succeeded
    assert not result.ops
    assert not result.executed_commands
    assert "fixture-a" not in str(result.error)
    assert "fixture-b" not in str(result.error)


def test_original_dependency_defaults_and_custom_consistency() -> None:
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    pg, rd = MODULE.dependency_configs(cfg, credentials(), None, None, None)
    assert pg.version == "17"
    assert rd.bind_addresses == ("127.0.0.1",)
    assert not rd.requirepass_enabled
    with pytest.raises(ValueError, match="authentication and port"):
        MODULE.dependency_configs(cfg, credentials(), None, RedisInstallConfig(requirepass_enabled=True), None)
    with pytest.raises(ValueError, match="version17"):
        MODULE.dependency_configs(cfg, credentials(), PostgresInstallConfig(version="16"), None, None)


@pytest.mark.parametrize(("version", "expected"), [("24.04", ()), ("25.04", ("libleptonica6",)), ("13", ())])
def test_original_distribution_package_condition(
    version: str, expected: tuple[str, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MODULE, "probe", lambda *a, **k: version)
    assert MODULE.version_packages() == expected


def test_uv_interpreter_symlink_still_registers_trust_before_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = PaperlessConfig(traefik_domain="home.example.test", verify_storage_mount=False)

    def stop(**kwargs: Any) -> None:
        raise DeployError("owned test stops before any dependency implementation")

    monkeypatch.setattr(MODULE, "deploy_uv_install", stop)
    responses = {
        **fakehost.UBUNTU,
        **fakehost.symlink(
            "/home/paperless/site/.venv/bin/python",
            "/home/paperless/.local/share/uv/python/bin/python3.14",
            user="paperless",
        ),
    }
    result = run_deploy_fake(deploy_paperless, cfg, credentials(), responses=responses)
    assert not result.succeeded
    assert len(result.ops) == 1
    assert "before dependency changes" in result.ops[0].name
    assert result.ops[0].read_only
    assert not result.executed_commands


def current_dependency_stubs(monkeypatch: pytest.MonkeyPatch, *, role_changed: bool = False) -> SimpleNamespace:
    """Isolate composition boundaries without running dependencies or host writes."""
    current = SimpleNamespace(will_change=False)
    for name in (
        "require_linux",
        "verify_trust",
        "deploy_uv_install",
        "deploy_redis_install",
        "deploy_postgres_install",
    ):
        monkeypatch.setattr(MODULE, name, lambda *a, **k: None)
    monkeypatch.setattr(MODULE, "version_packages", lambda: ())
    monkeypatch.setattr(MODULE, "host", SimpleNamespace(get_fact=lambda *a, **k: {"mode": "755"}))
    monkeypatch.setattr(
        MODULE,
        "postgres_database",
        lambda *a, **k: SimpleNamespace(role=SimpleNamespace(will_change=role_changed), database=current),
    )
    monkeypatch.setattr(MODULE.apt, "packages", lambda *a, **k: current)
    for name in ("require_storage", "account", "directories", "link"):
        monkeypatch.setattr(MODULE.layout, name, lambda *a, **k: current)
    monkeypatch.setattr(MODULE.scanner, "configure_scanner", lambda *a, **k: None)
    for name in ("ensure_venv", "install_packages"):
        monkeypatch.setattr(MODULE.python_runtime, name, lambda *a, **k: current)
    for name in ("python_assets", "nltk", "install_marker"):
        monkeypatch.setattr(MODULE.assets, name, lambda *a, **k: current)
    for name in ("put", "download"):
        monkeypatch.setattr(MODULE.files, name, lambda *a, **k: current)
    monkeypatch.setattr(MODULE.operations, "release", lambda *a, **k: current)
    monkeypatch.setattr(MODULE, "secret_file", lambda *a, **k: current)
    return current


@pytest.mark.parametrize("role_changed", [False, True])
def test_database_role_repair_defers_django_authentication(role_changed: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    current_dependency_stubs(monkeypatch, role_changed=role_changed)
    observed = []

    def migrations(*args: Any, **kwargs: Any) -> None:
        observed.append(kwargs["deferred"])
        raise DeployError("owned boundary before Django authentication")

    monkeypatch.setattr(MODULE.django, "migrate", migrations)
    result = run_deploy_fake(
        deploy_paperless, PaperlessConfig(traefik_domain="home.example.test"), credentials(), responses=fakehost.UBUNTU
    )
    assert not result.succeeded
    assert observed == [role_changed]
    assert not result.executed_commands


@pytest.mark.parametrize("change", ["migration", "static", "release", "packages", "env", "unit", "gunicorn", "ocr"])
def test_original_restart_dependencies_through_deploy_caller(change: str, monkeypatch: pytest.MonkeyPatch) -> None:
    current = current_dependency_stubs(monkeypatch)
    changed = SimpleNamespace(will_change=True)

    def selected(name: str) -> SimpleNamespace:
        return changed if change == name else current

    monkeypatch.setattr(MODULE.operations, "release", lambda *a, **k: selected("release"))
    monkeypatch.setattr(MODULE.python_runtime, "install_packages", lambda *a, **k: selected("packages"))
    monkeypatch.setattr(MODULE, "secret_file", lambda *a, **k: selected("env"))
    monkeypatch.setattr(
        MODULE.files,
        "put",
        lambda *a, **k: selected("gunicorn") if k.get("name") == "Write Paperless gunicorn configuration" else current,
    )
    monkeypatch.setattr(
        MODULE.assets, "python_assets", lambda *a, **k: selected("ocr") if k.get("action") == "ocr" else current
    )
    monkeypatch.setattr(MODULE.django, "migrate", lambda *a, **k: selected("migration"))
    monkeypatch.setattr(MODULE.django, "collect_static", lambda *a, **k: selected("static"))
    monkeypatch.setattr(MODULE.django, "ensure_admin", lambda *a, **k: current)
    monkeypatch.setattr(MODULE.assets, "apparmor", lambda *a, **k: current)
    monkeypatch.setattr(MODULE, "systemd_unit", lambda *a, **k: selected("unit"))
    monkeypatch.setattr(MODULE.systemd, "daemon_reload", lambda *a, **k: current)
    monkeypatch.setattr(MODULE.operations, "rebuild_index", lambda *a, **k: current)
    observed = []

    def rollout(unit: str, *, restart_when: list[SimpleNamespace]) -> None:
        observed.append((unit, any(item is changed for item in restart_when)))

    monkeypatch.setattr(MODULE, "service_rollout", rollout)
    monkeypatch.setattr(MODULE.server, "shell", lambda *a, **k: current)
    monkeypatch.setattr(MODULE, "mark_read_only", lambda op: op)

    def stop(*args: Any, **kwargs: Any) -> None:
        raise DeployError("owned boundary after unit composition; no commands executed")

    monkeypatch.setattr(MODULE, "http_check", stop)
    cfg = PaperlessConfig(traefik_domain="home.example.test", traefik_enabled=False)
    result = run_deploy_fake(deploy_paperless, cfg, credentials(), responses=fakehost.UBUNTU)
    assert not result.succeeded
    assert not result.executed_commands
    expected = {
        "migration": (False, False, False, False),
        "static": (False, False, False, False),
        "release": (True, True, True, True),
        "packages": (True, True, True, True),
        "env": (True, True, True, True),
        "unit": (True, True, True, True),
        "gunicorn": (True, False, False, False),
        "ocr": (False, True, False, True),
    }
    assert observed == list(zip(cfg.units, expected[change], strict=True))
