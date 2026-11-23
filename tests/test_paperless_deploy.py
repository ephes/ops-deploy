"""Dependency consistency is checked before planning any deployment operation."""

from __future__ import annotations

import importlib
import shlex
import subprocess
from pathlib import Path
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
    monkeypatch.setattr(MODULE, "require_gunicorn_forwarder_headers", lambda *a, **k: current)
    monkeypatch.setattr(MODULE, "systemd_unit", lambda *a, **k: selected("unit"))
    monkeypatch.setattr(MODULE.systemd, "daemon_reload", lambda *a, **k: current)
    monkeypatch.setattr(MODULE.operations, "rebuild_index", lambda *a, **k: current)
    observed = []

    def rollout(unit: str, *, restart_when: list[SimpleNamespace]) -> None:
        observed.append((unit, any(item is changed for item in restart_when)))

    monkeypatch.setattr(MODULE, "service_rollout", rollout)
    monkeypatch.setattr(MODULE.server, "shell", lambda *a, **k: current)
    monkeypatch.setattr(MODULE, "mark_read_only", lambda op: op)
    real_health = MODULE.operations.http_health
    readiness_operations = []

    def stop(*args: Any, **kwargs: Any) -> None:
        readiness_operations.append(real_health(*args, **kwargs))
        raise DeployError("owned boundary after unit composition; no commands executed")

    monkeypatch.setattr(MODULE.operations, "http_health", stop)
    cfg = PaperlessConfig(traefik_domain="home.example.test", traefik_enabled=False)
    result = run_deploy_fake(deploy_paperless, cfg, credentials(), responses=fakehost.UBUNTU)
    assert not result.succeeded
    assert not result.executed_commands
    assert len(readiness_operations) == 1
    expected = {
        "migration": (True, True, True, True),
        "static": (False, False, False, False),
        "release": (True, True, True, True),
        "packages": (True, True, True, True),
        "env": (True, True, True, True),
        "unit": (True, True, True, True),
        "gunicorn": (True, False, False, False),
        "ocr": (False, True, False, True),
    }
    assert observed == list(zip(cfg.units, expected[change], strict=True))


def test_paperless_uv_default_tracks_role_and_invalid_mapping_refuses() -> None:
    from ops_deploy.base.uv_install import UvInstallConfig
    from ops_deploy.services.paperless import PaperlessUvConfig

    assert UvInstallConfig().version == "0.13.9"
    assert PaperlessUvConfig().version == "0.13.9"
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    run = run_deploy_fake(
        deploy_paperless,
        cfg,
        credentials(),
        uv=PaperlessUvConfig(install_dir="/opt/foreign"),
        responses=fakehost.UBUNTU,
    )
    assert not run.succeeded
    assert not run.ops
    assert not run.executed_commands


def test_original_installed_virtual_provider_avoids_reinstall_but_missing_provider_installs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ops_deploy.infra import postgres_install

    monkeypatch.setattr(MODULE, "version_packages", lambda: ())
    installed = "\n".join("ii |" + name + "|" for name in MODULE.PACKAGES if name != "libfreetype6-dev")
    installed += "\nii |libfreetype-dev|libfreetype6-dev (= 2.13.2)"
    monkeypatch.setattr(postgres_install, "output", lambda query: installed)
    observed = []
    monkeypatch.setattr(MODULE.apt, "packages", lambda **kwargs: observed.append(kwargs))
    MODULE.prerequisites()
    assert not observed
    installed = installed.replace("libfreetype6-dev (= 2.13.2)", "")
    MODULE.prerequisites()
    assert observed == [{"name": "Install Paperless prerequisite packages", "packages": ["libfreetype6-dev"]}]


@pytest.mark.parametrize("release_changed", [False, True])
def test_release_change_stops_units_before_packages_and_migrations(
    release_changed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """3.5.1's documents.0028 drops tag columns that running 3.4.2 processes select."""
    current = current_dependency_stubs(monkeypatch)
    release = SimpleNamespace(will_change=release_changed, did_change=lambda: release_changed)
    order: list[str] = []
    gates: list[bool] = []

    def release_op(*args: Any, **kwargs: Any) -> SimpleNamespace:
        order.append("release")
        return release

    monkeypatch.setattr(MODULE.operations, "release", release_op)

    def shell(*args: Any, **kwargs: Any) -> SimpleNamespace:
        if kwargs.get("name") == "Stop Paperless units for the release change":
            order.append("stop")
            gates.append(kwargs["_if"]())
            assert kwargs["commands"] == [
                MODULE.django.stop_units_command(PaperlessConfig(traefik_domain="home.example.test"))
            ]
        return current

    def packages(*args: Any, **kwargs: Any) -> SimpleNamespace:
        order.append("packages")
        return current

    def migrations(*args: Any, **kwargs: Any) -> None:
        order.append("migrate")
        raise DeployError("owned boundary at migrations")

    monkeypatch.setattr(MODULE.server, "shell", shell)
    monkeypatch.setattr(MODULE.python_runtime, "install_packages", packages)
    monkeypatch.setattr(MODULE.django, "migrate", migrations)
    result = run_deploy_fake(
        deploy_paperless, PaperlessConfig(traefik_domain="home.example.test"), credentials(), responses=fakehost.UBUNTU
    )
    assert not result.succeeded
    assert order == ["release", "stop", "packages", "migrate"]
    assert gates == [release_changed]


def _run_stop(
    tmp_path: Path, states: dict[str, tuple[str, str]], *, stop_rc: int = 0, after: str = "inactive"
) -> subprocess.CompletedProcess[str]:
    """Run the stop script against a fake systemctl: unit -> (LoadState, ActiveState)."""
    log = tmp_path / "calls"
    stopped = tmp_path / "stopped"
    fake = tmp_path / "systemctl"
    marker = shlex.quote(str(stopped))
    prop = " ".join(
        f"{u}:LoadState) echo {s[0]};; {u}:ActiveState) [ -e {marker} ] && echo {after} || echo {s[1]};;"
        for u, s in states.items()
    )
    fake.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> {shlex.quote(str(log))}\n'
        'case "$1" in\n'
        f"  stop) touch {shlex.quote(str(stopped))}; exit {stop_rc};;\n"
        '  show) prop=${2#--property=}; unit=$5; case "$unit:$prop" in ' + prop + " *) exit 1;; esac;;\n"
        "esac\n"
    )
    fake.chmod(0o755)
    cmd = MODULE.django.stop_units_command(PaperlessConfig(traefik_domain="home.example.test"))
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin"}
    return subprocess.run(shlex.split(cmd), env=env, capture_output=True, text=True, check=False)


UNITS = PaperlessConfig(traefik_domain="home.example.test").units


def test_stop_script_stops_all_loaded_units_in_one_call(tmp_path: Path) -> None:
    result = _run_stop(tmp_path, {unit: ("loaded", "active") for unit in UNITS})
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "calls").read_text().splitlines()
    assert [c for c in calls if c.startswith("stop")] == ["stop -- " + " ".join(UNITS)]


def test_stop_script_fails_when_stop_fails_or_a_unit_is_not_down(tmp_path: Path) -> None:
    loaded = {unit: ("loaded", "active") for unit in UNITS}
    for sub in ("a", "b"):
        (tmp_path / sub).mkdir()
    assert _run_stop(tmp_path / "a", loaded, stop_rc=1).returncode != 0
    failed = _run_stop(tmp_path / "b", loaded, after="deactivating")
    assert failed.returncode != 0
    assert "still deactivating" in failed.stderr


def test_stop_script_stops_a_running_unit_whose_file_is_gone(tmp_path: Path) -> None:
    states = {unit: ("not-found", "inactive") for unit in UNITS}
    states[UNITS[1]] = ("not-found", "active")
    result = _run_stop(tmp_path, states)
    assert result.returncode == 0, result.stderr
    assert "stop -- " + UNITS[1] in (tmp_path / "calls").read_text().splitlines()


def test_stop_script_skips_absent_units_and_fails_on_inspection_errors(tmp_path: Path) -> None:
    for sub in ("a", "b"):
        (tmp_path / sub).mkdir()
    result = _run_stop(tmp_path / "a", {unit: ("not-found", "inactive") for unit in UNITS})
    assert result.returncode == 0
    assert not any(c.startswith("stop") for c in (tmp_path / "a" / "calls").read_text().splitlines())
    partial = {unit: ("loaded", "inactive") for unit in UNITS[1:]}
    assert _run_stop(tmp_path / "b", partial).returncode != 0


@pytest.mark.parametrize("ignore_errors", [False, True])
def test_pending_migrations_run_only_behind_a_confirmed_stop(
    ignore_errors: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real migrate operation (link already current, migrations pending).

    The stop and `migrate` are one command joined by `&&`, so a failed stop can
    never reach `migrate`, whether or not the run ignores errors.
    """
    from pyinfra.api import Config, deploy

    django = MODULE.django
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    monkeypatch.setattr(django, "migrations_pending", lambda _cfg: True)

    @deploy("migrate")
    def run() -> None:
        django.migrate(name="migrate", cfg=cfg)

    stop = django.stop_units_command(cfg)
    result = run_deploy_fake(run, pyinfra_config=Config(IGNORE_ERRORS=ignore_errors))
    commands = [c for c in result.executed_commands if "migrate" in c]
    assert commands == [stop + " && " + django.manage(cfg, "migrate", quiet=True)]
    assert all(c.startswith(stop + " && ") for c in result.executed_commands if "manage.py" in c and "migrate" in c)


def test_failed_stop_never_reaches_the_command_after_it(tmp_path: Path) -> None:
    """Shell semantics of the joined command, with a stop that fails."""
    marker = tmp_path / "migrated"
    (tmp_path / "systemctl").write_text('#!/bin/sh\ncase "$1" in show) echo loaded;; stop) exit 1;; esac\n')
    (tmp_path / "systemctl").chmod(0o755)
    stop = MODULE.django.stop_units_command(PaperlessConfig(traefik_domain="home.example.test"))
    command = stop + " && " + shlex.join(["touch", str(marker)])
    result = subprocess.run(
        ["sh", "-c", command], env={"PATH": f"{tmp_path}:/usr/bin:/bin"}, capture_output=True, text=True, check=False
    )
    assert result.returncode != 0
    assert not marker.exists()
