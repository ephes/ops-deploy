"""remove_native_app: a route-only app's route and deploy state go; Traefik is not restarted."""

from __future__ import annotations

from typing import Any

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.native_app import NativeAppConfig, NativeAppRemoveConfig, remove_native_app
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

ROUTE = "/etc/traefik/dynamic/proxy-fixture.yml"
STATE = "/var/lib/ops-deploy/proxy_fixture"


def _route_only(**changes: Any) -> NativeAppConfig:
    data: dict[str, Any] = {
        "service_name": "proxy_fixture",
        "title": "Proxy fixture",
        "user": "root",
        "site_path": STATE,
        "secrets": "secrets/fixture/proxy.yml",
        "route": {
            "name": "proxy-fixture",
            "host": "proxy.example.invalid",
            "port": 18001,
            "backend_host": "backend.example.invalid",
            "remote_reason": "Existing separately managed backend",
            "access": "internal_or_basic_auth",
            "basic_auth_user": "fixture",
            "basic_auth_password": {"secret": "password"},
        },
    }
    data.update(changes)
    return NativeAppConfig.model_validate(data)


def _run(cfg: NativeAppRemoveConfig, present: tuple[str, ...] = (ROUTE, STATE)) -> FakeRun:
    return run_deploy_fake(
        remove_native_app,
        cfg,
        responses={
            **fakehost.LINUX,
            **{f"{{ test -e {path} || test -L {path}; }} && echo yes": ["yes"] for path in present},
        },
    )


def test_remove_needs_confirmation() -> None:
    run = _run(NativeAppRemoveConfig(app=_route_only()))

    assert not run.succeeded
    assert "not confirmed" in str(run.error)
    assert run.executed_commands == []


def test_remove_takes_the_route_behind_the_guard_and_the_state() -> None:
    run = _run(NativeAppRemoveConfig(app=_route_only(), confirm=True))

    assert run.succeeded, run.error
    assert run.executed_commands == [route_guard_command(), f"rm -rf {ROUTE}", f"rm -rf {STATE}"]
    assert not any("traefik" in command and "systemctl" in command for command in run.executed_commands)


def test_a_dangling_symlink_counts_as_present() -> None:
    # `test -e` is false for a symlink whose target is gone; Ansible's
    # `state: absent` removes one, so the probe also asks `test -L`.
    run = _run(NativeAppRemoveConfig(app=_route_only(), confirm=True), present=(ROUTE,))

    assert run.succeeded, run.error
    assert run.executed_commands == [route_guard_command(), f"rm -rf {ROUTE}"]
    for path in (ROUTE, STATE):
        assert any(f"test -e {path} || test -L {path}" in command for command in run.fact_commands)


def test_the_route_name_defaults_to_the_service_name() -> None:
    app = _route_only()
    assert app.route is not None
    unnamed = app.model_copy(update={"route": app.route.model_copy(update={"name": None})})
    route = "/etc/traefik/dynamic/proxy-fixture.yml"

    run = _run(NativeAppRemoveConfig(app=unnamed, confirm=True), present=(route,))

    assert run.succeeded, run.error
    assert run.executed_commands == [route_guard_command(), f"rm -rf {route}"]


def test_a_removed_app_changes_nothing() -> None:
    run = _run(NativeAppRemoveConfig(app=_route_only(), confirm=True), present=())

    assert run.succeeded, run.error
    assert run.executed_commands == []
    assert not run.changed_ops


def test_an_app_with_a_unit_is_refused_before_any_change() -> None:
    app = NativeAppConfig.model_validate(
        {
            "service_name": "music_fixture",
            "title": "Music fixture",
            "user": "music_fixture",
            "site_path": "/var/lib/music-fixture",
            "account": {"name": "music_fixture", "group": "music_fixture", "home": "/var/lib/music-fixture"},
            "unit": {
                "name": "music-fixture",
                "description": "Music fixture",
                "user": "music_fixture",
                "group": "music_fixture",
                "working_directory": "/opt/music-fixture",
                "exec_start": ["/opt/music-fixture/server"],
            },
        }
    )

    run = _run(NativeAppRemoveConfig(app=app, confirm=True))

    assert not run.succeeded
    assert "only route-only native apps" in str(run.error)
    assert run.executed_commands == []
