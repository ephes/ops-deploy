"""Validation/rendering contracts of the minimal native subset."""

from __future__ import annotations

import tomllib
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.core.config import ConfigValidationError
from ops_deploy.helpers.traefik import TraefikRoute
from ops_deploy.services.native_app import NativeAppConfig
from ops_deploy.services.native_app.config import TomlData
from ops_deploy.services.native_app.render import render_route, render_toml, render_unit


def _app(**changes: Any) -> NativeAppConfig:
    data: dict[str, Any] = {
        "service_name": "music_fixture",
        "title": "Music fixture",
        "user": "music_fixture",
        "site_path": "/var/lib/music-fixture",
        "account": {"name": "music_fixture", "group": "music_fixture", "home": "/var/lib/music-fixture"},
        "source": {
            "version": "1.2.3",
            "url": "https://downloads.example.invalid/app_{arch}.tar.gz",
            "checksums": {"aarch64": "1" * 64},
            "member": "server",
            "dest": "/opt/music-fixture/server",
        },
        "unit": {
            "name": "music-fixture",
            "description": "Music fixture",
            "user": "music_fixture",
            "group": "music_fixture",
            "working_directory": "/opt/music-fixture",
            "exec_start": ["/opt/music-fixture/server", "--configfile", "/etc/music-fixture.toml"],
        },
    }
    data.update(changes)
    return NativeAppConfig.model_validate(data)


def _validate_render(bad: dict[str, Any]) -> None:
    cfg = _app(**bad)
    for config in cfg.configs:
        render_toml(config.data)


@pytest.mark.parametrize(
    "bad",
    [
        {"source": {"kind": "apt"}},
        {"source": {"kind": "pypi_uv"}},
        {"source": {"version": "master"}},
        {"mounts_required": ["/data/../other"]},
        {"health_url": "http://127.0.0.1/$(touch)"},
        {"health_url": "http://outside.example.invalid/"},
        {"configs": [{"path": "/etc/fixture.toml", "data": {"x": {"not a key": True}}}]},
    ],
)
def test_invalid_inputs_refuse(bad: dict[str, Any]) -> None:
    with pytest.raises((ConfigValidationError, ValidationError, ValueError)):
        _validate_render(bad)


def test_toml_scalar_types_and_escaping() -> None:
    data: TomlData = {
        "Address": "127.0.0.1",
        "Port": 18002,
        "Message": 'quote " and newline\n',
        "Enabled": False,
        "Scanner": {"Schedule": "@every 6h", "FollowSymlinks": True},
    }
    assert tomllib.loads(render_toml(data)) == data


def test_unit_uses_argv_without_shell_and_retains_mounts() -> None:
    cfg = _app(mounts_required=["/data"])
    text = render_unit(cfg)
    assert 'ExecStart="/opt/music-fixture/server" "--configfile" "/etc/music-fixture.toml"' in text
    assert "RequiresMountsFor=/data" in text
    assert "After=network-online.target" in text
    assert "Environment=ND_" not in text


def test_route_shapes_and_explicit_public_reason() -> None:
    route = TraefikRoute(name="fixture", host="fixture.example.invalid", app_port=18002)
    parsed = yaml.safe_load(render_route(route, None))["http"]
    assert parsed["routers"]["fixture-http"]["service"] == "fixture"
    assert parsed["services"]["fixture"]["loadBalancer"]["servers"] == [{"url": "http://127.0.0.1:18002"}]
    with pytest.raises(ConfigValidationError):
        NativeAppConfig.model_validate(
            {
                "service_name": "route_fixture",
                "title": "Fixture",
                "user": "root",
                "site_path": "/var/lib/fixture",
                "route": {"host": "fixture.example.invalid", "port": 18002, "access": "public"},
            }
        )


def test_empty_auth_user_refuses_before_host(monkeypatch: pytest.MonkeyPatch) -> None:
    import ops_deploy.services.native_app.deploy as module
    from ops_deploy.core.secrets import SecretRef, SecretValues
    from ops_deploy.services.native_app import deploy_native_app

    def no_host(_script: str) -> str:
        raise AssertionError("preflight reached before rejecting invalid auth")

    monkeypatch.setattr(module, "_fact", no_host)
    ref = SecretRef("secrets/fixture/auth.yml")

    def attempt() -> None:
        cfg = NativeAppConfig.model_validate(
            {
                "service_name": "auth_fixture",
                "title": "Auth fixture",
                "user": "root",
                "site_path": "/var/lib/auth-fixture",
                "secrets": ref,
                "route": {
                    "host": "auth.example.invalid",
                    "port": 18002,
                    "access": "internal_or_basic_auth",
                    "basic_auth_user": "",
                    "basic_auth_password": {"secret": "password"},
                },
            }
        )
        deploy_native_app(cfg, SecretValues(ref, {"password": "fixture-password"}))

    with pytest.raises(ConfigValidationError):
        attempt()


def test_environment_keeps_literal_dollars() -> None:
    cfg = _app()
    assert cfg.unit is not None
    cfg = cfg.model_copy(update={"unit": cfg.unit.model_copy(update={"environment": {"LITERAL": "$prefix"}})})
    assert 'Environment="LITERAL=$prefix"' in render_unit(cfg)
