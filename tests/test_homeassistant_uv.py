"""UV dependency and fake execution; no native installer claim."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base.uv_install import UvInstallConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.services.homeassistant.uv import HomeAssistantUvConfig, install_uv
from ops_deploy.testing import run_deploy_fake
from tests import fakehost


def test_version_follows_the_shared_installer() -> None:
    # Composition keeps the shared installer's default rather than an older one of its own.
    assert HomeAssistantUvConfig().version == UvInstallConfig().version


@pytest.mark.parametrize("as_model", [False, True])
def test_independent_binary_path_and_installer_owner(as_model: bool) -> None:
    values: dict[str, Any] = {"install_dir": "/srv/owned/bin", "owner": "uvowner", "group": "uvgroup"}
    uv = HomeAssistantUvConfig(**values) if as_model else values
    cfg = HomeAssistantRuntimeConfig.model_validate({"uv": uv})
    assert cfg.uv_path == "/srv/owned/bin/uv"
    assert cfg.uv.owner == "uvowner"
    assert cfg.uv.group == "uvgroup"
    override = HomeAssistantRuntimeConfig.model_validate({"uv": uv, "uv_path": "/opt/existing/uv"})
    assert override.uv_path == "/opt/existing/uv"
    assert override.uv.install_dir == "/srv/owned/bin"


@pytest.mark.parametrize("values", [{"darwin": True}, {"install_user": "ignored"}, {"version": "latest"}])
def test_invalid_dependency_inputs(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        HomeAssistantUvConfig(**values)


def test_disabled_dependency_does_not_probe_install_or_verify() -> None:
    run = run_deploy_fake(lambda: install_uv(HomeAssistantUvConfig(), manage=False))
    assert run.succeeded, run.error
    assert run.ops == []
    assert run.executed_commands == []


@pytest.mark.parametrize(
    ("version", "update", "force", "expected"),
    [
        ("0.13.5", True, False, False),
        ("0.13.4", True, False, True),
        ("0.13.4", False, False, False),
        ("0.13.5", False, True, True),
    ],
)
def test_actual_component_install_gate_and_post_checks(version: str, update: bool, force: bool, expected: bool) -> None:
    cfg = HomeAssistantUvConfig(update_existing=update, force_reinstall=force)
    responses = {
        **fakehost.LINUX,
        "uname -m": ["x86_64"],
        "/usr/local/bin/uv --version": [f"uv {version} (x86_64-unknown-linux-gnu)"],
        **fakehost.directory("/usr/local/bin"),
        **fakehost.file("/usr/local/bin/uv", "binary", mode="-rwxr-xr-x"),
        **fakehost.file("/usr/local/bin/uvx", "binary", mode="-rwxr-xr-x"),
    }
    run = run_deploy_fake(lambda: install_uv(cfg, manage=True), responses=responses)
    assert run.succeeded, run.error
    downloads = [command for command in run.executed_commands if "release.tar.gz" in command]
    assert bool(downloads) is expected
    assert run.executed_commands[-1] == "/usr/local/bin/uv --version && /usr/local/bin/uv --help >/dev/null"
    if expected:
        assert "/download/0.13.5/" in downloads[0]
        assert cfg.checksums["x86_64-unknown-linux-gnu"] in downloads[0]
    else:
        assert run.mutating_changed_ops == []
        assert run.changed_ops == ["Verify Home Assistant UV version and functionality"]
        assert run.uploads == []


@pytest.mark.parametrize("broken", [False, True])
def test_update_disabled_does_not_invent_uv_or_uvx_repair(broken: bool) -> None:
    responses = {
        "/usr/local/bin/uv --version &&": {"success": not broken},
        **fakehost.LINUX,
        "uname -m": ["x86_64"],
        "/usr/local/bin/uv --version": [] if broken else ["uv 0.13.5 (x86_64-unknown-linux-gnu)"],
        **fakehost.directory("/usr/local/bin"),
        **fakehost.file("/usr/local/bin/uv", "binary", mode="-rwxr-xr-x"),
        # uvx is deliberately absent. Original role does not inspect it.
    }
    run = run_deploy_fake(
        lambda: install_uv(HomeAssistantUvConfig(update_existing=False), manage=True), responses=responses
    )
    assert run.succeeded is not broken
    assert not any("release.tar.gz" in c for c in run.executed_commands)
    assert run.mutating_changed_ops == []


def test_symlink_replacement_and_effective_owner_path_reach_actual_script() -> None:
    cfg = HomeAssistantUvConfig(install_dir="/srv/owned/bin", owner="uvowner", group="uvgroup", update_existing=False)
    run = run_deploy_fake(
        lambda: install_uv(cfg, manage=True),
        responses={
            **fakehost.LINUX,
            "uname -m": ["x86_64"],
            **fakehost.symlink("/srv/owned/bin/uv", "/old/uv"),
        },
    )
    assert run.succeeded, run.error
    (command,) = [c for c in run.executed_commands if "release.tar.gz" in c]
    assert "install -o uvowner -g uvgroup -m 0755" in command
    assert "/srv/owned/bin/.uv.ops-deploy-new /srv/owned/bin/uv" in command
    assert "/srv/owned/bin/.uvx.ops-deploy-new /srv/owned/bin/uvx" in command
    assert run.executed_commands[-1] == "/srv/owned/bin/uv --version && /srv/owned/bin/uv --help >/dev/null"


def test_foreign_owned_uv_is_never_run_and_gets_fresh_bytes() -> None:
    responses = {
        **fakehost.LINUX,
        "uname -m": ["x86_64"],
        **fakehost.directory("/usr/local/bin"),
        **fakehost.file("/usr/local/bin/uv", "binary", user="cast", mode="-rwxr-xr-x"),
        "/usr/local/bin/uv --version": ["uv 0.13.5 (x86_64-unknown-linux-gnu)"],
    }

    run = run_deploy_fake(lambda: install_uv(HomeAssistantUvConfig(), manage=True), responses=responses)

    assert any("release.tar.gz" in c for c in run.executed_commands)
    assert not any(e.value.startswith("/usr/local/bin/uv --version") for e in run.events if e.kind == "fact")


def test_broken_trusted_uv_is_reinstalled_when_updates_are_on() -> None:
    responses = {
        **fakehost.LINUX,
        "uname -m": ["x86_64"],
        **fakehost.directory("/usr/local/bin"),
        **fakehost.file("/usr/local/bin/uv", "binary", mode="-rwxr-xr-x"),
        "/usr/local/bin/uv --version": [],
    }

    run = run_deploy_fake(lambda: install_uv(HomeAssistantUvConfig(), manage=True), responses=responses)

    assert any("release.tar.gz" in c for c in run.executed_commands)


def test_newer_uv_is_kept() -> None:
    responses = {
        **fakehost.LINUX,
        "uname -m": ["x86_64"],
        "/usr/local/bin/uv --version &&": {"success": True},
        **fakehost.directory("/usr/local/bin"),
        **fakehost.file("/usr/local/bin/uv", "binary", mode="-rwxr-xr-x"),
        "/usr/local/bin/uv --version": ["uv 9.0.0 (x86_64-unknown-linux-gnu)"],
    }

    run = run_deploy_fake(lambda: install_uv(HomeAssistantUvConfig(), manage=True), responses=responses)

    assert run.succeeded, run.error
    assert not any("release.tar.gz" in c for c in run.executed_commands)
    assert run.mutating_changed_ops == []
