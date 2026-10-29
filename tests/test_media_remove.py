"""Original media removal effects, independent keep flags and failure boundaries."""

from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services._lifecycle import media_remove as common
from ops_deploy.services.jellyfin import JellyfinRemoveConfig, deploy_jellyfin_remove
from ops_deploy.services.metube import MetubeRemoveConfig, deploy_metube_remove
from ops_deploy.services.navidrome import NavidromeRemoveConfig, deploy_navidrome_remove
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

SERVICES = [
    (NavidromeRemoveConfig, deploy_navidrome_remove),
    (MetubeRemoveConfig, deploy_metube_remove),
    (JellyfinRemoveConfig, deploy_jellyfin_remove),
]


def state_for(cfg: Any, *, present: bool = True) -> dict[str, Any]:
    paths = {v for k, v in cfg.model_dump().items() if isinstance(v, str) and v.startswith("/")}
    if isinstance(cfg, NavidromeRemoveConfig):
        paths |= {cfg.cache_dir or f"{cfg.data_dir}/cache", cfg.bin_path or f"{cfg.install_dir}/navidrome"}
    return {
        "paths": {p: {"mode": stat.S_IFDIR | 0o700, "uid": 0, "gid": 0} if present else None for p in paths},
        "user": {"uid": 900, "gid": 900, "home": "/owned/service-home"} if present and cfg.remove_user else None,
        "group": 900 if present and cfg.remove_user else None,
        "packages": list(common.PACKAGES) if present and getattr(cfg, "remove_packages", False) else [],
    }


def run(cfg: Any, deploy: Any, *, present: bool = True, metadata: Any = ..., active: bool = True) -> FakeRun:
    # Match only selected paths: keeping a flag does not need metadata about it.
    from unittest.mock import patch

    import ops_deploy.helpers.probes as probes

    state = state_for(cfg, present=present) if metadata is ... else metadata
    original = probes.probe

    def selected(command: str, **kwargs: Any) -> str | None:
        if command == common._command("inspect"):
            request = json.loads(kwargs["stdin"])
            if metadata is ... and isinstance(state, dict) and "paths" in state:
                chosen = {**state, "paths": {p: state["paths"][p] for p in request["paths"]}}
                return json.dumps(chosen)
            return None if state is None else json.dumps(state)
        return original(command, **kwargs)

    with patch.object(common, "probe", side_effect=selected):
        return run_deploy_fake(
            deploy,
            cfg,
            responses={
                **fakehost.LINUX,
                "cat /proc/1/comm": ["systemd"],
                "for unit in": [
                    f"Id={cfg.service_name}.service",
                    "LoadState=loaded" if present else "LoadState=not-found",
                    "ActiveState=active" if present and active else "ActiveState=inactive",
                    "UnitFileState=enabled" if present and active else "UnitFileState=disabled",
                    "---",
                ],
            },
        )


@pytest.mark.parametrize(("model", "deploy"), SERVICES)
def test_confirm_refuses_before_facts_or_commands(model: Any, deploy: Any) -> None:
    result = run(model(), deploy)
    assert not result.succeeded
    assert "not confirmed" in str(result.error)
    assert not result.events


@pytest.mark.parametrize(("model", "deploy"), SERVICES)
def test_absent_repeat_is_empty_and_no_shadow_or_broad_account_reads(model: Any, deploy: Any) -> None:
    result = run(model(confirm=True), deploy, present=False)
    assert result.succeeded, result.error
    assert not result.changed_ops
    assert not result.executed_commands
    assert not any("/etc/passwd" in e.value or "/etc/shadow" in e.value for e in result.events)


def test_navidrome_default_order_and_no_music_path() -> None:
    result = run(NavidromeRemoveConfig(confirm=True), deploy_navidrome_remove)
    assert result.succeeded, result.error
    commands = result.executed_commands
    assert commands[:2] == ["systemctl stop navidrome.service || true", "systemctl disable navidrome.service || true"]
    assert commands.index("rm -rf -- /etc/systemd/system/navidrome-rescan.timer") < commands.index(
        "systemctl daemon-reload"
    )
    assert commands.index("systemctl daemon-reload") < commands.index("rm -rf -- /etc/navidrome.toml")
    assert "rm -rf -- /var/lib/navidrome/cache" in commands
    assert commands[-1].endswith(" accounts")
    assert not any("/media/" in command or "reload traefik" in command for command in commands)


@pytest.mark.parametrize(
    ("flag", "paths"),
    [
        ("remove_data", ["/var/lib/navidrome", "/var/lib/navidrome/cache"]),
        ("remove_logs", ["/var/log/navidrome"]),
        ("remove_binary", ["/opt/navidrome/navidrome", "/usr/local/bin/navidrome", "/opt/navidrome"]),
        ("remove_traefik_config", ["/etc/traefik/dynamic/navidrome.yml"]),
    ],
)
def test_navidrome_each_keep_flag(flag: str, paths: list[str]) -> None:
    cfg = NavidromeRemoveConfig.model_validate({"confirm": True, flag: False})
    result = run(cfg, deploy_navidrome_remove)
    assert result.succeeded, result.error
    assert all("rm -rf -- " + p not in result.executed_commands for p in paths)
    assert "rm -rf -- /etc/navidrome.toml" in result.executed_commands


def test_metube_downloads_default_keep_and_handlers_at_completion() -> None:
    result = run(MetubeRemoveConfig(confirm=True), deploy_metube_remove)
    assert result.succeeded, result.error
    commands = result.executed_commands
    assert not any("/mnt/cryptdata" in c for c in commands)
    assert "rm -rf -- /var/cache/metube" in commands
    assert commands[-1] == "systemctl reload traefik || true"
    assert commands.index("systemctl daemon-reload") > commands.index("rm -rf -- /etc/metube")


@pytest.mark.parametrize(
    ("flag", "paths"),
    [
        ("remove_service", ["/etc/systemd/system/metube.service"]),
        ("remove_install_dir", ["/opt/metube", "/var/cache/metube"]),
        ("remove_state", ["/var/lib/metube"]),
        ("remove_env", ["/etc/metube"]),
        ("remove_traefik_config", ["/etc/traefik/dynamic/metube.yml"]),
    ],
)
def test_metube_each_keep_flag(flag: str, paths: list[str]) -> None:
    result = run(MetubeRemoveConfig.model_validate({"confirm": True, flag: False}), deploy_metube_remove)
    assert result.succeeded, result.error
    assert all("rm -rf -- " + p not in result.executed_commands for p in paths)
    if flag == "remove_service":
        assert not any("systemctl" in c and "metube" in c for c in result.executed_commands)
    if flag == "remove_traefik_config":
        assert "systemctl reload traefik || true" not in result.executed_commands


def test_metube_download_opt_in_and_literal_space_paths() -> None:
    cfg = MetubeRemoveConfig(
        confirm=True,
        remove_downloads=True,
        download_dir="/owned/media downloads",
        service_name="owned-metube",
        service_unit="/owned/unit files/custom.service",
        user="owned_media",
        group="owned_media",
    )
    result = run(cfg, deploy_metube_remove)
    assert result.succeeded, result.error
    assert "rm -rf -- '/owned/media downloads'" in result.executed_commands
    assert "rm -rf -- '/owned/unit files/custom.service'" in result.executed_commands
    assert "systemctl stop owned-metube.service || true" in result.executed_commands


def test_jellyfin_purges_only_original_four_including_config_only() -> None:
    cfg = JellyfinRemoveConfig(confirm=True)
    result = run(cfg, deploy_jellyfin_remove)
    assert result.succeeded, result.error
    command = next(c for c in result.executed_commands if "apt-get" in c)
    assert command == "env DEBIAN_FRONTEND=noninteractive apt-get -y purge -- " + " ".join(common.PACKAGES)
    assert not any(
        "keyring" in c or "sources.list" in c or "/media/" in c or "apache2-utils" in c
        for c in result.executed_commands
    )


@pytest.mark.parametrize(
    ("flag", "path"),
    [
        ("remove_config", "/etc/jellyfin"),
        ("remove_data", "/var/lib/jellyfin"),
        ("remove_logs", "/var/log/jellyfin"),
        ("remove_traefik_config", "/etc/traefik/dynamic/jellyfin.yml"),
    ],
)
def test_jellyfin_each_keep_flag(flag: str, path: str) -> None:
    result = run(JellyfinRemoveConfig.model_validate({"confirm": True, flag: False}), deploy_jellyfin_remove)
    assert result.succeeded, result.error
    assert "rm -rf -- " + path not in result.executed_commands


@pytest.mark.parametrize(("model", "deploy"), SERVICES)
def test_keep_user_does_not_collect_or_remove_account(model: Any, deploy: Any) -> None:
    result = run(model(confirm=True, remove_user=False), deploy)
    assert result.succeeded, result.error
    assert not any(c.endswith(" accounts") for c in result.executed_commands)


def test_jellyfin_keep_packages_does_not_query_or_purge() -> None:
    result = run(JellyfinRemoveConfig(confirm=True, remove_packages=False), deploy_jellyfin_remove)
    assert result.succeeded, result.error
    assert not any("apt-get" in c for c in result.executed_commands)


@pytest.mark.parametrize("invalid", [None, {}, {"paths": {}, "user": None, "group": None, "packages": []}])
def test_incomplete_metadata_refuses_before_effects(invalid: Any) -> None:
    result = run(NavidromeRemoveConfig(confirm=True), deploy_navidrome_remove, metadata=invalid)
    assert not result.succeeded
    assert not result.executed_commands


@pytest.mark.parametrize("home", ["/", "//etc/", "/var/lib", "/tmp/../root", "relative"])
def test_protected_account_home_refuses_before_effects(home: str) -> None:
    cfg = NavidromeRemoveConfig(confirm=True)
    state = state_for(cfg)
    state["user"]["home"] = home
    result = run(cfg, deploy_navidrome_remove, metadata=state)
    assert not result.succeeded
    assert not result.executed_commands


@pytest.mark.parametrize("path", ["/", "//etc", "/etc/./", "/var/lib", "/tmp/../root", "/tmp/x;touch-pwn"])
def test_protected_and_traversal_paths_refuse(path: str) -> None:
    with pytest.raises(ValidationError):
        MetubeRemoveConfig(download_dir=path)


def test_host_package_query_distinguishes_config_files_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    path = Path(common.__file__).parent / "files/media_remove_host.py"
    spec = importlib.util.spec_from_file_location("media_host_test", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = SimpleNamespace(
        returncode=1,
        stdout="jellyfin\tconfig-files\n",
        stderr="\n".join(f"dpkg-query: no packages found matching {p}" for p in common.PACKAGES[1:]),
    )
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **kw: result)
    assert module.selected_packages() == ["jellyfin"]
    result.stderr = "dpkg-query: error: failed to open package status database"
    with pytest.raises(RuntimeError, match="Cannot establish"):
        module.selected_packages()


@pytest.mark.parametrize(("model", "deploy"), SERVICES)
def test_selected_route_uses_existing_transaction_guard_before_deletion(model: Any, deploy: Any) -> None:
    from ops_deploy.helpers.traefik import route_guard_command

    cfg = model(confirm=True)
    result = run(cfg, deploy)
    assert result.succeeded, result.error
    commands = result.executed_commands
    assert commands.index(route_guard_command()) < commands.index("rm -rf -- " + cfg.traefik_config_path)
    cfg = model(confirm=True, remove_traefik_config=False)
    kept = run(cfg, deploy)
    assert kept.succeeded, kept.error
    assert route_guard_command() not in kept.executed_commands


@pytest.mark.parametrize(
    "path",
    [
        "/usr/sbin",
        "/usr/lib/systemd/system",
        "/usr/share",
        "/var/spool",
        "/etc/traefik/dynamic",
        "/mnt/cryptdata/media",
        "/mnt/cryptdata/media/video",
    ],
)
def test_named_system_media_and_route_parent_roots_refuse(path: str) -> None:
    with pytest.raises(ValidationError):
        MetubeRemoveConfig(download_dir=path)
