"""Software-live convergence and the accepted collector gate over real operations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.software_live import SoftwareLiveConfig, deploy_software_live
from ops_deploy.services.software_live.common import PRODUCTION, RESOURCE, endpoint_json, nice_json, render
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

VALUE = "fixture-software-password"
SECRETS = SecretValues(SecretRef("secrets/fixture.yml"), {"endpoint_password": VALUE})
PREFIX = "Deploy software live | "


def config(**changes: Any) -> SoftwareLiveConfig:
    return SoftwareLiveConfig.model_validate(
        {
            "secrets": "secrets/fixture.yml",
            "auth_user": "nyxmon",
            "policy": {"host": "fixture", "os": {}, "postgresql": {}, "traefik": {}},
            **changes,
        }
    )


def converged(cfg: SoftwareLiveConfig) -> dict[Any, Any]:
    response = {
        **fakehost.UBUNTU,
        "tailscale ip --4": ["100.64.0.7"],
        **fakehost.accounts({"metrics": "/home/metrics"}),
        **fakehost.deb_installed(*cfg.packages),
        "/usr/bin/python3 -I - /var/lib/software-live/state.json": [json.dumps({"exists": True, "fresh": True})],
        '"root": "/usr/local/lib/software-live/releases"': [
            json.dumps({"versions": [], "unknown": [], "last_live": "", "shadow_pin": ""})
        ],
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory(str(cfg.install_dir)),
        **fakehost.stat(str(cfg.config_dir), group=cfg.group, mode="drwxr-x---"),
        **fakehost.stat(str(cfg.data_dir), group=cfg.group, mode="drwxr-x---"),
    }
    for name in ("software_live.py", "nyxmon_checks.py"):
        response.update(
            fakehost.file(str(cfg.install_dir / name), RESOURCE.joinpath("files", name).read_text(), mode="-rwxr-xr-x")
        )
    for name, content in [
        ("policy.json", nice_json(cfg.policy)),
        ("endpoint.json", endpoint_json(cfg, "100.64.0.7")),
        ("htpasswd", f"nyxmon:{hash_password(VALUE)}\n"),
    ]:
        path = str(cfg.config_dir / name)
        response.update(fakehost.file(path, content))
        response.update(fakehost.stat(path, group=cfg.group, mode="-rw-r-----"))
    for name, template in zip(
        PRODUCTION, ("collector.service.j2", "collector.timer.j2", "endpoint.service.j2"), strict=True
    ):
        response.update(fakehost.file(str(cfg.systemd_dir / name), render(template, cfg)))
    for name in ("software-live-endpoint.service", "software-live-collector.timer"):
        response.update(fakehost.service(name))
    return response


def changed(run: FakeRun) -> list[str]:
    return [name.removeprefix(PREFIX) for name in run.mutating_changed_ops]


def test_fresh_converged_state_has_no_collection_restart_or_managed_change() -> None:
    cfg = config()
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=converged(cfg))
    assert result.succeeded, result.error
    assert changed(result) == []
    assert not any("systemctl start software-live-collector.service" in cmd for cmd in result.executed_commands)


def test_stale_state_collects_without_restarting_or_rewriting_configuration() -> None:
    cfg = config()
    responses = converged(cfg)
    responses["/usr/bin/python3 -I - /var/lib/software-live/state.json"] = [
        json.dumps({"exists": True, "fresh": False})
    ]
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=responses)
    assert result.succeeded, result.error
    assert changed(result) == ["Collect a changed or stale software observation"]


def test_policy_change_collects_but_does_not_restart_endpoint() -> None:
    cfg = config()
    responses = converged(cfg)
    responses.update(fakehost.file("/etc/software-live/policy.json", "old"))
    responses.update(fakehost.stat("/etc/software-live/policy.json", group="metrics", mode="-rw-r-----"))
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=responses)
    assert result.succeeded, result.error
    assert changed(result) == [
        "Write /etc/software-live/policy.json",
        "Collect a changed or stale software observation",
    ]


def test_unknown_state_inspection_does_not_queue_collection_or_manage_resources() -> None:
    cfg = config()
    responses = converged(cfg)
    responses["/usr/bin/python3 -I - /var/lib/software-live/state.json"] = ["ops-deploy-probe-failed"]
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=responses)
    assert not result.succeeded
    assert not result.ops


def with_rust_dropins(cfg: SoftwareLiveConfig, responses: dict[Any, Any]) -> dict[Any, Any]:
    from ops_deploy.services.software_live.switch import paths

    for path in paths(cfg)["dropins"]:
        responses.update(fakehost.file(path, "old Rust implementation"))
    return responses


def test_invalid_shadow_release_fails_after_python_rollback() -> None:
    cfg = config(rust_shadow=True, rust_version="invalid")
    responses = with_rust_dropins(cfg, converged(cfg))
    responses["Invalid software-live shadow release inputs"] = {"success": False}
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=responses)
    assert not result.succeeded
    commands = result.executed_commands
    rejected = next(i for i, cmd in enumerate(commands) if "Invalid software-live shadow" in cmd)
    assert any("daemon-reload" in cmd for cmd in commands[:rejected])
    assert any("restart software-live-endpoint.service" in cmd for cmd in commands[:rejected])
    assert sum("rm -f" in cmd and "impl.conf" in cmd for cmd in commands[:rejected]) == 2
    assert not any(" pin " in cmd or " prune " in cmd for cmd in commands)


def test_unreadable_shadow_archive_fails_after_python_rollback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = tmp_path / "candidate.tar.gz"
    archive.write_bytes(b"owned archive fixture")
    original = Path.read_bytes

    def denied(path: Path) -> bytes:
        if path == archive:
            raise PermissionError("owned injected archive read failure")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", denied)
    cfg = config(rust_shadow=True, rust_version="0.1.1", rust_local_archive=archive)
    responses = with_rust_dropins(cfg, converged(cfg))
    responses["cat -- /etc/os-release"] = ["ID=ubuntu", 'VERSION_ID="24.04"']
    responses["Software-live controller archive unreadable"] = {"success": False}
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=responses)
    assert not result.succeeded
    commands = result.executed_commands
    rejected = next(i for i, cmd in enumerate(commands) if "controller archive unreadable" in cmd)
    assert any("restart software-live-endpoint.service" in cmd for cmd in commands[:rejected])
    assert sum("rm -f" in cmd and "impl.conf" in cmd for cmd in commands[:rejected]) == 2
    assert not any(" pin " in cmd or " prune " in cmd for cmd in commands)


def test_invalid_selected_rust_fails_before_any_managed_operations() -> None:
    cfg = config(impl="rust", rust_version="invalid")
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=converged(cfg))
    assert not result.succeeded
    assert result.ops == []


def test_verify_process_root_is_forwarded_to_actual_driver() -> None:
    cfg = config(proc_root="/tmp/fixture-proc")
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=converged(cfg))
    assert result.succeeded
    assert any("--proc-root /tmp/fixture-proc" in cmd for cmd in result.executed_commands)


def test_removal_keeps_production_data_by_default_and_is_repeatable() -> None:
    from ops_deploy.services.software_live import SoftwareLiveRemoveConfig, remove_software_live

    cfg = SoftwareLiveRemoveConfig()
    responses = {
        **fakehost.UBUNTU,
        **fakehost.directory(str(cfg.config_dir)),
        **fakehost.directory(str(cfg.install_dir)),
        **fakehost.directory(str(cfg.data_dir)),
        **fakehost.directory(str(cfg.data_dir / "shadow")),
    }
    result = run_deploy_fake(remove_software_live, cfg, responses=responses)
    assert result.succeeded
    commands = result.executed_commands
    assert any("rm -rf /var/lib/software-live/shadow" in cmd for cmd in commands)
    assert not any(cmd.endswith("rm -rf /var/lib/software-live") for cmd in commands)
    repeat = run_deploy_fake(remove_software_live, cfg, responses=fakehost.UBUNTU)
    assert repeat.succeeded
    assert repeat.mutating_changed_ops == []
    assert not any("daemon-reload" in cmd for cmd in repeat.executed_commands)


def test_explicit_removal_also_removes_production_data() -> None:
    from ops_deploy.services.software_live import SoftwareLiveRemoveConfig, remove_software_live

    cfg = SoftwareLiveRemoveConfig(remove_data=True)
    result = run_deploy_fake(
        remove_software_live, cfg, responses={**fakehost.UBUNTU, **fakehost.directory(str(cfg.data_dir))}
    )
    assert result.succeeded
    assert any("Remove software observation state" in op for op in result.mutating_changed_ops)
