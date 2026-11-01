"""Software-live convergence, the S12 retirement and the accepted collector gate over real operations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.software_live import SoftwareLiveConfig, deploy_software_live
from ops_deploy.services.software_live.common import PRODUCTION, RESOURCE, endpoint_json, nice_json, render
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

VALUE = "fixture-software-password"
SHA = "b5ea97633a77d3297ef93991d6db38475f37995fae654cea995e7050ae998305"
RELEASES = "/usr/local/lib/software-live/releases"
DROPINS = (
    "/etc/systemd/system/software-live-endpoint.service.d/impl.conf",
    "/etc/systemd/system/software-live-collector.service.d/impl.conf",
)
SECRETS = SecretValues(SecretRef("secrets/fixture.yml"), {"endpoint_password": VALUE})
PREFIX = "Deploy software live | "


def config(**changes: Any) -> SoftwareLiveConfig:
    return SoftwareLiveConfig.model_validate(
        {
            "secrets": "secrets/fixture.yml",
            "auth_user": "nyxmon",
            "policy": {"host": "fixture", "os": {}, "postgresql": {}, "traefik": {}},
            "rust_version": "0.1.1",
            "rust_sha256": {"ubuntu24.04": SHA},
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
        "cat -- /etc/os-release": ["ID=ubuntu", 'VERSION_ID="24.04"'],
        **fakehost.directory(RELEASES),
        **fakehost.directory(f"{RELEASES}/{cfg.rust_version}"),
        **fakehost.file(f"{RELEASES}/{cfg.rust_version}/.archive-sha256", f"{SHA}\n"),
        " --check": ["current"],
        **fakehost.stat(str(cfg.config_dir), group=cfg.group, mode="drwxr-x---"),
        **fakehost.stat(str(cfg.data_dir), group=cfg.group, mode="drwxr-x---"),
    }
    response.update(
        fakehost.file(
            str(cfg.install_dir / "nyxmon_checks.py"),
            RESOURCE.joinpath("files", "nyxmon_checks.py").read_text(),
            mode="-rwxr-xr-x",
        )
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


def pre_s12(cfg: SoftwareLiveConfig, responses: dict[Any, Any]) -> dict[Any, Any]:
    """A host as deploys left it before the Python retirement: Python base units,
    impl.conf drop-ins running the release, the Python program and its cache."""

    python = {
        "software-live-endpoint.service": render("endpoint.service.j2", cfg).replace(
            str(cfg.binary), "/usr/bin/python3 /usr/local/lib/software-live/software_live.py"
        ),
        "software-live-collector.service": render("collector.service.j2", cfg).replace(
            str(cfg.binary), "/usr/bin/python3 /usr/local/lib/software-live/software_live.py"
        ),
    }
    # First: the fake connector answers with the first key a command contains,
    # and ``cat <unit>`` is contained in ``cat <unit>.d/impl.conf``.
    first: dict[Any, Any] = {}
    for path in DROPINS:
        first.update(fakehost.file(path, f"[Service]\nExecStart=\nExecStart={cfg.binary} ...\n"))
    for name, text in python.items():
        responses.update(fakehost.file(str(cfg.systemd_dir / name), text))
    responses.update(fakehost.file(str(cfg.install_dir / "software_live.py"), "# retired\n", mode="-rwxr-xr-x"))
    responses.update(fakehost.directory(str(cfg.install_dir / "__pycache__")))
    return {**first, **responses}


def test_s12_upgrade_retires_python_and_the_dropins_with_one_restart() -> None:
    cfg = config()
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=pre_s12(cfg, converged(cfg)))
    assert result.succeeded, result.error
    commands = result.executed_commands
    assert changed(result) == [
        "Remove retired drop-in " + DROPINS[0],
        "Remove empty /etc/systemd/system/software-live-endpoint.service.d",
        "Remove retired drop-in " + DROPINS[1],
        "Remove empty /etc/systemd/system/software-live-collector.service.d",
        "Install software-live-collector.service",
        "Install software-live-endpoint.service",
        "Reload software-live production units",
        "Restart software-live-endpoint.service",
        "Restart software-live-collector.timer",
        "Collect a changed or stale software observation",
        "Remove the retired Python software observation program",
        "Remove the retired Python bytecode cache",
    ]
    assert commands.count("systemctl restart software-live-endpoint.service") == 1
    assert commands.count("systemctl daemon-reload") == 1
    for path in DROPINS:
        assert f"rm -f {path}" in commands
    # Only empty directories go: rmdir refuses a directory holding another drop-in.
    assert any(c.startswith("rmdir -- /etc/systemd/system/software-live-endpoint.service.d") for c in commands)
    assert not any(c.startswith("rm -rf /etc/systemd/system/software-live-") for c in commands)
    for name in ("software-live-endpoint.service", "software-live-collector.service"):
        text = result.upload(str(cfg.systemd_dir / name)).decode()
        assert f"ExecStart={cfg.binary} " in text
        assert "software_live.py" not in text
    verify = next(i for i, c in enumerate(commands) if "--proc-root" in c)
    removal = commands.index("rm -f /usr/local/lib/software-live/software_live.py")
    assert commands.index("rm -f " + DROPINS[0]) < commands.index("systemctl daemon-reload") < verify < removal
    names = [op.name.removeprefix(PREFIX) for op in result.ops]
    assert (
        names.index("Verify software-live running implementation")
        < names.index("Remove the retired Python software observation program")
        < names.index("Pin software-live for software-live")
    )
    assert any("rm -rf /usr/local/lib/software-live/__pycache__" in c for c in commands)
    assert not any("software_live.py validate" in c for c in commands)
    assert not any("/usr/local/lib/software-live/software_live.py" in path for path, _ in result.uploads)


def test_failed_verification_keeps_the_python_program() -> None:
    cfg = config()
    responses = pre_s12(cfg, converged(cfg))
    responses["--proc-root"] = {"success": False}
    result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=responses)
    assert not result.succeeded
    commands = result.executed_commands
    assert "rm -f /usr/local/lib/software-live/software_live.py" not in commands
    assert not any(" pin " in cmd or " prune " in cmd for cmd in commands)


def test_python_is_refused_before_any_operation() -> None:
    with pytest.raises(ConfigValidationError, match="retired in S12"):
        config(impl="python")
    with pytest.raises(ConfigValidationError, match="rust_version is required"):
        config(rust_version="")
    assert config().impl == "rust"
    assert "python3-apt" not in config().packages


def test_invalid_release_fails_before_any_managed_operations() -> None:
    for changes in ({"rust_version": "invalid"}, {"rust_shadow": True, "rust_version": "invalid"}):
        cfg = config(**changes)
        result = run_deploy_fake(deploy_software_live, cfg, SECRETS, responses=converged(cfg))
        assert not result.succeeded
        assert result.ops == []


def test_missing_local_archive_fails_before_any_managed_operations(tmp_path: Path) -> None:
    cfg = config(rust_local_archive=tmp_path / "missing.tar.gz")
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
