"""OTBR safety boundaries and convergence."""

import json
import os
from pathlib import Path
from typing import Any

import pytest
from jinja2 import Environment
from pydantic import ValidationError

from ops_deploy.infra.otbr import SOURCE_GUARD, OtbrConfig, build_environment, deploy_otbr, render_defaults, render_udev
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

CFG = OtbrConfig(
    repo_version="b" * 40,
    rcp_device="/dev/serial/by-id/usb-fixture",
    infra_interface="eth0",
    build_window_approved=True,
)


def converged() -> dict[str, Any]:
    desired = json.dumps({"commit": CFG.repo_version, "environment": build_environment(CFG)}, sort_keys=True) + "\n"
    return {
        **fakehost.LINUX,
        "cat /proc/1/comm": ["systemd"],
        SOURCE_GUARD: ["safe"],
        "command -v ss": ["checked"],
        "systemctl show --property=LoadState": ["not-found", "not-found", "not-found"],
        "test -c /dev/serial/by-id/usb-fixture": ["device"],
        "test -d /sys/class/net/eth0": ["interface"],
        "cat /opt/ot-br-posix/.ops-deploy-build-config": [desired.strip()],
        "git -C /opt/ot-br-posix rev-parse HEAD": [CFG.repo_version],
        "cat /opt/ot-br-posix/.ops-deploy-bootstrap-config": [desired.strip()],
        "test -x /usr/sbin/otbr-agent": ["binary"],
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed("ca-certificates", "curl", "git", "lsb-release", "sudo"),
        **fakehost.directory("/etc/default"),
        **fakehost.directory("/opt/ot-br-posix"),
        **fakehost.file("/opt/ot-br-posix/.ops-deploy-build-config", desired),
        **fakehost.file("/opt/ot-br-posix/.ops-deploy-bootstrap-config", desired),
        **fakehost.file("/opt/ot-br-posix/.ops-deploy-agent-defaults", render_defaults(CFG)),
        **fakehost.directory("/etc/udev/rules.d"),
        **fakehost.file("/etc/default/otbr-agent", render_defaults(CFG)),
        **fakehost.file("/etc/udev/rules.d/99-otbr-zbt2.rules", render_udev()),
        **fakehost.service("otbr-agent.service"),
    }


def test_converged_has_no_mutations() -> None:
    result = run_deploy_fake(deploy_otbr, CFG, responses=converged())
    assert result.succeeded, result.error
    assert not result.mutating_changed_ops


@pytest.mark.parametrize(
    "response",
    [
        {SOURCE_GUARD: ["unsafe"]},
        {"command -v ss": ["listener", "checked"]},
        {"dpkg-query -W": ["installed"]},
        {"test -c /dev/serial/by-id/usb-fixture": []},
        {"test -d /sys/class/net/eth0": []},
        {"systemctl show --property=LoadState": ["loaded", "not-found", "not-found"]},
        {"systemctl show --property=LoadState": []},
    ],
)
def test_guard_failures_precede_every_write(response: dict[str, Any]) -> None:
    responses = converged()
    responses.update(response)
    result = run_deploy_fake(deploy_otbr, CFG, responses=responses)
    assert not result.succeeded
    assert not result.executed_commands
    assert not result.uploaded_paths


def test_device_window_is_required() -> None:
    result = run_deploy_fake(
        deploy_otbr, CFG.model_copy(update={"build_window_approved": False}), responses=converged()
    )
    assert not result.succeeded
    assert not result.executed_commands


def test_changed_commit_builds_then_records_success() -> None:
    responses = converged()
    responses["git -C /opt/ot-br-posix rev-parse HEAD"] = ["a" * 40]
    result = run_deploy_fake(deploy_otbr, CFG, responses=responses)
    assert result.succeeded, result.error
    text = result.all_text()
    assert text.index("script/bootstrap") < text.index("script/setup")
    assert "git checkout --detach " + CFG.repo_version in text
    assert "ot-ctl" not in text


@pytest.mark.parametrize(
    "change",
    [
        {"repo_version": "main"},
        {"rcp_device": "/dev/ttyUSB0"},
        {"install_dir": "/tmp/otbr"},
        {"rest_listen_address": "0.0.0.0"},
        {"build_options": "evil"},
    ],
)
def test_unsafe_or_unsupported_inputs_are_refused(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        OtbrConfig.model_validate({**CFG.model_dump(), **change})


def test_fresh_role_render_parity() -> None:
    source = os.environ.get("OTBR_PARITY_LIBRARY_PATH")
    if source is None:
        pytest.skip("fresh library parity is a separate targeted check")
    role = Path(source) / "roles/otbr_deploy/templates"
    env = Environment(keep_trailing_newline=True, trim_blocks=True)
    env.filters["ternary"] = lambda value, yes, no: yes if value else no
    variables = {"otbr_" + key: value for key, value in CFG.model_dump().items()}
    variables.update(
        otbr_backbone_interface=CFG.infra_interface,
        otbr_agent_extra_opts="",
        otbr_udev_pids=["4001", "831a"],
        otbr_udev_vid="303a",
        otbr_udev_group="dialout",
        otbr_udev_mode="0660",
    )
    assert env.from_string((role / "otbr-agent.defaults.j2").read_text()).render(variables) == render_defaults(CFG)
    assert env.from_string((role / "99-otbr-zbt2.rules.j2").read_text()).render(variables) == render_udev()


def test_failed_build_never_records_success() -> None:
    responses = converged()
    responses["git -C /opt/ot-br-posix rev-parse HEAD"] = ["a" * 40]
    responses["./script/setup"] = {"success": False, "stderr": "build failed"}
    result = run_deploy_fake(deploy_otbr, CFG, responses=responses)
    assert not result.succeeded
    assert "/opt/ot-br-posix/.ops-deploy-build-config" not in result.uploaded_paths
    assert not any("systemctl restart" in command for command in result.executed_commands)


def test_applied_marker_keeps_failed_configuration_restart_pending() -> None:
    cfg = CFG.model_copy(update={"no_auto_attach": True})
    responses = converged()
    # A previous attempt wrote defaults, but failed before recording application.
    responses.update(fakehost.file("/etc/default/otbr-agent", render_defaults(cfg)))
    result = run_deploy_fake(deploy_otbr, cfg, responses=responses)
    assert result.succeeded, result.error
    assert "systemctl restart otbr-agent.service" in result.executed_commands
    assert not any("script/setup" in command for command in result.executed_commands)


def test_source_guard_is_valid_bash() -> None:
    import subprocess

    result = subprocess.run(["bash", "-n"], input=SOURCE_GUARD, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("field", ["remove_bind", "manage_packages"])
def test_unsupported_bootstrap_variants_fail_before_planning(field: str) -> None:
    with pytest.raises(ValidationError):
        OtbrConfig.model_validate({**CFG.model_dump(), field: False})


def test_failed_bootstrap_retries_for_the_current_commit() -> None:
    responses = converged()
    responses["cat /opt/ot-br-posix/.ops-deploy-bootstrap-config"] = ["old revision"]
    responses["./script/bootstrap"] = {"success": False}
    failed = run_deploy_fake(deploy_otbr, CFG, responses=responses)
    assert not failed.succeeded
    assert "/opt/ot-br-posix/.ops-deploy-bootstrap-config" not in failed.uploaded_paths
    del responses["./script/bootstrap"]
    retry = run_deploy_fake(deploy_otbr, CFG, responses=responses)
    assert retry.succeeded, retry.error
    assert any("script/bootstrap" in command for command in retry.executed_commands)
    assert any("script/setup" in command for command in retry.executed_commands)


def test_rebuild_repairs_uninitialized_submodules_before_scripts() -> None:
    responses = converged()
    cfg = CFG.model_copy(update={"force_rebuild": True})
    result = run_deploy_fake(deploy_otbr, cfg, responses=responses)
    assert result.succeeded, result.error
    commands = result.executed_commands
    update = next(i for i, command in enumerate(commands) if "git submodule update" in command)
    setup = next(i for i, command in enumerate(commands) if "./script/setup" in command)
    cleanup = next(i for i, command in enumerate(commands) if "apt-get -y purge bind9" in command)
    assert update < setup < cleanup


def test_failed_build_with_leftover_bind_refuses_recovery_before_writes() -> None:
    responses = converged()
    responses["dpkg-query -W"] = ["installed"]
    result = run_deploy_fake(deploy_otbr, CFG, responses=responses)
    assert not result.succeeded
    assert not result.executed_commands
    assert not result.uploaded_paths


def test_first_clone_is_staged_and_published_only_after_checkout() -> None:
    import subprocess

    responses = converged()
    responses[SOURCE_GUARD] = ["absent"]
    responses["git -C /opt/ot-br-posix rev-parse HEAD"] = []
    result = run_deploy_fake(deploy_otbr, CFG, responses=responses)
    assert result.succeeded, result.error
    checkout = next(command for command in result.executed_commands if "mktemp -d /opt/.otbr-source" in command)
    assert checkout.index("git checkout --detach") < checkout.index("mv -T")
    assert 'git clone --no-checkout https://github.com/openthread/ot-br-posix.git "$stage"' in checkout
    assert subprocess.run(["bash", "-n"], input=checkout, text=True, check=False).returncode == 0


@pytest.mark.parametrize(
    ("flag", "script", "bootstrap_expected"),
    [("force_rebuild", "./script/setup", False), ("force_bootstrap", "./script/bootstrap", True)],
)
def test_failed_forced_attempt_invalidates_persisted_proofs_for_normal_retry(
    flag: str, script: str, bootstrap_expected: bool
) -> None:
    responses = converged()
    responses[script] = {"success": False}
    first = run_deploy_fake(deploy_otbr, CFG.model_copy(update={flag: True}), responses=responses)
    assert not first.succeeded
    # Carry actual marker removals from the failed caller into the next host
    # snapshot. Keeping an old proof here reproduces the original false no-op.
    persisted = converged()
    markers = ["/opt/ot-br-posix/.ops-deploy-build-config", "/opt/ot-br-posix/.ops-deploy-bootstrap-config"]
    for marker in markers:
        removed = any(command.startswith("rm ") and marker in command for command in first.executed_commands)
        if removed:
            persisted = {key: value for key, value in persisted.items() if marker not in key}
    retry = run_deploy_fake(deploy_otbr, CFG, responses=persisted)
    assert retry.succeeded, retry.error
    assert any("./script/setup" in command for command in retry.executed_commands)
    assert any("./script/bootstrap" in command for command in retry.executed_commands) is bootstrap_expected
