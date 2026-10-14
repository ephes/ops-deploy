from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import HeadlessModeConfig, deploy_headless_mode
from ops_deploy.testing import run_deploy_fake
from tests.fakehost import LINUX

SYSTEMD = {**LINUX, "cat /proc/1/comm": ["systemd"]}


def units(*states: tuple[str, str, str]) -> dict[str, Any]:
    """``UnitStates`` fact output: (LoadState, ActiveState, UnitFileState) per unit, in order."""

    lines: list[str] = []
    for load, active, file_state in states:
        lines += [f"LoadState={load}", f"ActiveState={active}", f"UnitFileState={file_state}", "---"]
    return {"for unit in": lines}


def test_switches_target_and_disables_and_stops_display_manager() -> None:
    cfg = HeadlessModeConfig(display_manager_service="gdm3", disable_services=("cups-browsed",))
    responses = {
        **SYSTEMD,
        "systemctl get-default": ["graphical.target"],
        **units(("loaded", "active", "enabled"), ("loaded", "inactive", "disabled")),
    }

    run = run_deploy_fake(deploy_headless_mode, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.executed_commands == [
        "systemctl set-default multi-user.target",
        "systemctl disable gdm3.service",
        "systemctl stop gdm3.service",
    ]
    assert "for unit in gdm3.service cups-browsed.service;" in "\n".join(run.fact_commands)


def test_converged_host_changes_nothing() -> None:
    cfg = HeadlessModeConfig(display_manager_service="gdm3")
    responses = {**SYSTEMD, "systemctl get-default": ["multi-user.target"], **units(("loaded", "inactive", "disabled"))}

    run = run_deploy_fake(deploy_headless_mode, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_apply_now_false_only_disables() -> None:
    cfg = HeadlessModeConfig(display_manager_service="gdm3", apply_now=False)
    responses = {**SYSTEMD, "systemctl get-default": ["multi-user.target"], **units(("loaded", "active", "enabled"))}

    run = run_deploy_fake(deploy_headless_mode, cfg, responses=responses)

    assert run.executed_commands == ["systemctl disable gdm3.service"]


def test_static_unit_is_only_stopped() -> None:
    cfg = HeadlessModeConfig(disable_services=("x.service",))
    responses = {**SYSTEMD, "systemctl get-default": ["multi-user.target"], **units(("loaded", "active", "static"))}

    run = run_deploy_fake(deploy_headless_mode, cfg, responses=responses)

    assert run.executed_commands == ["systemctl stop x.service"]


def test_unknown_unit_fails_before_any_change() -> None:
    cfg = HeadlessModeConfig(display_manager_service="nosuchdm")
    responses = {**SYSTEMD, "systemctl get-default": ["graphical.target"], **units(("not-found", "inactive", ""))}

    run = run_deploy_fake(deploy_headless_mode, cfg, responses=responses)

    assert "nosuchdm.service not found" in str(run.error)
    assert run.executed_commands == []


def test_refuses_non_systemd_host() -> None:
    run = run_deploy_fake(deploy_headless_mode, HeadlessModeConfig(), responses={**LINUX, "cat /proc/1/comm": ["init"]})

    assert "requires a systemd-managed host" in str(run.error)
    assert run.ops == []


@pytest.mark.parametrize(
    "overrides",
    [{"default_target": "multi-user"}, {"default_target": ""}, {"disable_services": ("",)}, {"apply_now": "maybe"}],
)
def test_rejects_invalid_config(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        HeadlessModeConfig(**overrides)
