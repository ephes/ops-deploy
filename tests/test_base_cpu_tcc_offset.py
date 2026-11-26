"""cpu_tcc_offset against the fake connector: first run, converged run, drift and refusals."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import CpuTccOffsetConfig, deploy_cpu_tcc_offset
from ops_deploy.base.cpu_tcc_offset import RULE_PATH, TRIGGER, render_rule, tcc_device, verify_command
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.fakehost import LINUX, directory, file

P = "CPU TCC offset | "
CFG = CpuTccOffsetConfig(offset=10)
# What macmini (i5-8500B, TjMax 100 °C) shows: intel_tcc_cooling's device, offset 0 of at most 63.
DEVICE = "/sys/class/thermal/cooling_device11"
PROBE_KEY = "for d in /sys/class/thermal/cooling_device*"


def host(
    *,
    devices: list[str] | None = None,
    installed: bool = True,
    current: int = 10,
    mode: str = "root:root 644 regular file",
) -> dict[str, Any]:
    responses: dict[str, Any] = {
        **LINUX,
        PROBE_KEY: [f"{DEVICE} {current} 63"] if devices is None else devices,
        **directory("/etc/udev/rules.d"),
    }
    if installed:
        responses |= file(RULE_PATH, render_rule(CFG))
        responses[f"cat {RULE_PATH} 2>/dev/null"] = render_rule(CFG).splitlines()
        responses[f"stat -c '%U:%G %a %F' {RULE_PATH}"] = [mode]
    return responses


def deploy(responses: dict[str, Any], cfg: CpuTccOffsetConfig = CFG, *, ok: bool = True) -> FakeRun:
    run = run_deploy_fake(deploy_cpu_tcc_offset, cfg, responses=responses)
    assert run.succeeded is ok, run.error
    return run


def test_rendered_rule() -> None:
    assert render_rule(CFG) == (
        "# Managed by ops-deploy base.cpu_tcc_offset; local changes are overwritten.\n"
        'ACTION=="add", SUBSYSTEM=="thermal", KERNEL=="cooling_device*", '
        'ATTR{type}=="TCC Offset", ATTR{cur_state}="10"\n'
    )


def test_trigger_reaches_only_the_tcc_device() -> None:
    assert TRIGGER == (
        "udevadm control --reload && udevadm trigger --action=add --subsystem-match=thermal "
        "--attr-match='type=TCC Offset' --settle"
    )


@pytest.mark.parametrize("offset", [0, 64, -1])
def test_offset_bounds(offset: int) -> None:
    with pytest.raises(ValidationError):
        CpuTccOffsetConfig(offset=offset)


def test_first_run_installs_the_rule_and_applies_it_through_udev() -> None:
    run = deploy(host(installed=False, current=0))

    assert run.upload(RULE_PATH).decode() == render_rule(CFG)
    assert run.mutating_changed_ops == [f"{P}Install {RULE_PATH}", f"{P}Apply the TCC offset through the udev rule"]
    assert TRIGGER in run.executed_commands
    assert verify_command(DEVICE, 10) in run.executed_commands
    # The deploy never writes cur_state itself: the value comes from the rule, as at boot.
    assert not any("> " in command and "cur_state" in command for command in run.executed_commands)


def test_converged_host_plans_no_change() -> None:
    run = deploy(host())

    assert run.ops == []
    assert TRIGGER not in run.executed_commands


def test_a_rule_with_other_permissions_is_rewritten_and_applied() -> None:
    run = deploy(host(mode="root:root 666 regular file"))

    assert f"{P}Apply the TCC offset through the udev rule" in run.mutating_changed_ops
    assert TRIGGER in run.executed_commands


def test_a_reset_offset_is_applied_again_without_a_rule_change() -> None:
    run = deploy(host(current=0))

    assert run.mutating_changed_ops == [f"{P}Apply the TCC offset through the udev rule"]
    assert verify_command(DEVICE, 10) in run.executed_commands


def test_a_changed_rule_is_applied_even_when_the_offset_already_matches() -> None:
    cfg = CpuTccOffsetConfig(offset=12)
    run = deploy(host(current=12), cfg)

    assert run.mutating_changed_ops == [f"{P}Install {RULE_PATH}", f"{P}Apply the TCC offset through the udev rule"]


@pytest.mark.parametrize(
    "devices",
    [[], [f"{DEVICE} 0 63", "/sys/class/thermal/cooling_device12 0 63"], [f"{DEVICE} 0"], [f"{DEVICE} x 63"]],
)
def test_a_host_without_one_readable_tcc_device_is_refused(devices: list[str]) -> None:
    run = deploy(host(devices=devices), ok=False)

    assert "TCC Offset" in str(run.error)
    assert RULE_PATH not in " ".join(run.executed_commands)


def test_an_offset_above_the_device_maximum_is_refused() -> None:
    run = deploy({**host(devices=[f"{DEVICE} 0 7"])}, ok=False)

    assert "above the device's maximum 7" in str(run.error)


def test_tcc_device_parses_the_probe_line() -> None:
    assert tcc_device(f"{DEVICE} 0 63\n") == (DEVICE, 0, 63)


def test_verify_command_fails_on_another_value() -> None:
    assert verify_command(DEVICE, 10) == (
        f'test "$(cat {DEVICE}/cur_state)" = 10 || '
        f'{{ echo "{DEVICE}: cur_state is $(cat {DEVICE}/cur_state), not 10" >&2; exit 1; }}'
    )
