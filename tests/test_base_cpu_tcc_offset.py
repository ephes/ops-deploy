"""cpu_tcc_offset against the fake connector: first run, converged run, drift and refusals."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import CpuTccOffsetConfig, deploy_cpu_tcc_offset
from ops_deploy.base.cpu_tcc_offset import APPLY, KIND, RULE_PATH, STATE, render_rule, verify_command
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.fakehost import LINUX, directory, file

P = "CPU TCC offset | "
CFG = CpuTccOffsetConfig(offset=10)


def host(
    *, rule: str | None = None, mode: str = "-rw-r--r--", state: str | None = "0", applied: str = "10"
) -> dict[str, Any]:
    """``state`` is the TCC Offset device's ``cur_state``; ``None``: the host has no such device.

    ``applied`` is what the device holds after the apply (what the read-back sees).
    """

    responses: dict[str, Any] = {**LINUX, **directory("/etc/udev/rules.d")}
    responses[verify_command(CFG)] = {"success": applied == str(CFG.offset)}
    responses[f"{STATE} 2>/dev/null || true"] = [] if state is None else [state]
    responses[KIND] = ["missing" if rule is None else "regular file"]
    if rule is not None:
        responses |= file(RULE_PATH, rule, mode=mode)
    return responses


def deploy(responses: dict[str, Any]) -> FakeRun:
    run = run_deploy_fake(deploy_cpu_tcc_offset, CFG, responses=responses)
    assert run.succeeded, run.error
    return run


def test_rendered_rule() -> None:
    assert render_rule(CFG) == (
        "# Managed by ops-deploy base.cpu_tcc_offset; local changes are overwritten.\n"
        'ACTION=="add", SUBSYSTEM=="thermal", KERNEL=="cooling_device*", '
        'ATTR{type}=="TCC Offset", ATTR{cur_state}="10"\n'
    )


def test_apply_replays_only_the_tcc_device() -> None:
    assert APPLY == (
        "udevadm control --reload && udevadm trigger --action=add --subsystem-match=thermal "
        "--attr-match='type=TCC Offset' --settle"
    )


def test_first_run_installs_the_rule_and_applies_it() -> None:
    run = deploy(host())
    assert run.upload(RULE_PATH).decode() == render_rule(CFG)
    assert run.mutating_changed_ops == [f"{P}Install {RULE_PATH}", f"{P}Apply the TCC offset through the udev rule"]
    assert APPLY in run.executed_commands


def test_apply_reads_the_offset_back() -> None:
    assert verify_command(CFG) == (
        f'test "$({STATE})" = 10 || '
        '{ echo "cpu_tcc_offset: TCC Offset cur_state is not 10 after the apply" >&2; exit 1; }'
    )
    run = deploy(host())
    assert run.executed_commands.index(verify_command(CFG)) > run.executed_commands.index(APPLY)


@pytest.mark.parametrize("applied", ["0", "5", ""])
def test_offset_not_taken_after_the_apply_fails_the_deploy(applied: str) -> None:
    """udev ignores a failed ``ATTR{cur_state}`` write; the read-back turns it into a failed deploy."""

    run = run_deploy_fake(deploy_cpu_tcc_offset, CFG, responses=host(rule=render_rule(CFG), applied=applied))
    assert not run.succeeded
    assert APPLY in run.executed_commands


def test_host_without_the_device_only_writes_the_rule() -> None:
    run = deploy(host(state=None))
    assert run.upload(RULE_PATH).decode() == render_rule(CFG)
    assert run.mutating_changed_ops == [f"{P}Install {RULE_PATH}"]
    assert APPLY not in run.executed_commands


def test_converged_host_without_the_device_plans_no_change() -> None:
    run = deploy(host(rule=render_rule(CFG), state=None))
    assert run.planned_changes == []
    assert run.executed_commands == []


@pytest.mark.parametrize("kind", ["symbolic link", "directory", "fifo", ""])
def test_non_regular_rule_path_is_refused_before_any_change(kind: str) -> None:
    """A symlink at the rule path (e.g. to /dev/null) is never written through."""

    run = run_deploy_fake(deploy_cpu_tcc_offset, CFG, responses={**host(), KIND: [kind]})
    assert not run.succeeded
    assert f"{RULE_PATH} is a " in str(run.error)
    assert run.uploads == []
    assert run.executed_commands == []


def test_device_at_the_offset_plans_no_change() -> None:
    run = deploy(host(rule=render_rule(CFG), state="10"))
    assert run.planned_changes == []
    assert run.executed_commands == []


@pytest.mark.parametrize("state", ["0", "5"])
def test_device_with_another_offset_is_applied_again(state: str) -> None:
    """A failed apply of an earlier run (the rule is in place, the device is not) is retried."""

    run = deploy(host(rule=render_rule(CFG), state=state))
    assert run.uploads == []
    assert run.mutating_changed_ops == [f"{P}Apply the TCC offset through the udev rule"]
    assert APPLY in run.executed_commands


def test_state_reads_only_the_tcc_device() -> None:
    assert STATE == (
        "for d in /sys/class/thermal/cooling_device*; do grep -qx 'TCC Offset' $d/type && cat $d/cur_state; done"
    )


def test_changed_rule_is_rewritten_and_applied() -> None:
    run = deploy(host(rule=render_rule(CpuTccOffsetConfig(offset=5))))
    assert run.upload(RULE_PATH).decode() == render_rule(CFG)
    assert APPLY in run.executed_commands


def test_wrong_mode_is_corrected() -> None:
    run = deploy(host(rule=render_rule(CFG), mode="-rw-rw-rw-", state="10"))
    assert run.uploads == []
    assert f"chmod 644 {RULE_PATH}" in run.executed_commands


@pytest.mark.parametrize("offset", [0, 64, -1])
def test_offset_out_of_range_is_refused(offset: int) -> None:
    with pytest.raises(ValidationError):
        CpuTccOffsetConfig(offset=offset)


def test_non_linux_host_is_refused() -> None:
    run = run_deploy_fake(deploy_cpu_tcc_offset, CFG, responses={**host(), "uname -s": ["Darwin"]})
    assert not run.succeeded
    assert "Linux hosts only" in str(run.error)
