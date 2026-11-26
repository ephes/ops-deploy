"""cpu_tcc_offset against the fake connector: first run, converged run, drift and refusals."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import CpuTccOffsetConfig, deploy_cpu_tcc_offset
from ops_deploy.base.cpu_tcc_offset import APPLY, RULE_PATH, render_rule
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.fakehost import LINUX, directory, file

P = "CPU TCC offset | "
CFG = CpuTccOffsetConfig(offset=10)


def host(*, rule: str | None = None, mode: str = "-rw-r--r--") -> dict[str, Any]:
    responses: dict[str, Any] = {**LINUX, **directory("/etc/udev/rules.d")}
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


def test_converged_host_plans_no_change() -> None:
    run = deploy(host(rule=render_rule(CFG)))
    assert run.planned_changes == []
    assert run.executed_commands == []


def test_changed_rule_is_rewritten_and_applied() -> None:
    run = deploy(host(rule=render_rule(CpuTccOffsetConfig(offset=5))))
    assert run.upload(RULE_PATH).decode() == render_rule(CFG)
    assert APPLY in run.executed_commands


def test_wrong_mode_is_corrected() -> None:
    run = deploy(host(rule=render_rule(CFG), mode="-rw-rw-rw-"))
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
