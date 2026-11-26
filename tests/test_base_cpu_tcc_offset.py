"""cpu_tcc_offset against the fake connector: first run, converged run, drift and refusals."""

from __future__ import annotations

import hashlib
import subprocess
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import CpuTccOffsetConfig, deploy_cpu_tcc_offset
from ops_deploy.base.cpu_tcc_offset import (
    APPLY,
    DIGEST,
    KIND,
    RULE_PATH,
    STATE,
    render_rule,
    verify_command,
    write_command,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.fakehost import LINUX

P = "CPU TCC offset | "
CFG = CpuTccOffsetConfig(offset=10)


def host(
    *, rule: str | None = None, kind: str = "regular file 644 root:root", state: str = "0", applied: str = "10"
) -> dict[str, Any]:
    """``state`` is what the device read prints (``absent``: the host has no TCC Offset device).

    ``applied`` is what the device holds after the apply (what the read-back sees).
    """

    responses: dict[str, Any] = dict(LINUX)
    responses[verify_command(CFG)] = {"success": applied == str(CFG.offset)}
    responses[f"{STATE} 2>/dev/null || true"] = [state] if state else []
    responses[f"{KIND} 2>/dev/null || true"] = ["missing" if rule is None else kind]
    if rule is not None:
        responses[f"{DIGEST} 2>/dev/null || true"] = [f"{hashlib.sha256(rule.encode()).hexdigest()}  {RULE_PATH}"]
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
    assert run.mutating_changed_ops == [f"{P}Install {RULE_PATH}", f"{P}Apply the TCC offset through the udev rule"]
    commands = run.executed_commands
    assert commands.index(write_command(CFG)) < commands.index(APPLY) < commands.index(verify_command(CFG))
    assert run.uploads == []


def test_write_renames_a_temp_file_over_the_rule_path() -> None:
    """The rename replaces a symlink at the rule path; nothing is written through it."""

    command = write_command(CFG)
    assert command.startswith("tmp=$(mktemp /etc/udev/rules.d/.60-cpu-tcc-offset.rules.XXXXXX) && ")
    assert f'mv -fT "$tmp" {RULE_PATH}' in command
    assert '>"$tmp"' in command
    assert f"> {RULE_PATH}" not in command
    assert f">{RULE_PATH}" not in command


def test_write_replaces_a_symlink_instead_of_following_it(tmp_path: Any) -> None:
    """Runs the write in a scratch directory: a symlink at the path is replaced, its target untouched."""

    target = tmp_path / "target"
    target.write_text("untouched\n")
    rules = tmp_path / "rules.d"
    rules.mkdir()
    (rules / "60-cpu-tcc-offset.rules").symlink_to(target)
    command = (
        write_command(CFG)
        .replace("/etc/udev/rules.d", str(rules))
        .replace('chown root:root "$tmp" && ', "")
        .replace("mv -fT", "mv -f")  # BSD mv on the test host; rename(2) semantics are the same for a symlink
    )
    subprocess.run(["sh", "-c", command], check=True, timeout=30)
    rule = rules / "60-cpu-tcc-offset.rules"
    assert not rule.is_symlink()
    assert rule.read_text() == render_rule(CFG)
    assert target.read_text() == "untouched\n"
    assert sorted(p.name for p in rules.iterdir()) == ["60-cpu-tcc-offset.rules"]


def test_apply_reads_the_offset_back() -> None:
    assert verify_command(CFG) == (
        f'test "$({STATE})" = 10 || '
        '{ echo "cpu_tcc_offset: TCC Offset cur_state is not 10 after the apply" >&2; exit 1; }'
    )


@pytest.mark.parametrize("applied", ["0", "5", ""])
def test_offset_not_taken_after_the_apply_fails_the_deploy(applied: str) -> None:
    """udev ignores a failed ``ATTR{cur_state}`` write; the read-back turns it into a failed deploy."""

    run = run_deploy_fake(deploy_cpu_tcc_offset, CFG, responses=host(rule=render_rule(CFG), applied=applied))
    assert not run.succeeded
    assert APPLY in run.executed_commands


@pytest.mark.parametrize("state", ["", "unreadable", "10\nunreadable", "10\n5", "garbage"])
def test_unreadable_device_state_fails_before_any_change(state: str) -> None:
    """Only ``absent`` means no device; a failed read never passes as one."""

    run = run_deploy_fake(deploy_cpu_tcc_offset, CFG, responses=host(state=state))
    assert not run.succeeded
    assert "cannot read the TCC Offset cur_state" in str(run.error)
    assert run.executed_commands == []


def test_state_prints_absent_unreadable_or_the_value() -> None:
    assert STATE == (
        "{ found=; for d in /sys/class/thermal/cooling_device*; do "
        "grep -qx 'TCC Offset' \"$d/type\" || continue; found=1; "
        'cat "$d/cur_state" || echo unreadable; done; [ -n "$found" ] || echo absent; }'
    )


@pytest.mark.parametrize(
    ("devices", "expected"),
    [
        ({}, "absent"),
        ({"0": ("Processor", "3")}, "absent"),
        ({"1": ("TCC Offset", "10")}, "10"),
        ({"1": ("TCC Offset", None)}, "unreadable"),
    ],
)
def test_state_script(tmp_path: Any, devices: dict[str, tuple[str, str | None]], expected: str) -> None:
    for n, (kind, value) in devices.items():
        d = tmp_path / f"cooling_device{n}"
        d.mkdir()
        (d / "type").write_text(kind + "\n")
        if value is not None:
            (d / "cur_state").write_text(value + "\n")
    script = STATE.replace("/sys/class/thermal", str(tmp_path))
    result = subprocess.run(["sh", "-c", f"{script} 2>/dev/null || true"], capture_output=True, text=True, timeout=30)
    assert result.stdout.strip() == expected


def test_host_without_the_device_only_writes_the_rule() -> None:
    run = deploy(host(state="absent"))
    assert run.mutating_changed_ops == [f"{P}Install {RULE_PATH}"]
    assert APPLY not in run.executed_commands


def test_converged_host_without_the_device_plans_no_change() -> None:
    run = deploy(host(rule=render_rule(CFG), state="absent"))
    assert run.planned_changes == []
    assert run.executed_commands == []


@pytest.mark.parametrize(
    "kind", ["symbolic link 777 root:root", "directory 755 root:root", "fifo 644 root:root", "", "unknown"]
)
def test_non_regular_rule_path_is_replaced(kind: str) -> None:
    """A symlink (e.g. to /dev/null) or other non-file at the rule path is renamed over, never written through."""

    run = deploy(host(rule=render_rule(CFG), kind=kind, state="10"))
    assert run.mutating_changed_ops == [f"{P}Install {RULE_PATH}", f"{P}Apply the TCC offset through the udev rule"]
    assert write_command(CFG) in run.executed_commands


def test_failed_write_fails_the_deploy_before_the_apply() -> None:
    """E.g. a directory at the rule path: ``mv -T`` cannot replace it."""

    responses = {**host(rule=render_rule(CFG), kind="directory 755 root:root"), write_command(CFG): {"success": False}}
    run = run_deploy_fake(deploy_cpu_tcc_offset, CFG, responses=responses)
    assert not run.succeeded
    assert APPLY not in run.executed_commands


def test_device_at_the_offset_plans_no_change() -> None:
    run = deploy(host(rule=render_rule(CFG), state="10"))
    assert run.planned_changes == []
    assert run.executed_commands == []


@pytest.mark.parametrize("state", ["0", "5"])
def test_device_with_another_offset_is_applied_again(state: str) -> None:
    """A failed apply of an earlier run (the rule is in place, the device is not) is retried."""

    run = deploy(host(rule=render_rule(CFG), state=state))
    assert run.mutating_changed_ops == [f"{P}Apply the TCC offset through the udev rule"]
    assert APPLY in run.executed_commands


def test_changed_rule_is_rewritten_and_applied() -> None:
    run = deploy(host(rule=render_rule(CpuTccOffsetConfig(offset=5)), state="5"))
    assert write_command(CFG) in run.executed_commands
    assert APPLY in run.executed_commands


@pytest.mark.parametrize("kind", ["regular file 666 root:root", "regular file 644 jochen:root"])
def test_wrong_mode_or_owner_is_rewritten(kind: str) -> None:
    run = deploy(host(rule=render_rule(CFG), kind=kind, state="10"))
    assert write_command(CFG) in run.executed_commands


@pytest.mark.parametrize("offset", [0, 64, -1])
def test_offset_out_of_range_is_refused(offset: int) -> None:
    with pytest.raises(ValidationError):
        CpuTccOffsetConfig(offset=offset)


def test_non_linux_host_is_refused() -> None:
    run = run_deploy_fake(deploy_cpu_tcc_offset, CFG, responses={**host(), "uname -s": ["Darwin"]})
    assert not run.succeeded
    assert "Linux hosts only" in str(run.error)
