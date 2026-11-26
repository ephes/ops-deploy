"""A TCC offset: the CPU throttles itself ``offset`` °C below TjMax (no ops-library role).

Intel CPUs throttle in hardware (the thermal control circuit, TCC) once the
package reaches its activation temperature: TjMax minus the programmable TCC
offset (``MSR_IA32_TEMPERATURE_TARGET``). The kernel's ``intel_tcc_cooling``
driver shows that offset as the thermal cooling device of type ``TCC
Offset``; its ``cur_state`` is the offset in °C. The value does not survive a
reboot.

The deploy installs ``/etc/udev/rules.d/60-cpu-tcc-offset.rules``, which
writes the offset whenever that cooling device appears (at every boot), and
applies it with ``udevadm trigger`` for that one device, so the run sets the
value through the same rule a boot uses; a read-only check then reads
``cur_state`` back. A host without the device (another CPU vendor, a locked
offset, the driver not loaded) is refused before any change. A converged host
plans no change.
"""

from __future__ import annotations

import shlex
from io import StringIO

from pydantic import Field
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server

from ops_deploy.base._common import RoleConfig, output, require_linux
from ops_deploy.helpers import mark_read_only

RULE_PATH = "/etc/udev/rules.d/60-cpu-tcc-offset.rules"
DEVICE_TYPE = "TCC Offset"
HEADER = "# Managed by ops-deploy base.cpu_tcc_offset; local changes are overwritten.\n"
# One line per cooling device of DEVICE_TYPE: ``<sysfs dir> <cur_state> <max_state>``.
PROBE = (
    "for d in /sys/class/thermal/cooling_device*; do "
    f'if [ "$(cat "$d/type")" = {shlex.quote(DEVICE_TYPE)} ]; then '
    'echo "$d $(cat "$d/cur_state") $(cat "$d/max_state")"; fi; done'
)
TRIGGER = (
    "udevadm control --reload && udevadm trigger --action=add --subsystem-match=thermal "
    f"--attr-match={shlex.quote('type=' + DEVICE_TYPE)} --settle"
)


class CpuTccOffsetConfig(RoleConfig):
    """The TCC offset in °C: the CPU throttles at TjMax minus ``offset``."""

    offset: int = Field(ge=1, le=63)


def render_rule(cfg: CpuTccOffsetConfig) -> str:
    return (
        f"{HEADER}"
        f'ACTION=="add", SUBSYSTEM=="thermal", KERNEL=="cooling_device*", '
        f'ATTR{{type}}=="{DEVICE_TYPE}", ATTR{{cur_state}}="{cfg.offset}"\n'
    )


def tcc_device(shown: str) -> tuple[str, int, int]:
    """The one ``TCC Offset`` cooling device in :data:`PROBE` output: path, current and maximum offset."""

    lines = [line.split() for line in shown.splitlines() if line.strip()]
    if len(lines) != 1 or len(lines[0]) != 3 or not all(part.isdigit() for part in lines[0][1:]):
        raise DeployError(
            f"cpu_tcc_offset: expected one {DEVICE_TYPE!r} cooling device (intel_tcc_cooling), found {len(lines)}"
        )
    path, current, maximum = lines[0]
    return path, int(current), int(maximum)


def verify_command(path: str, offset: int) -> str:
    state = shlex.quote(f"{path}/cur_state")
    failure = f'echo "{path}: cur_state is $(cat {state}), not {offset}" >&2; exit 1;'
    return f'test "$(cat {state})" = {offset} || {{ {failure} }}'


@deploy("CPU TCC offset")
def deploy_cpu_tcc_offset(cfg: CpuTccOffsetConfig) -> None:
    require_linux("cpu_tcc_offset")
    path, current, maximum = tcc_device(output(PROBE))
    if cfg.offset > maximum:
        raise DeployError(f"cpu_tcc_offset: offset {cfg.offset} is above the device's maximum {maximum}")
    logger.info(f"{host.print_prefix}cpu_tcc_offset: {path} cur_state {current} (max {maximum}), wanted {cfg.offset}")

    rule = render_rule(cfg)
    quoted = shlex.quote(RULE_PATH)
    installed = output(f"stat -c '%U:%G %a %F' {quoted}") == "root:root 644 regular file" and output(
        f"cat {quoted}"
    ) == rule.rstrip("\n")
    if installed and current == cfg.offset:
        return
    files.put(
        name=f"Install {RULE_PATH}",
        src=StringIO(rule),
        dest=RULE_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    server.shell(name="Apply the TCC offset through the udev rule", commands=[TRIGGER])
    mark_read_only(
        server.shell(name=f"Check the TCC offset is {cfg.offset}", commands=[verify_command(path, cfg.offset)])
    )
