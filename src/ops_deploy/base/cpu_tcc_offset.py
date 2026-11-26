"""A TCC offset: the CPU throttles itself ``offset`` °C below TjMax (no ops-library role).

Intel CPUs throttle in hardware (the thermal control circuit, TCC) once the
package reaches TjMax minus the TCC offset. The kernel's ``intel_tcc_cooling``
driver shows that offset as the thermal cooling device of type ``TCC Offset``
(``cur_state`` is the offset in °C); the value is lost at every reboot.

The deploy installs one managed file, ``/etc/udev/rules.d/60-cpu-tcc-offset.rules``,
which sets ``cur_state`` whenever that device appears, so at every boot. A
symlink, directory or other non-regular file at that path is refused before
any change, never written through. When the host has the device and the file
changes, or the device holds another offset (a failed apply of an earlier
run), it reloads udev, replays the ``add`` event of that one device and reads
``cur_state`` back: udev ignores a failed attribute write, so the deploy fails
unless the device now holds the offset. A converged host plans no change.
"""

from __future__ import annotations

from io import StringIO

from pydantic import Field
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server

from ops_deploy.base._common import RoleConfig, output, require_linux

RULE_PATH = "/etc/udev/rules.d/60-cpu-tcc-offset.rules"
HEADER = "# Managed by ops-deploy base.cpu_tcc_offset; local changes are overwritten.\n"
APPLY = (
    "udevadm control --reload && udevadm trigger --action=add --subsystem-match=thermal "
    "--attr-match='type=TCC Offset' --settle"
)
# The ``cur_state`` of the TCC Offset device; empty when the host has none.
STATE = "for d in /sys/class/thermal/cooling_device*; do grep -qx 'TCC Offset' $d/type && cat $d/cur_state; done"
# ``stat`` file type of the rule path, not following a symlink (C locale: English names).
KIND = f"LC_ALL=C LANG=C stat -c %F {RULE_PATH} 2>/dev/null || echo missing"


class CpuTccOffsetConfig(RoleConfig):
    """The TCC offset in °C: the CPU throttles at TjMax minus ``offset``."""

    offset: int = Field(ge=1, le=63)


def verify_command(cfg: CpuTccOffsetConfig) -> str:
    """Fails unless the TCC Offset device holds the offset (run after the apply)."""

    return (
        f'test "$({STATE})" = {cfg.offset} || '
        f'{{ echo "cpu_tcc_offset: TCC Offset cur_state is not {cfg.offset} after the apply" >&2; exit 1; }}'
    )


def render_rule(cfg: CpuTccOffsetConfig) -> str:
    return (
        f"{HEADER}"
        'ACTION=="add", SUBSYSTEM=="thermal", KERNEL=="cooling_device*", '
        f'ATTR{{type}}=="TCC Offset", ATTR{{cur_state}}="{cfg.offset}"\n'
    )


@deploy("CPU TCC offset")
def deploy_cpu_tcc_offset(cfg: CpuTccOffsetConfig) -> None:
    require_linux("cpu_tcc_offset")
    kind = output(KIND).strip()
    if kind not in ("missing", "regular file", "regular empty file"):
        raise DeployError(f"cpu_tcc_offset: {RULE_PATH} is a {kind or 'file of unknown type'}, not a regular file")
    state = output(STATE).strip()
    rule = files.put(
        name=f"Install {RULE_PATH}",
        src=StringIO(render_rule(cfg)),
        dest=RULE_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    # No device (``state`` empty): the rule matches nothing, there is nothing to apply.
    if state and (rule.will_change or state != str(cfg.offset)):
        server.shell(
            name="Apply the TCC offset through the udev rule",
            commands=[APPLY, verify_command(cfg)],
        )
