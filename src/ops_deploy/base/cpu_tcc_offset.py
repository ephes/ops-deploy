"""A TCC offset: the CPU throttles itself ``offset`` °C below TjMax (no ops-library role).

Intel CPUs throttle in hardware (the thermal control circuit, TCC) once the
package reaches TjMax minus the TCC offset. The kernel's ``intel_tcc_cooling``
driver shows that offset as the thermal cooling device of type ``TCC Offset``
(``cur_state`` is the offset in °C); the value is lost at every reboot.

The deploy installs one managed file, ``/etc/udev/rules.d/60-cpu-tcc-offset.rules``,
which sets ``cur_state`` whenever that device appears, so at every boot. When
the file changed, it reloads udev and replays the ``add`` event of that one
device, so the offset takes effect without a reboot. A converged host plans no
change.
"""

from __future__ import annotations

from io import StringIO

from pydantic import Field
from pyinfra.api import deploy
from pyinfra.operations import files, server

from ops_deploy.base._common import RoleConfig, require_linux

RULE_PATH = "/etc/udev/rules.d/60-cpu-tcc-offset.rules"
HEADER = "# Managed by ops-deploy base.cpu_tcc_offset; local changes are overwritten.\n"
APPLY = (
    "udevadm control --reload && udevadm trigger --action=add --subsystem-match=thermal "
    "--attr-match='type=TCC Offset' --settle"
)


class CpuTccOffsetConfig(RoleConfig):
    """The TCC offset in °C: the CPU throttles at TjMax minus ``offset``."""

    offset: int = Field(ge=1, le=63)


def render_rule(cfg: CpuTccOffsetConfig) -> str:
    return (
        f"{HEADER}"
        'ACTION=="add", SUBSYSTEM=="thermal", KERNEL=="cooling_device*", '
        f'ATTR{{type}}=="TCC Offset", ATTR{{cur_state}}="{cfg.offset}"\n'
    )


@deploy("CPU TCC offset")
def deploy_cpu_tcc_offset(cfg: CpuTccOffsetConfig) -> None:
    require_linux("cpu_tcc_offset")
    rule = files.put(
        name=f"Install {RULE_PATH}",
        src=StringIO(render_rule(cfg)),
        dest=RULE_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    server.shell(name="Apply the TCC offset through the udev rule", commands=[APPLY], _if=rule.did_change)
