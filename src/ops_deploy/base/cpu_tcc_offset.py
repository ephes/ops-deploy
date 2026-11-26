"""A TCC offset: the CPU throttles itself ``offset`` °C below TjMax (no ops-library role).

Intel CPUs throttle in hardware (the thermal control circuit, TCC) once the
package reaches TjMax minus the TCC offset. The kernel's ``intel_tcc_cooling``
driver shows that offset as the thermal cooling device of type ``TCC Offset``
(``cur_state`` is the offset in °C); the value is lost at every reboot.

The deploy keeps one file, ``/etc/udev/rules.d/60-cpu-tcc-offset.rules``
(``root:root 0644``), which sets ``cur_state`` whenever that device appears,
so at every boot. The file is written to a temporary file in the same
directory and renamed over the rule path (``mv -fT``): the rename replaces a
symlink at that path instead of writing through it, and fails on a directory.
When the host has the device and the file changes, or the device holds another
offset (a failed apply of an earlier run), it reloads udev, replays the
``add`` event of that one device and reads ``cur_state`` back: udev ignores a
failed attribute write, so the deploy fails unless the device now holds the
offset. ``cur_state`` that cannot be read fails the deploy before any change;
only a host without a ``TCC Offset`` device skips the apply. A converged host
plans no change.
"""

from __future__ import annotations

import hashlib
import shlex

from pydantic import Field
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server

from ops_deploy.base._common import RoleConfig, output, require_linux

RULE_PATH = "/etc/udev/rules.d/60-cpu-tcc-offset.rules"
HEADER = "# Managed by ops-deploy base.cpu_tcc_offset; local changes are overwritten.\n"
APPLY = (
    "udevadm control --reload && udevadm trigger --action=add --subsystem-match=thermal "
    "--attr-match='type=TCC Offset' --settle"
)
# The ``cur_state`` of the TCC Offset device, ``absent`` when the host has
# none, ``unreadable`` when its ``cur_state`` cannot be read.
STATE = (
    "{ found=; for d in /sys/class/thermal/cooling_device*; do "
    "grep -qx 'TCC Offset' \"$d/type\" || continue; found=1; "
    'cat "$d/cur_state" || echo unreadable; done; [ -n "$found" ] || echo absent; }'
)
# File type, mode and owner of the rule path, not following a symlink (C locale: English names).
KIND = f"LC_ALL=C LANG=C stat -c '%F %a %U:%G' {RULE_PATH} || echo missing"
DIGEST = f"sha256sum {RULE_PATH}"
CONVERGED_KIND = "regular file 644 root:root"


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


def write_command(cfg: CpuTccOffsetConfig) -> str:
    """Writes the rule to a temporary file next to it and renames it over the rule path.

    ``mv -T`` renames onto the path itself: a symlink there is replaced, not
    followed, and a directory there fails the rename. udev reads only
    ``*.rules``, so the temporary file is never loaded.
    """

    return (
        "tmp=$(mktemp /etc/udev/rules.d/.60-cpu-tcc-offset.rules.XXXXXX) && "
        f'{{ printf %s {shlex.quote(render_rule(cfg))} >"$tmp" && chown root:root "$tmp" && chmod 0644 "$tmp" '
        f'&& mv -fT "$tmp" {RULE_PATH} || {{ rm -f "$tmp"; exit 1; }}; }}'
    )


def device_state() -> str | None:
    """The device's ``cur_state``; ``None`` when the host has no TCC Offset device."""

    state = output(STATE).strip()
    if state == "absent":
        return None
    if not state.isdigit():
        raise DeployError(f"cpu_tcc_offset: cannot read the TCC Offset cur_state ({state or 'no output'})")
    return state


@deploy("CPU TCC offset")
def deploy_cpu_tcc_offset(cfg: CpuTccOffsetConfig) -> None:
    require_linux("cpu_tcc_offset")
    state = device_state()
    digest = hashlib.sha256(render_rule(cfg).encode()).hexdigest()
    current = output(DIGEST).split()
    changed = output(KIND).strip() != CONVERGED_KIND or current[:1] != [digest]
    if changed:
        server.shell(name=f"Install {RULE_PATH}", commands=[write_command(cfg)])
    # No device: the rule matches nothing, there is nothing to apply.
    if state is not None and (changed or state != str(cfg.offset)):
        server.shell(
            name="Apply the TCC offset through the udev rule",
            commands=[APPLY, verify_command(cfg)],
        )
