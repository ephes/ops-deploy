"""Mask systemd units that cannot work on a host (the ``systemd_unit_masks`` role)."""

from __future__ import annotations

import shlex
from typing import Annotated

from pydantic import Field, model_validator
from pyinfra.api import deploy
from pyinfra.operations import server

from ops_deploy.base._common import RoleConfig, require_systemd
from ops_deploy.base._units import ACTIVE, unit_states

# The type suffix is required: a bare name silently means ``<name>.service``,
# which makes it easy to mask something other than what was intended.
MaskedUnit = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@:\\-]+\.[a-z]+$")]


class UnitMask(RoleConfig):
    unit: MaskedUnit
    # Documentation only: why the unit cannot work on this host.
    reason: str = ""


class SystemdUnitMasksConfig(RoleConfig):
    units: tuple[UnitMask, ...] = ()
    # Units to unmask again, so dropping a mask is reversible through the deploy.
    unmask: tuple[MaskedUnit, ...] = ()
    # Stop a unit before masking it (a masked unit keeps running until reboot).
    stop_now: bool = True
    # Clear a lingering ``failed`` state, which masking does not reset.
    reset_failed: bool = True

    @model_validator(mode="after")
    def _mask_and_unmask_are_disjoint(self) -> SystemdUnitMasksConfig:
        if {mask.unit for mask in self.units} & set(self.unmask):
            raise ValueError("a unit cannot be both masked and unmasked")
        return self


def _is_masked(state: dict[str, str]) -> bool:
    return state.get("LoadState") == "masked" or state.get("UnitFileState") in {"masked", "masked-runtime"}


@deploy("systemd unit masks")
def deploy_systemd_unit_masks(cfg: SystemdUnitMasksConfig) -> None:
    require_systemd("systemd_unit_masks")
    masks = [mask.unit for mask in cfg.units]
    states = unit_states([*cfg.unmask, *masks])

    for unit in cfg.unmask:
        if _is_masked(states[unit]):
            server.shell(name=f"Unmask {unit}", commands=[f"systemctl unmask {shlex.quote(unit)}"])

    for mask in cfg.units:
        unit, state = mask.unit, states[mask.unit]
        quoted = shlex.quote(unit)
        commands = []
        # Stop first: once masked, systemd refuses to act on the unit. A stop
        # that fails does not stop the deploy (the role ignores it too).
        stopping = cfg.stop_now and state.get("ActiveState") in ACTIVE
        if stopping:
            commands.append(f"systemctl stop {quoted} || true")
        # Only a persistent mask counts: a runtime mask (/run) is gone after reboot.
        if state.get("UnitFileState") != "masked":
            commands.append(f"systemctl mask {quoted}")
        if cfg.reset_failed and state.get("ActiveState") == "failed":
            commands.append(f"systemctl reset-failed {quoted}")
        elif cfg.reset_failed and stopping:
            # It may have failed while stopping; if not, systemd has already
            # unloaded the masked unit and reset-failed says "not loaded".
            commands.append(f"systemctl reset-failed {quoted} 2>/dev/null || true")
        if commands:
            label = f"Mask {unit}" + (f" ({mask.reason})" if mask.reason else "")
            server.shell(name=label, commands=commands)
