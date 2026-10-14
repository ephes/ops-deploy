"""Boot a host into a non-graphical target (the ``headless_mode`` role)."""

from __future__ import annotations

import shlex
from typing import Annotated

from pydantic import Field
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server

from ops_deploy.base._common import RoleConfig, output, require_systemd
from ops_deploy.base._units import ACTIVE, ENABLED, unit_name, unit_states

UnitName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@:\\-]+$")]


class HeadlessModeConfig(RoleConfig):
    default_target: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+\.target$")] = "multi-user.target"
    # A display manager such as ``gdm3``; empty for none.
    display_manager_service: Annotated[str, Field(pattern=r"^([A-Za-z0-9_.@:\\-]+)?$")] = ""
    disable_services: tuple[UnitName, ...] = ()
    # Stop the services now as well, instead of only at the next boot.
    apply_now: bool = True

    @property
    def services(self) -> tuple[str, ...]:
        names = (
            (self.display_manager_service, *self.disable_services)
            if self.display_manager_service
            else self.disable_services
        )
        return tuple(dict.fromkeys(unit_name(name) for name in names))


@deploy("Headless mode")
def deploy_headless_mode(cfg: HeadlessModeConfig) -> None:
    require_systemd("headless_mode")

    if output("systemctl get-default") != cfg.default_target:
        server.shell(
            name=f"Set default boot target {cfg.default_target}",
            commands=[f"systemctl set-default {shlex.quote(cfg.default_target)}"],
        )

    for unit, state in unit_states(cfg.services).items():
        if state.get("LoadState") == "not-found":
            # As Ansible's systemd_service, which fails on an unknown unit.
            raise DeployError(f"headless_mode: unit {unit} not found")
        commands = []
        if state.get("UnitFileState") in ENABLED:
            commands.append(f"systemctl disable {shlex.quote(unit)}")
        if cfg.apply_now and state.get("ActiveState") in ACTIVE:
            commands.append(f"systemctl stop {shlex.quote(unit)}")
        if commands:
            server.shell(name=f"Disable {unit}", commands=commands)
