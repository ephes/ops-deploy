"""Set the system hostname (the ``hostname_set`` role)."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field
from pyinfra.api import deploy
from pyinfra.operations import server

from ops_deploy.base._common import RoleConfig


class HostnameConfig(RoleConfig):
    # The role's regex; the private side passes the inventory host name, as the
    # role's default ``inventory_hostname`` does.
    hostname: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")]


@deploy("Set hostname")
def deploy_hostname(cfg: HostnameConfig) -> None:
    # ``hostnamectl set-hostname`` (static and transient name), only when
    # ``uname -n`` differs; like Ansible's systemd strategy.
    server.hostname(name=f"Set hostname {cfg.hostname}", hostname=cfg.hostname)
