"""Set the system hostname (the ``hostname_set`` role)."""

from __future__ import annotations

import shlex
from collections.abc import Generator
from typing import Annotated

from pydantic import Field
from pyinfra import host
from pyinfra.api import StringCommand, deploy, operation
from pyinfra.facts.server import Command, Kernel
from pyinfra.operations import server

from ops_deploy.base._common import RoleConfig


class HostnameConfig(RoleConfig):
    # The role's regex; the private side passes the inventory host name, as the
    # role's default ``inventory_hostname`` does.
    hostname: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")]


def darwin_local_hostname(name: str) -> str:
    """Ansible's DarwinStrategy scrub transformation, including its dash rule."""
    name = name.replace("_", "-").replace(".", "")
    while "--" in name:
        name = name.replace("--", "")
    return name.rstrip("-")


@operation()
def _darwin_hostname(hostname: str) -> Generator[StringCommand, None, None]:
    expected = {
        "HostName": hostname,
        "ComputerName": hostname,
        "LocalHostName": darwin_local_hostname(hostname),
    }
    # An unset HostName exits 1. Like DarwinStrategy, treat its empty output
    # as drift rather than failing fact collection before a setter can run.
    current = {
        key: host.get_fact(Command, command=f"/usr/sbin/scutil --get {key} 2>/dev/null || true") for key in expected
    }
    if current != expected:
        # DarwinStrategy updates all three names together when any differs.
        for key, value in expected.items():
            yield StringCommand(shlex.join(["/usr/sbin/scutil", "--set", key, value]))


@deploy("Set hostname")
def deploy_hostname(cfg: HostnameConfig) -> None:
    if host.get_fact(Kernel) == "Darwin":
        _darwin_hostname(name=f"Set native macOS hostname {cfg.hostname}", hostname=cfg.hostname)
        return
    # ``hostnamectl set-hostname`` (static and transient name), only when
    # ``uname -n`` differs; like Ansible's systemd strategy.
    server.hostname(name=f"Set hostname {cfg.hostname}", hostname=cfg.hostname)
