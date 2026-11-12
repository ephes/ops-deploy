"""fq_codel as the default qdisc and as the root qdisc of chosen interfaces (no ops-library role).

``net.core.default_qdisc`` only decides the qdisc of a qdisc created later: an
interface keeps the root qdisc it got when it first came up (a link going down
and up again keeps it). An interface brought up before the sysctl applies (by
the initramfs, as for a host with remote LUKS unlock and ``ip=`` on the kernel
command line) therefore keeps the kernel's ``pfifo_fast`` (under ``mq`` on a
multiqueue NIC) until something replaces it.

The deploy writes ``/etc/sysctl.d/60-default-qdisc.conf`` and applies the
value with ``sysctl -w`` when the running one differs; replaces the root qdisc
of each configured interface with ``tc qdisc replace dev <iface> root
fq_codel`` when ``tc qdisc show`` does not already show fq_codel there; and
installs and enables ``default-qdisc.service``, a oneshot that runs the same
``tc qdisc replace`` at boot, so the interfaces come back with fq_codel after a
reboot. The unit is not started by the deploy (the deploy replaces the running
qdisc itself). A converged host plans no change.
"""

from __future__ import annotations

import re
from io import StringIO
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server, systemd

from ops_deploy.base._common import RoleConfig, output, require_linux, require_systemd
from ops_deploy.base._units import unit_states
from ops_deploy.helpers import systemd_unit

TC = "/usr/sbin/tc"
SYSCTL_KEY = "net.core.default_qdisc"
SYSCTL_PATH = "/etc/sysctl.d/60-default-qdisc.conf"
RUNNING_PATH = "/proc/sys/net/core/default_qdisc"
SERVICE = "default-qdisc.service"
HEADER = "# Managed by ops-deploy base.default_qdisc; local changes are overwritten.\n"

# A kernel interface name (at most 15 bytes); no ``:`` alias labels, no ``/``.
Interface = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")]
# ``tc qdisc show dev <iface> root``: ``qdisc <kind> <handle>: root ...``.
_ROOT = re.compile(r"^qdisc (?P<kind>[A-Za-z0-9_-]+) [0-9a-f]+: (dev \S+ )?root\b")


class DefaultQdiscConfig(RoleConfig):
    """``qdisc`` for new qdiscs and as root qdisc of every interface in ``interfaces``."""

    qdisc: Literal["fq_codel"] = "fq_codel"
    interfaces: tuple[Interface, ...] = Field(min_length=1)

    @field_validator("interfaces")
    @classmethod
    def _unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("interfaces lists an interface twice")
        return value


def render_sysctl(cfg: DefaultQdiscConfig) -> str:
    return f"{HEADER}{SYSCTL_KEY} = {cfg.qdisc}\n"


def device_unit(interface: str) -> str:
    """systemd's ``.device`` unit of a network interface (``-`` escaped as ``\\x2d``)."""

    escaped = interface.replace("-", "\\x2d")
    return f"sys-subsystem-net-devices-{escaped}.device"


def replace_command(cfg: DefaultQdiscConfig, interface: str) -> str:
    return f"{TC} qdisc replace dev {interface} root {cfg.qdisc}"


def render_service(cfg: DefaultQdiscConfig) -> str:
    """A oneshot that sets the root qdiscs again at boot, once each interface's device exists."""

    devices = " ".join(device_unit(interface) for interface in cfg.interfaces)
    starts = "".join(f"ExecStart={replace_command(cfg, interface)}\n" for interface in cfg.interfaces)
    return (
        f"{HEADER}[Unit]\n"
        f"Description={cfg.qdisc} as root qdisc on {' '.join(cfg.interfaces)}\n"
        f"Wants={devices}\nAfter={devices}\n\n"
        f"[Service]\nType=oneshot\nRemainAfterExit=yes\n{starts}\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def root_qdisc(shown: str) -> str | None:
    """The kind of the root qdisc in ``tc qdisc show dev <iface> root`` output, or ``None``."""

    for line in shown.splitlines():
        match = _ROOT.match(line.strip())
        if match:
            return match["kind"]
    return None


def _root_qdiscs(cfg: DefaultQdiscConfig) -> dict[str, str]:
    """The current root qdisc per interface, read while planning; a missing interface is refused."""

    if output(f"test -x {TC} && echo present").strip() != "present":
        raise DeployError(f"default_qdisc needs {TC}; install the iproute2 package first")
    kinds = {}
    for interface in cfg.interfaces:
        if output(f"test -d /sys/class/net/{interface} && echo present").strip() != "present":
            raise DeployError(f"default_qdisc: interface {interface} does not exist on this host")
        kind = root_qdisc(output(f"{TC} qdisc show dev {interface} root"))
        if kind is None:
            raise DeployError(f"default_qdisc: could not read the root qdisc of {interface}")
        kinds[interface] = kind
    return kinds


@deploy("Default qdisc")
def deploy_default_qdisc(cfg: DefaultQdiscConfig) -> None:
    require_linux("default_qdisc")
    require_systemd("default_qdisc")
    running = output(f"cat {RUNNING_PATH}").strip()
    if not running:
        raise DeployError(f"default_qdisc: could not read {SYSCTL_KEY}")
    kinds = _root_qdiscs(cfg)
    logger.info(
        f"{host.print_prefix}default_qdisc: {SYSCTL_KEY} = {running}; root qdisc "
        + ", ".join(f"{interface} {kind}" for interface, kind in kinds.items())
    )
    unit = unit_states([SERVICE])[SERVICE]

    files.put(
        name=f"Install {SYSCTL_PATH}",
        src=StringIO(render_sysctl(cfg)),
        dest=SYSCTL_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    if running != cfg.qdisc:
        server.shell(name=f"Set {SYSCTL_KEY} to {cfg.qdisc}", commands=[f"sysctl -w {SYSCTL_KEY}={cfg.qdisc}"])

    installed = systemd_unit(SERVICE, render_service(cfg))
    systemd.daemon_reload(name=f"Reload systemd for {SERVICE}", _if=installed.did_change)
    # Only a persistent enablement survives a reboot (not ``enabled-runtime``).
    if unit.get("UnitFileState") != "enabled":
        server.shell(name=f"Enable {SERVICE}", commands=[f"systemctl enable {SERVICE}"])

    for interface, kind in kinds.items():
        if kind != cfg.qdisc:
            server.shell(
                name=f"Replace the root qdisc of {interface} ({kind}) with {cfg.qdisc}",
                commands=[replace_command(cfg, interface)],
            )
