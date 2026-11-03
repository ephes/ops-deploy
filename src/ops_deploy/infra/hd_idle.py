"""Idle spindown with the packaged hd-idle daemon, configured per disk by ``/dev/disk/by-id`` name.

hd-idle only reads ``/proc/diskstats``; it never queries a disk's power state.
A disk is sent one SCSI STOP UNIT (libata: ATA STANDBY IMMEDIATE, the command
``hdparm -y`` issues) once its read and write counters stayed unchanged for its
idle time. Starting the daemon touches no disk. See
``docs/services/fractal_storage_services.md`` for the evidence.
"""

from __future__ import annotations

from io import StringIO
from typing import Annotated

from pydantic import Field, StrictInt, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.server import Which
from pyinfra.operations import apt, files

from ops_deploy.base._common import RoleConfig, require_linux, require_systemd
from ops_deploy.helpers.systemd import UNIT_DIR, service_rollout

SERVICE = "hd-idle.service"
# The packaged unit's EnvironmentFile; the drop-in pins it so no other file can
# supply HD_IDLE_OPTS.
CONFIG_PATH = "/etc/default/hd-idle"
DROPIN_DIR = str(UNIT_DIR / f"{SERVICE}.d")
DROPIN_PATH = f"{DROPIN_DIR}/10-ops-deploy.conf"
HEADER = "# Managed by ops-deploy infra.hd_idle; local changes are overwritten.\n"

# A whole-disk by-id link (no "-partN"); hd-idle resolves it with readlink() at
# start and strips trailing digits, so partitions and kernel names are refused.
ByIdDisk = Annotated[str, Field(pattern=r"^/dev/disk/by-id/[A-Za-z0-9_.:+-]+$")]


class HdIdleDisk(RoleConfig):
    device: ByIdDisk
    # Seconds without a /proc/diskstats read or write before the disk is spun down.
    idle_time: Annotated[StrictInt, Field(ge=60)]

    @model_validator(mode="after")
    def _whole_disk(self) -> HdIdleDisk:
        name = self.device.rsplit("/", 1)[1]
        if name in {".", ".."}:
            raise ValueError("hd-idle disks must name a by-id link")
        if "-part" in name:
            raise ValueError("hd-idle disks must be whole-disk by-id links, not partitions")
        return self


class HdIdleConfig(RoleConfig):
    disks: tuple[HdIdleDisk, ...] = Field(min_length=1)
    # Idle time for every other sd* disk; 0 never spins one down.
    default_idle_time: Annotated[StrictInt, Field(ge=0)] = 0

    @model_validator(mode="after")
    def _unique(self) -> HdIdleConfig:
        if len({disk.device for disk in self.disks}) != len(self.disks):
            raise ValueError("hd-idle disks must be unique")
        return self


def options(cfg: HdIdleConfig) -> str:
    """``HD_IDLE_OPTS``: the global ``-i`` first, then ``-a <disk> -i <seconds>`` per disk."""

    parts = ["-i", str(cfg.default_idle_time)]
    for disk in cfg.disks:
        parts += ["-a", disk.device, "-i", str(disk.idle_time)]
    return " ".join(parts)


def render_config(cfg: HdIdleConfig) -> str:
    return (
        HEADER + "# hd-idle resolves each -a link to its kernel name once, at service start.\n"
        f'HD_IDLE_OPTS="{options(cfg)}"\n'
    )


def device_unit(path: str) -> str:
    """systemd's ``.device`` unit name for ``path`` (``systemd-escape --path``)."""

    escaped = []
    for index, char in enumerate(path.strip("/")):
        if char == "/":
            escaped.append("-")
        elif char.isascii() and (char.isalnum() or char in ":_" or (char == "." and index)):
            escaped.append(char)
        else:
            escaped.append("".join(f"\\x{byte:02x}" for byte in char.encode()))
    return "".join(escaped) + ".device"


def render_dropin(cfg: HdIdleConfig) -> str:
    """Pin the config file and start only after the by-id links exist (or their device job timed out)."""

    devices = " ".join(device_unit(disk.device) for disk in cfg.disks)
    return (
        f"{HEADER}[Unit]\nWants={devices}\nAfter={devices}\n\n"
        f"[Service]\nEnvironmentFile=\nEnvironmentFile={CONFIG_PATH}\n"
    )


@deploy("Configure hd-idle idle spindown")
def deploy_hd_idle(cfg: HdIdleConfig) -> None:
    require_linux("hd-idle")
    require_systemd("hd-idle")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("hd-idle needs Debian/Ubuntu apt")
    installed = host.get_fact(DebPackages)
    apt.packages(
        name="Ensure hd-idle package", packages=["hd-idle"], update="hd-idle" not in installed, cache_time=3600
    )
    config = files.put(
        name=f"Install {CONFIG_PATH}",
        src=StringIO(render_config(cfg)),
        dest=CONFIG_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    files.directory(name=f"Ensure {DROPIN_DIR}", path=DROPIN_DIR, user="root", group="root", mode="0755")
    dropin = files.put(
        name=f"Install {SERVICE} drop-in",
        src=StringIO(render_dropin(cfg)),
        dest=DROPIN_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    # Starting or restarting hd-idle reads /proc/diskstats only; no disk is opened.
    service_rollout(SERVICE, units=(dropin,), restart_when=(config,))
