"""systemd unit files and change-gated service rollout.

Replaces ``webapp_deploy_internal`` ``systemd_service`` plus the per-role
``reload systemd`` / ``restart <svc>`` handlers: the unit is written with
:func:`systemd_unit`, and :func:`service_rollout` reloads systemd only when a
unit changed and restarts only when something the service reads changed.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from io import StringIO
from pathlib import PurePosixPath

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, systemd
from pyinfra.operations.util import any_changed

UNIT_DIR = PurePosixPath("/etc/systemd/system")

_UNIT_PATTERN = re.compile(r"^[A-Za-z0-9@_.-]+\.(service|socket|timer|path|target|mount)$")


def unit_name(name: str) -> str:
    """``name`` with a ``.service`` suffix unless it already has a unit type."""

    unit = name if _UNIT_PATTERN.match(name) else f"{name}.service"
    if not _UNIT_PATTERN.match(unit) or unit.startswith("."):
        raise ValueError(f"invalid systemd unit name: {name!r}")
    return unit


def systemd_unit(name: str, content: str) -> OperationMeta:
    """Install a unit file as ``root:root 0644``; changed only if the content differs."""

    unit = unit_name(name)
    return files.put(
        name=f"Install systemd unit {unit}",
        src=StringIO(content),
        dest=str(UNIT_DIR / unit),
        user="root",
        group="root",
        mode="0644",
    )


@dataclass(frozen=True)
class Rollout:
    """Operation results of one :func:`service_rollout`; ``None`` where skipped."""

    daemon_reload: OperationMeta | None
    enable: OperationMeta
    start: OperationMeta
    restart: OperationMeta


def service_rollout(
    name: str,
    *,
    units: Sequence[OperationMeta] = (),
    restart_when: Sequence[OperationMeta] = (),
    always_restart: bool = False,
) -> Rollout:
    """Enable and start ``name``; reload/restart only on change.

    - ``systemctl daemon-reload`` runs if any of ``units`` changed.
    - The service is enabled and started (no-ops when already so).
    - It is restarted if any of ``units`` or ``restart_when`` changed, or
      always with ``always_restart`` (fastdeploy keeps its unconditional
      restart, even right after this run started it). Otherwise there is no
      restart right after this run started the service.
    """

    unit = unit_name(name)
    reload = systemd.daemon_reload(name=f"Reload systemd for {unit}", _if=any_changed(*units)) if units else None
    enable = systemd.service(name=f"Enable {unit}", service=unit, running=None, enabled=True)
    start = systemd.service(name=f"Start {unit}", service=unit, running=True)

    triggers = (*units, *restart_when)

    def should_restart() -> bool:
        if always_restart:
            return True
        if start.did_change():
            return False
        return any(meta.did_change() for meta in triggers)

    # ``restarted=True`` only restarts a unit pyinfra saw running at plan time;
    # an unconditional restart must also hit one this run just started.
    how = {"command": "restart"} if always_restart else {"restarted": True}
    restart = systemd.service(name=f"Restart {unit}", service=unit, running=None, _if=should_restart, **how)
    return Rollout(daemon_reload=reload, enable=enable, start=start, restart=restart)
