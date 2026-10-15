"""Pieces shared by the service backup, restore and removal ports.

Backups and restores run on the host as one bash script each, so the roles'
``block``/``always``/``rescue`` structure keeps its meaning; :func:`script`
puts the settings in front of the script body. Removals are planned from what
the host has, so a second run changes nothing.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path

from pyinfra.operations import server

from ops_deploy.base._common import output
from ops_deploy.base._units import ACTIVE, ENABLED, unit_states

COMMON = Path(__file__).parent / "common.sh"


def flag(value: bool) -> str:
    return "1" if value else "0"


def script(body: Path, values: Mapping[str, str | Sequence[str]], *, call: str = "") -> str:
    """bash: ``set -euo pipefail``, ``values`` as variables (lists as arrays), ``common.sh``, ``body``, ``call``."""

    lines = ["set -euo pipefail"]
    for name, value in values.items():
        if isinstance(value, str):
            lines.append(f"{name}={shlex.quote(value)}")
        else:
            lines.append(f"{name}=({' '.join(shlex.quote(item) for item in value)})")
    return "\n".join([*lines, COMMON.read_text(), body.read_text(), call]).rstrip() + "\n"


def exists(path: str) -> bool:
    return output(f"test -e {shlex.quote(path)} && echo yes").strip() == "yes"


def private_local_dir(path: str) -> None:
    """The controller directory backups are fetched into (``0700``, as the roles create it)."""

    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def remove_path(path: str) -> bool:
    if not exists(path):
        return False
    server.shell(name=f"Remove {path}", commands=[f"rm -rf {shlex.quote(path)}"])
    return True


def stop_disable(units: Sequence[str]) -> None:
    """Stop and disable ``units`` where needed; failures do not stop a removal (the roles' ignore_errors)."""

    states = unit_states(list(units))
    for unit in units:
        if states[unit].get("ActiveState") in ACTIVE:
            server.shell(name=f"Stop {unit}", commands=[f"systemctl stop {shlex.quote(unit)} || true"])
        if states[unit].get("UnitFileState") in ENABLED:
            server.shell(name=f"Disable {unit}", commands=[f"systemctl disable {shlex.quote(unit)} || true"])


def kill_user_processes(user: str, *, graceful: bool = True) -> None:
    """End every process of ``user``, when it runs any.

    ``graceful``: nyxmon_remove's SIGTERM, 5 s, SIGKILL, 3 s, ``systemd-run
    pkill`` sequence; otherwise fastdeploy_remove's single ``pkill``.
    """

    quoted = shlex.quote(user)
    if not output(f"ps -u {quoted} -o pid --no-headers"):
        return
    if not graceful:
        server.shell(name=f"Stop every process of {user}", commands=[f"pkill -u {quoted} || true"])
        return
    server.shell(
        name=f"Stop every process of {user}",
        commands=[
            f"for pid in $(ps -u {quoted} -o pid --no-headers || true); do kill $pid || true; done; sleep 5; "
            f"for pid in $(ps -u {quoted} -o pid --no-headers || true); do kill -9 $pid || true; done; sleep 3; "
            f"if ps -u {quoted} >/dev/null 2>&1; then "
            f"systemd-run --uid=0 --gid=0 --wait -- pkill -9 -u {quoted} || true; sleep 2; fi"
        ],
    )


def remove_account(user: str, group: str) -> None:
    """``user`` (``userdel -r``) and ``group``; failures do not stop a removal."""

    if output(f"getent passwd {shlex.quote(user)}"):
        server.shell(name=f"Remove user {user}", commands=[f"userdel -r {shlex.quote(user)} || true"])
    if output(f"getent group {shlex.quote(group)}"):
        server.shell(name=f"Remove group {group}", commands=[f"groupdel {shlex.quote(group)} || true"])
