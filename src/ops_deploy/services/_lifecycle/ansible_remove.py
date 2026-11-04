"""Operations with the semantics of the Ansible modules the removal roles call.

``ansible.builtin.systemd`` (``state: stopped`` and/or ``enabled: false``),
``ansible.builtin.user`` (``state: absent`` with or without ``remove``) and
``ansible.builtin.file`` (``state: absent``). Each inspects the host when it
executes, so an earlier step of the same removal (a ``userdel`` that also
removed the private group, a purged package that took its directory) is seen.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable, Generator
from pathlib import PurePosixPath
from typing import Any

from pyinfra import host
from pyinfra.api import FunctionCommand, OperationError, QuoteString, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command, Users
from pyinfra.operations import files

from ops_deploy.helpers.traefik import DYNAMIC_DIR, guarded

SERVICE_PROBE = """import json, subprocess, sys
try:
    unit = sys.argv[1]
    show = subprocess.run(['systemctl', 'show', unit],
                          capture_output=True, text=True, timeout=60)
    enabled = subprocess.run(['systemctl', 'is-enabled', unit, '-l'],
                             capture_output=True, text=True, timeout=60)
    fields = dict(line.split('=', 1) for line in show.stdout.splitlines() if '=' in line)
    result = dict(success=show.returncode == 0 and
                          (fields.get('LoadState') == 'masked' or 'LoadError' not in fields),
                  load=fields.get('LoadState', ''),
                  active=fields.get('ActiveState', ''),
                  enabled=enabled.returncode == 0 and enabled.stdout.rstrip()
                          not in ('enabled-runtime', 'indirect', 'alias'))
except Exception:
    result = dict(success=False)
print(json.dumps(result))
"""
# The systemd module stops a unit in these states.
RUNNING = ("active", "activating", "deactivating")


def _unavailable(label: str) -> Callable[[], None]:
    def fail() -> None:
        raise OperationError(f"{label} service inspection failed or unit was absent")

    return fail


@operation()
def service_absent(
    service: str, label: str, stop: bool = True, disable: bool = True
) -> Generator[StringCommand | FunctionCommand, None, None]:
    """``systemd`` with ``state: stopped`` (``stop``) and/or ``enabled: false`` (``disable``).

    The module disables BEFORE stopping and fails, without stopping, on a unit
    it cannot inspect or that is not loaded; the roles ignore that failure
    (``_ignore_errors=True`` at the call), and the removal goes on.
    """

    raw = host.get_fact(Command, command=shlex.join(["/usr/bin/python3", "-I", "-B", "-c", SERVICE_PROBE, service]))
    try:
        observed = json.loads(raw or "")
        if (
            set(observed) != {"success", "load", "active", "enabled"}
            or observed["success"] is not True
            or type(observed["enabled"]) is not bool
            or not all(type(observed[key]) is str for key in ("load", "active"))
            or observed["load"] in ("", "not-found")
            or not observed["active"]
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        yield FunctionCommand(_unavailable(label), (), {})
        return
    if disable and observed["enabled"]:
        yield StringCommand("systemctl", "disable", QuoteString(service))
    if stop and observed["active"] in RUNNING:
        yield StringCommand("systemctl", "stop", QuoteString(service))


@operation()
def user_absent(user: str, remove_home: bool) -> Generator[StringCommand, None, None]:
    """``user: state=absent``; ``remove_home`` is the module's ``remove: true`` (``userdel -r``).

    server.user(present=False) does not expose ``remove``. A failing userdel
    fails the operation, including a partial failure, as the module does.
    """

    if user in host.get_fact(Users):
        yield StringCommand("userdel", *(["-r"] if remove_home else []), QuoteString(user))


def absent(name: str, path: str, **arguments: Any) -> OperationMeta:
    """``file: state=absent``: a directory, file or leaf symlink (not followed), no backup.

    Below the Traefik dynamic directory it waits, like every route writer on
    the host, for no Traefik transaction to hold the lock.
    """

    if PurePosixPath(path).is_relative_to(DYNAMIC_DIR):
        return _absent_route(name=name, path=path, **arguments)
    return files.directory(name=name, path=path, present=False, force=True, force_backup=False, **arguments)


@operation()
def _absent_route(path: str) -> Generator[Any, None, None]:
    yield from guarded(files.directory._inner(path=path, present=False, force=True, force_backup=False))
