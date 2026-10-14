"""Service system users, their directories and sudoers rules.

Replaces the ``tasks/user.yml`` every ``*_deploy`` role carries: a group, a
system user with that primary group, directories owned by the user, and the
``/etc/sudoers.d`` drop-ins some roles add.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from collections.abc import Generator, Sequence
from dataclasses import dataclass
from io import StringIO
from pathlib import PurePosixPath

from pyinfra import host, logger
from pyinfra.api import OperationValueError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File, Sha256File
from pyinfra.facts.server import Users
from pyinfra.operations import files, server

SUDOERS_DIR = PurePosixPath("/etc/sudoers.d")


@dataclass(frozen=True)
class SystemUser:
    group: OperationMeta
    # None when the user already existed and was already in ``group``.
    user: OperationMeta | None
    directories: tuple[OperationMeta, ...]


def system_user(
    user: str,
    *,
    home: PurePosixPath,
    group: str | None = None,
    shell: str = "/bin/bash",
    directories: Sequence[PurePosixPath] = (),
    mode: str = "0755",
) -> SystemUser:
    """Ensure ``group`` (default: ``user``), the system user and its directories.

    ``home`` is created owned by the user; ``directories`` are created after
    it, in order, with the same owner and ``mode``.

    Like the roles' ``user.yml``, an existing user is never modified apart
    from being added to ``group``: its home, shell and primary group stay as
    they are. A difference is logged as a warning so drift is visible.
    """

    group = group or user
    group_op = server.group(name=f"Ensure group {group}", group=group, system=True)
    existing = host.get_fact(Users).get(user)
    user_op: OperationMeta | None = None
    if existing is None:
        user_op = server.user(
            name=f"Ensure user {user}",
            user=user,
            group=group,
            home=str(home),
            shell=shell,
            system=True,
            ensure_home=False,
            create_home=False,
        )
    else:
        wanted = {"home": str(home), "shell": shell, "group": group}
        for key, value in wanted.items():
            if existing.get(key) != value:
                logger.warning(
                    f"{host.name}: existing user {user} has {key} {existing.get(key)!r}, "
                    f"wanted {value!r}; left unchanged"
                )
        if group != existing.get("group") and group not in existing.get("groups", []):
            user_op = server.user(
                name=f"Add {user} to group {group}", user=user, groups=[group], append=True, ensure_home=False
            )
    dirs = tuple(
        files.directory(
            name=f"Ensure directory {path}",
            path=str(path),
            user=user,
            group=group,
            mode=mode,
        )
        for path in (home, *[path for path in directories if path != home])
    )
    return SystemUser(group=group_op, user=user_op, directories=dirs)


@operation()
def _sudoers(path: str, content: str) -> Generator[StringCommand, None, None]:
    info = host.get_fact(File, path=path)
    if (
        info
        and (info["user"], info["group"], info["mode"]) == ("root", "root", 440)
        and host.get_fact(Sha256File, path=path) == hashlib.sha256(content.encode()).hexdigest()
    ):
        host.noop(f"{path} is up to date")
        return
    # sudo skips drop-ins whose name contains a dot, so the staged copy is
    # never live; it replaces the rule only once visudo accepts it.
    staged = shlex.quote(str(PurePosixPath(path).with_name(f".ops-deploy-{PurePosixPath(path).name}")))
    yield from files.put._inner(src=StringIO(content), dest=staged, user="root", group="root", mode="0440")
    yield StringCommand(f"visudo -cqf {staged} && mv -f {staged} {shlex.quote(path)} || {{ rm -f {staged}; exit 1; }}")


def sudoers_file(name: str, content: str) -> OperationMeta:
    """Install ``/etc/sudoers.d/<name>`` as ``root:root 0440`` once ``visudo -c`` accepts it.

    Like the roles' ``template`` with ``validate: visudo -cf %s``: a rule
    that does not parse never replaces the installed one.
    """

    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise OperationValueError(f"sudoers drop-in names may only use letters, digits, _ and -: {name!r}")
    return _sudoers(name=f"Install sudoers rule {name}", path=str(SUDOERS_DIR / name), content=content)
