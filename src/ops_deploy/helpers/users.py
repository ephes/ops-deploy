"""Service system users and their directories.

Replaces the ``tasks/user.yml`` every ``*_deploy`` role carries: a group, a
system user with that primary group, and directories owned by the user.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

from pyinfra import host, logger
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Users
from pyinfra.operations import files, server


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
