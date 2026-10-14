"""Service system users and their directories.

Replaces the ``tasks/user.yml`` every ``*_deploy`` role carries: a group, a
system user with that primary group, and directories owned by the user.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, server


@dataclass(frozen=True)
class SystemUser:
    group: OperationMeta
    user: OperationMeta
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
    it, in order, with the same owner and ``mode``. An existing user keeps
    its home contents: the home directory is never moved.
    """

    group = group or user
    group_op = server.group(name=f"Ensure group {group}", group=group, system=True)
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
