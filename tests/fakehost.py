"""Building blocks for ``fake_responses`` that describe an Ubuntu host."""

from __future__ import annotations

import hashlib
from typing import Any

LINUX: dict[str, Any] = {
    "uname -s": ["Linux"],
    "command -v useradd": ["/usr/sbin/useradd"],
    "command -v usermod": ["/usr/sbin/usermod"],
    "command -v groupadd": ["/usr/sbin/groupadd"],
}


def stat(path: str, *, user: str = "root", group: str | None = None, mode: str = "-rw-r--r--") -> dict[str, Any]:
    """``File``/``Directory`` fact: ``path`` exists with this owner and mode."""

    line = f"user={user} group={group or user} mode={mode} atime=0 mtime=0 ctime=0 size=10 '{path}'"
    return {f"test -e {path} ||": [line]}


def file(path: str, content: str, *, user: str = "root", mode: str = "-rw-r--r--") -> dict[str, Any]:
    """A regular file with ``content`` (stat, sha1 and ``FileContents``)."""

    digest = hashlib.sha1(content.encode()).hexdigest()
    return {
        f"sha1sum {path} ": [f"{digest}  {path}"],
        f"cat {path}": content.splitlines(),
        **stat(path, user=user, mode=mode),
    }


def directory(path: str, *, user: str = "root", mode: str = "drwxr-xr-x") -> dict[str, Any]:
    return stat(path, user=user, mode=mode)


def system_account(user: str, home: str, *, uid: int = 999, shell: str = "/bin/bash") -> dict[str, Any]:
    """``Users`` and ``Groups`` facts listing ``user`` with a same-named group."""

    entry = f"{user}:x:{uid}:{uid}::{home}:{shell}|{user}|{user}||!"
    return {
        "cat /etc/group": ["root:x:0:", f"{user}:x:{uid}:"],
        "cat /etc/passwd | cut": ["root:x:0:0:root:/root:/bin/bash|root|root||!", entry],
    }


def service(unit: str, *, running: bool = True, enabled: bool = True) -> dict[str, Any]:
    return {
        f"--property SubState {unit}": [f"Id={unit}", f"SubState={'running' if running else 'dead'}"],
        f"--property UnitFileState {unit}": [f"Id={unit}", f"UnitFileState={'enabled' if enabled else 'disabled'}"],
    }


def venv(path: str) -> dict[str, Any]:
    """A venv at ``path`` with a working (executable) ``bin/python``."""

    return {f"test -x {path}/bin/python": ["present"]}
