"""Building blocks for ``fake_responses`` that describe an Ubuntu host."""

from __future__ import annotations

import hashlib
import time
from typing import Any

LINUX: dict[str, Any] = {
    "uname -s": ["Linux"],
    "command -v useradd": ["/usr/sbin/useradd"],
    "command -v usermod": ["/usr/sbin/usermod"],
    "command -v groupadd": ["/usr/sbin/groupadd"],
    "command -v curl": ["/usr/bin/curl"],
}


def stat(
    path: str, *, user: str = "root", group: str | None = None, mode: str = "-rw-r--r--", mtime: int = 0
) -> dict[str, Any]:
    """``File``/``Directory`` fact: ``path`` exists with this owner and mode."""

    line = f"user={user} group={group or user} mode={mode} atime=0 mtime={mtime} ctime=0 size=10 '{path}'"
    return {f"test -e {path} ||": [line]}


def file(path: str, content: str, *, user: str = "root", mode: str = "-rw-r--r--") -> dict[str, Any]:
    """A regular file with ``content`` (stat, sha1, sha256 and ``FileContents``)."""

    digest = hashlib.sha1(content.encode()).hexdigest()
    sha256 = hashlib.sha256(content.encode()).hexdigest()
    return {
        f"sha1sum {path} ": [f"{digest}  {path}"],
        f"sha256sum {path} ": [f"{sha256}  {path}"],
        f"cat {path}": content.splitlines(),
        **stat(path, user=user, mode=mode),
    }


def symlink(path: str, target: str, *, user: str = "root") -> dict[str, Any]:
    """``Link`` fact: ``path`` is a symlink to ``target``."""

    line = f"user={user} group={user} mode=lrwxrwxrwx atime=0 mtime=0 ctime=0 size=10 '{path}' -> '{target}'"
    return {f"test -e {path} ||": [line]}


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


def apt_cache_fresh() -> dict[str, Any]:
    """``apt.update(cache_time=...)`` finds a cache refreshed just now."""

    return stat("/var/lib/apt/periodic/update-success-stamp", mtime=int(time.time()))


def deb_installed(*packages: str) -> dict[str, Any]:
    """``DebPackages`` fact listing ``packages`` as installed."""

    return {"dpkg -l": [f"ii  {name}  1.0  all  {name}" for name in packages]}


def venv(path: str) -> dict[str, Any]:
    """A venv at ``path`` with a working (executable) ``bin/python``."""

    return {f"test -x {path}/bin/python": ["present"]}


def accounts(
    users: dict[str, str], groups: tuple[str, ...] = (), *, shell: str = "/usr/sbin/nologin"
) -> dict[str, Any]:
    """``Users`` and ``Groups`` facts: each user (name -> home) with a same-named group, plus ``groups``."""

    passwd = ["root:x:0:0:root:/root:/bin/bash|root|root||!"]
    group_lines = ["root:x:0:"]
    for index, (user, home) in enumerate(users.items()):
        uid = 900 + index
        passwd.append(f"{user}:x:{uid}:{uid}::{home}:{shell}|{user}|{user}||!")
        group_lines.append(f"{user}:x:{uid}:")
    group_lines += [f"{name}:x:{800 + index}:" for index, name in enumerate(groups)]
    return {"cat /etc/group": group_lines, "cat /etc/passwd | cut": passwd}


# An Ubuntu 24.04 amd64 host as the os-release and architecture probes see it.
UBUNTU: dict[str, Any] = {
    **LINUX,
    "command -v apt-get": ["/usr/bin/apt-get"],
    'echo "$ID"': ["ubuntu"],
    ". /etc/os-release": ["noble"],
    "uname -m": ["x86_64"],
    "cat /proc/1/comm": ["systemd"],
}
