"""Validation shared by the NFS server and client deploys: options, paths and ``xprtsec``."""

from __future__ import annotations

import posixpath
import re
from pathlib import PurePosixPath

# ``key`` or ``key=value``; values may hold ``:`` lists (``sec=sys:krb5``).
OPTION = re.compile(r"^[a-z0-9_]+(=[A-Za-z0-9_.:/@-]+)?$")
_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
TLS_MODES = frozenset({"tls", "mtls"})


def option_key(option: str) -> str:
    return option.partition("=")[0]


def check_options(options: tuple[str, ...], what: str) -> tuple[str, ...]:
    """Well-formed ``key[=value]`` options, each key at most once."""

    for option in options:
        if not OPTION.match(option):
            raise ValueError(f"invalid {what} option {option!r}")
    keys = [option_key(option) for option in options]
    if len(set(keys)) != len(keys):
        raise ValueError(f"{what} options must not repeat")
    return options


def wants_tls(options: tuple[str, ...]) -> bool:
    """Whether an ``xprtsec=`` option asks for TLS (``tls`` or ``mtls`` in its list)."""

    return any(
        option_key(option) == "xprtsec" and TLS_MODES & set(option.partition("=")[2].split(":")) for option in options
    )


def check_path(path: PurePosixPath, what: str) -> PurePosixPath:
    """An absolute, normalized path other than ``/`` of letters, digits and ``._-/``."""

    text = str(path)
    if not _PATH.match(text) or posixpath.normpath(text) != text or "//" in text or ".." in path.parts:
        raise ValueError(f"{what} must be an absolute, normalized path of letters, digits, '._-/' other than /")
    return path
