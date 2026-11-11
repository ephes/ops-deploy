"""Live-state parsing for the ``echoport_remote_command_guard`` role.

``confirm_live.yml`` (rust/echoport-command-guard/PLAN.md 6.2) moves the Rust
guard's pins and prunes old versions only after it has read root's
``authorized_keys``:

* the line of the pinned deploy key must carry exactly the forced command the
  role published (``commands`` below), and
* every version of the Rust guard any line names is protected from the prune
  (``versions``). A line that mentions the install root in any other form, or
  a file that cannot be read, makes the live state unknown (``unknown``), and
  the prune then deletes nothing.

Plain functions, unit-tested in ``tests/test_echoport_remote_command_guard_role.py``.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any

BINARY = "echoport-command-guard"
# The release version grammar of rust_release_binary (plugins/filter/rust_release.py
# VERSION_RE; the unit test keeps both equal).
VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)"
    r"(-[0-9A-Za-z-]+([.][0-9A-Za-z-]+)*)?$"
)
# Characters that may precede a path in a line: start, blank, a quote that
# opens command="…", or an option separator.
_BEFORE_PATH = frozenset(' \t"=,')
# Characters that may end the binary path: blank, the closing quote, end.
_AFTER_PATH = frozenset(' \t"')
# Key types sshd accepts at the start of a line without options (sshkey.c).
_KEY_TYPE_RE = re.compile(
    r"^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp(256|384|521)|"
    r"sk-(ecdsa-sha2-nistp256|ssh-ed25519)@openssh\.com)(-cert-v01@openssh\.com)?$"
)


def echoport_guard_path_chain(path: Any) -> list[str]:
    """``/a/b/c`` → ``['/a/b/c', '/a/b', '/a', '/']`` (every path component)."""

    if not isinstance(path, str) or not path.startswith("/") or posixpath.normpath(path) != path:
        raise ValueError(f"not a normalised absolute path: {path!r}")
    chain = [path]
    while chain[-1] != "/":
        chain.append(posixpath.dirname(chain[-1]))
    return chain


def _split_options(line: str) -> tuple[str, str] | None:
    """Split ``options rest`` at the first blank outside quotes (sshd's rule)."""

    quoted = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quoted and ch == "\\" and line[i + 1 : i + 2] == '"':
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
        elif not quoted and ch in " \t":
            return line[:i], line[i:].lstrip(" \t")
        i += 1
    return None


def _option_commands(options: str) -> list[str] | None:
    """The values of every ``command="…"`` option, or None if malformed."""

    commands: list[str] = []
    quoted = False
    start = 0
    parts: list[str] = []
    i = 0
    while i < len(options):
        ch = options[i]
        if quoted and ch == "\\" and options[i + 1 : i + 2] == '"':
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
        elif ch == "," and not quoted:
            parts.append(options[start:i])
            start = i + 1
        i += 1
    if quoted:
        return None
    parts.append(options[start:])
    for part in parts:
        name, sep, value = part.partition("=")
        if name.lower() != "command":
            continue
        if not sep or len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
            return None
        commands.append(value[1:-1].replace('\\"', '"'))
    return commands


def _parse_key_line(line: str) -> dict[str, Any] | None:
    """``{'type', 'blob', 'commands'}`` of a key line, or None if unparsable."""

    fields = line.split()
    if not fields:
        return None
    if _KEY_TYPE_RE.match(fields[0]):
        options, rest = "", line
    else:
        split = _split_options(line)
        if split is None:
            return None
        options, rest = split
    key = rest.split()
    if len(key) < 2 or not _KEY_TYPE_RE.match(key[0]):
        return None
    commands = _option_commands(options) if options else []
    if commands is None:
        return None
    return {"type": key[0], "blob": key[1], "commands": commands}


def _mentions(line: str, roots: list[str]) -> tuple[set[str], list[str]]:
    """Versions named as ``<root>/<version>/echoport-command-guard`` and the
    other mentions of a root in one line."""

    versions: set[str] = set()
    other: list[str] = []
    for root in roots:
        start = line.find(root)
        while start != -1:
            before = line[start - 1] if start > 0 else " "
            tail = line[start + len(root) :]
            match = re.match(r"/([^/\s\"]+)/" + re.escape(BINARY), tail)
            end = match.end() if match else 0
            after = tail[end] if match and end < len(tail) else " "
            if (
                before in _BEFORE_PATH
                and match
                and VERSION_RE.match(match.group(1))
                and after in _AFTER_PATH
            ):
                versions.add(match.group(1))
            else:
                other.append(line[max(0, start - 8) : start + len(root) + 40])
            start = line.find(root, start + 1)
    return versions, other


def echoport_guard_live_state(content: Any, public_key: Any, roots: Any) -> dict[str, Any]:
    """Parse root's ``authorized_keys`` for ``confirm_live.yml``.

    ``content`` is the file's text (None when it could not be read),
    ``public_key`` the pinned deploy key (``<type> <base64> [comment]``) and
    ``roots`` the spellings of the Rust install root (configured and resolved;
    empty when the Rust inputs are unusable: then no version is read).

    Returns ``{'commands': [...], 'versions': [...], 'unknown': [...]}``:
    ``commands`` holds, for every line with that key, its ``command="…"``
    values (a list per line; ``None`` for a line sshd would not parse is never
    matched); ``versions`` the sorted versions any line names as
    ``<root>/<version>/echoport-command-guard``; ``unknown`` the reasons the
    live state cannot be trusted for a prune (empty when it can).
    """

    unknown: list[str] = []
    if not isinstance(roots, list) or not all(
        isinstance(r, str) and r.startswith("/") and r != "/" and not r.endswith("/") for r in roots
    ):
        raise ValueError(f"roots must be absolute paths: {roots!r}")
    key_fields = public_key.split() if isinstance(public_key, str) else []
    if len(key_fields) < 2 or not _KEY_TYPE_RE.match(key_fields[0]):
        raise ValueError("public_key must be '<type> <base64> [comment]'")
    if not isinstance(content, str):
        return {"commands": [], "versions": [], "unknown": ["cannot read authorized_keys"]}

    commands: list[list[str]] = []
    versions: set[str] = set()
    for number, raw in enumerate(content.split("\n"), start=1):
        line = raw.rstrip("\r")
        if "\0" in line:
            unknown.append(f"line {number} holds a NUL byte")
            continue
        found, other = _mentions(line, roots)
        versions |= found
        unknown.extend(f"line {number} mentions the install root as {snippet!r}" for snippet in other)
        stripped = line.strip(" \t")
        if not stripped or stripped.startswith("#"):
            continue
        parsed = _parse_key_line(stripped)
        if parsed is None:
            continue
        if (parsed["type"], parsed["blob"]) == (key_fields[0], key_fields[1]):
            commands.append(parsed["commands"])
    return {"commands": commands, "versions": sorted(versions), "unknown": unknown}


class FilterModule:
    """Ansible filters of the echoport_remote_command_guard role."""

    def filters(self) -> dict[str, Any]:
        return {
            "echoport_guard_path_chain": echoport_guard_path_chain,
            "echoport_guard_live_state": echoport_guard_live_state,
        }
