"""One original root forced-command key; unrelated authorization remains in RAM only."""

import base64
import json
import os
import re
import stat
import struct
import sys
import tempfile
from pathlib import Path


def admit(path):
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)) or ".." in path.parts:
        raise ValueError("invalid authorization path")
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("linked authorization path")
        if part == path and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024):
            raise ValueError("invalid existing authorization metadata")


def key_fields(content):
    if not isinstance(content, str) or "\n" in content.strip() or "\r" in content or "\0" in content:
        raise ValueError("invalid source public key")
    fields = content.strip().split()
    if len(fields) < 2 or fields[0] not in (
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ):
        raise ValueError("unsupported source key")
    raw = base64.b64decode(fields[1], validate=True)
    if len(raw) < 4:
        raise ValueError("invalid source key wire shape")
    count = struct.unpack(">I", raw[:4])[0]
    if raw[4 : 4 + count] != fields[0].encode():
        raise ValueError("invalid source key wire type")
    return fields[:2]


def candidate(original, v):
    kind, value = key_fields(v["key"])
    if not re.fullmatch(r"/[A-Za-z0-9_./+-]+", v["command"]) or ".." in Path(v["command"]).parts:
        raise ValueError("invalid forced-command path")
    if any(c in v["comment"] for c in "\0\r\n"):
        raise ValueError("invalid source key comment")
    desired = (
        'command="'
        + v["command"]
        + '",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding '
        + kind
        + " "
        + value
        + " "
        + v["comment"]
        + "\n"
    )
    rows = []
    found = False
    for row in original.splitlines(keepends=True):
        if row.lstrip().startswith("#") or not row.strip():
            rows.append(row)
            continue
        # Locate identity using OpenSSH's sshkey_advance_past_options rule,
        # never POSIX shell quoting or free-form comment tokens. Only a
        # backslash followed by a double quote skips both bytes.
        line = row.rstrip("\r\n").lstrip(" \t")
        fields = re.split(r"[ \t]+", line, maxsplit=2)
        selected = fields[:2] == [kind, value]
        if not selected:
            offset = 0
            quoted = False
            while offset < len(line) and (quoted or line[offset] not in " \t"):
                if line[offset] == chr(92) and line[offset + 1 : offset + 2] == '"':
                    offset += 2
                    continue
                if line[offset] == '"':
                    quoted = not quoted
                offset += 1
            fields = re.split(r"[ \t]+", line[offset:].lstrip(" \t"), maxsplit=2)
            selected = not quoted and fields[:2] == [kind, value]
        if selected:
            if not found:
                # The complete raw line must contain exactly the six original
                # literal tokens. The permitted command path cannot contain a
                # comma/quote/space; keeping its quotes is therefore stricter
                # than interpreting arbitrary OpenSSH option syntax.
                suffix = r"[ \t]+" + re.escape(v["comment"]) if v["comment"] else ""
                raw = re.fullmatch(
                    r"[ \t]*(?P<options>[^ \t\r\n]+)[ \t]+"
                    + re.escape(kind)
                    + r"[ \t]+"
                    + re.escape(value)
                    + suffix
                    + r"[ \t]*",
                    row.rstrip("\r\n"),
                )
                options = raw.group("options").split(",") if raw else []
                wanted = {
                    'command="' + v["command"] + '"',
                    "no-agent-forwarding",
                    "no-port-forwarding",
                    "no-pty",
                    "no-user-rc",
                    "no-X11-forwarding",
                }
                policy_equal = len(options) == len(wanted) and set(options) == wanted
                rows.append(row if raw is not None and policy_equal else desired)
                found = True
        else:
            rows.append(row)
    if not found:
        if rows and not rows[-1].endswith("\n"):
            rows[-1] += "\n"
        rows.append(desired)
    return "".join(rows)


def main():
    if os.geteuid() != 0:
        raise ValueError("existing root identity required")
    v = json.load(sys.stdin)
    target = Path(v["path"])
    admit(target)
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        original = ""
        info = None
    else:
        try:
            info = os.fstat(fd)
            original = os.read(fd, 4 * 1024 * 1024 + 1).decode()
        finally:
            os.close(fd)
    desired = candidate(original, v)
    metadata = info is not None and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o600)
    pending = original != desired or not metadata
    if sys.argv[1] == "check":
        print("pending" if pending else "current")
        return
    if sys.argv[1] != "apply":
        raise ValueError("unknown authorization action")
    if not pending:
        print("current")
        return
    admit(target)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if original == desired:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
    else:
        fd, temporary = tempfile.mkstemp(prefix=".backup-authorized-key-", dir=target.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(desired)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchown(stream.fileno(), 0, 0)
                os.fchmod(stream.fileno(), 0o600)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    print("current")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Declared backup forced-command authorization failed; keys/file content suppressed", file=sys.stderr)
        raise SystemExit(2) from None
