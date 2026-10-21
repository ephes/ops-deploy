"""Sync Vaultwarden's SMTP settings into its data/config.json, as vaultwarden_deploy does.

Settings saved in the admin panel land in config.json and override the
environment file, so the role merges its SMTP settings into that file when it
exists. The vaultwarden deploy runs this on the host as root with
``python3 -I -c <this source> check|apply`` and a JSON request on stdin::

    {"path": "...", "owner": "vaultwarden", "group": "vaultwarden",
     "settings": {"smtp_host": "...", ...}}

``check`` (read-only) prints ``absent`` (no config.json: nothing to sync),
``current`` (every setting already has the requested value and type, and the
file is owned by owner:group with mode 0600) or ``pending``. ``apply`` keeps
every other key: when a setting differs it writes the merged object the way
Ansible's ``to_nice_json`` does (sorted keys, indent 4, ASCII escapes, no
final newline) through a temporary file renamed over config.json, owner:group
0600; when only owner or mode differ it fixes those. It prints what it did.

The file holds the admin token and SMTP password once the admin panel saved
them: nothing here prints, logs or passes on its content, also not in errors.
A symlink, a non-regular file (a FIFO included, opened without blocking),
invalid JSON or JSON that is not an object fail.
The source has no backslashes: it travels on a command line that a fish login
shell must not change.
"""

import grp
import json
import os
import pwd
import stat
import sys
import tempfile

MODE = 0o600
NEWLINE = chr(10)


def fail(message):
    sys.stderr.write("vaultwarden config.json: " + message + NEWLINE)
    sys.exit(1)


def canonical(value):
    # Type-strict: true and 1, 587 and 587.0, "587" and 587 all differ.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def nice_json(value):
    # Ansible's to_nice_json: json.dumps(indent=4, sort_keys=True, separators=(",", ": ")).
    return json.dumps(value, indent=4, sort_keys=True, separators=(",", ": "))


def open_config(path):
    """A read-only descriptor of the regular file at path, or None when it is missing."""

    # O_NONBLOCK: opening a FIFO must not wait for a writer before fstat can refuse it.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        fail("cannot be opened without following a symlink (" + (exc.strerror or "error") + ")")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        fail("is not a regular file")
    return fd


def load(fd):
    with os.fdopen(fd, "rb", closefd=False) as handle:
        raw = handle.read()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        fail("is not valid JSON")
    if not isinstance(data, dict):
        fail("is not a JSON object")
    return data


def ids(request):
    try:
        uid = pwd.getpwnam(request["owner"]).pw_uid
    except KeyError:
        fail("owner " + request["owner"] + " does not exist")
    try:
        gid = grp.getgrnam(request["group"]).gr_gid
    except KeyError:
        fail("group " + request["group"] + " does not exist")
    return uid, gid


def write(path, merged, uid, gid):
    fd, temp = tempfile.mkstemp(prefix=".config.json.ops-deploy-", dir=os.path.dirname(path))
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(nice_json(merged).encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass
        raise


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "apply"):
        fail("usage: check|apply with the request on stdin")
    action = sys.argv[1]
    request = json.loads(sys.stdin.read())
    path = request["path"]
    settings = request["settings"]
    if not isinstance(settings, dict) or not settings:
        fail("the request has no settings")
    fd = open_config(path)
    if fd is None:
        print("absent")
        return
    try:
        current = load(fd)
        info = os.fstat(fd)
        uid, gid = ids(request)
        merged = dict(current)
        merged.update(settings)
        content_ok = canonical(current) == canonical(merged)
        attributes_ok = info.st_uid == uid and info.st_gid == gid and stat.S_IMODE(info.st_mode) == MODE
        if action == "check":
            print("current" if content_ok and attributes_ok else "pending")
            return
        if not content_ok:
            write(path, merged, uid, gid)
            print("rewritten")
        elif not attributes_ok:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, MODE)
            print("owner and mode fixed")
        else:
            print("current")
    finally:
        os.close(fd)


main()
