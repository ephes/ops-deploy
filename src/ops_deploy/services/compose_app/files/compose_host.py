"""compose_app on the host: files completed with host values, the applied stamp, key copies.

Run as root: ``python3 -I -c <this file> <mode>``. The request is JSON,
base64-encoded on stdin; secrets travel only there. Every line printed names
an item and its state, never content, values or digests.

Modes:

- ``render-probe`` / ``render-apply``: env files whose values include a host
  secret (created once, ``secrets.token_urlsafe``, root 0600; an existing
  file is adopted unchanged) or a uid/gid. Prints ``id <kind>:<name> <id|missing>``
  per requested id, then ``file <path> same|differs`` (probe) or
  ``changed|noop`` (apply). The probe changes nothing; a missing host secret
  makes its file ``differs``.
- ``stamp``: writes ``applied.json`` (the fingerprint, with the ids resolved
  here) in the root-only state directory, then removes the ``pending`` marker.
- ``copy-probe`` / ``copy-apply``: json_key_copy. Probe prints ``same``,
  ``differs`` or ``waiting`` (no key in the source yet); apply waits for the
  key, writes the destination when it differs and prints ``changed|noop``.

Paths are reached without following symlinks; files are replaced atomically.
"""

import base64
import errno
import grp
import json
import os
import pwd
import secrets
import stat
import sys
import time

# What a host secret may contain to sit inside KEY='...' unchanged.
SECRET_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~+/=")


class Fail(Exception):
    pass


def request():
    return json.loads(base64.b64decode(sys.stdin.read()))


def open_dir(path):
    """A descriptor of the absolute directory ``path``, reached without following symlinks."""

    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    for part in [p for p in path.split("/") if p]:
        try:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise Fail(path + " is not a plain directory") from None
            raise
        os.close(fd)
        fd = child
    return fd


def split(path):
    parent, _, name = path.rpartition("/")
    if not name or not parent.startswith("/") and parent != "":
        raise Fail("not an absolute file path: " + path)
    return parent or "/", name


def read(path):
    """(content, stat) of the regular file ``path``, or (None, None) when it does not exist."""

    parent, name = split(path)
    try:
        dfd = open_dir(parent)
    except FileNotFoundError:
        return None, None
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        except FileNotFoundError:
            return None, None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise Fail(path + " is a symlink") from None
            raise
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise Fail(path + " is not a regular file")
            chunks = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks), info
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def write(path, data, mode, uid, gid):
    """Replace ``path`` atomically with ``data`` (owner and mode set before the rename)."""

    parent, name = split(path)
    dfd = open_dir(parent)
    tmp = "." + name + ".ops-deploy-" + secrets.token_hex(6)
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = None
        os.fsync(dfd)
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except FileNotFoundError:
                pass
        os.close(dfd)


def owner_ids(owner, group):
    """(uid, gid), or None when the owner does not exist (yet: a probe before the first deploy)."""

    def resolve(value, lookup):
        if value.isdigit():
            return int(value)
        try:
            return lookup(value)
        except KeyError:
            return None

    ids = resolve(owner, lambda n: pwd.getpwnam(n).pw_uid), resolve(group, lambda n: grp.getgrnam(n).gr_gid)
    return None if None in ids else ids


def required_owner(owner, group):
    ids = owner_ids(owner, group)
    if ids is None:
        raise Fail("no such user or group: " + owner + ":" + group)
    return ids


def same(path, data, mode, ids):
    if ids is None:
        return False
    content, info = read(path)
    return (
        content == data
        and stat.S_IMODE(info.st_mode) == mode
        and info.st_uid == ids[0]
        and info.st_gid == ids[1]
    )


def host_id(kind, name):
    try:
        if kind == "user":
            return pwd.getpwnam(name).pw_uid
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def host_secret(path, size, create):
    content, info = read(path)
    if content is None:
        if not create:
            return None
        os.umask(0o077)
        content = (secrets.token_urlsafe(size) + "\n").encode()
        write(path, content, 0o600, os.geteuid(), os.getegid())
    value = content.decode("utf-8", "replace").strip()
    if not value or not set(value) <= SECRET_CHARS:
        raise Fail("host secret " + path + " holds characters an env file cannot carry")
    return value


def rendered(spec, create):
    parts = []
    for segment in spec["segments"]:
        kind = segment[0]
        if kind == "text":
            parts.append(segment[1])
        elif kind == "host_secret":
            value = host_secret(segment[1], segment[2], create)
            if value is None:
                return None
            parts.append(value)
        else:
            value = host_id(kind, segment[1])
            if value is None:
                if create:
                    raise Fail("no " + kind + " " + segment[1] + " on this host")
                return None
            parts.append(str(value))
    return "".join(parts).encode()


def render(req, apply):
    for kind, name in req["ids"]:
        value = host_id(kind, name)
        print("id", kind + ":" + name, "missing" if value is None else value)
    for spec in req["files"]:
        path, mode = spec["path"], int(spec["mode"], 8)
        ids = required_owner(spec["owner"], spec["group"]) if apply else owner_ids(spec["owner"], spec["group"])
        data = rendered(spec, apply)
        current = data is not None and same(path, data, mode, ids)
        if not apply:
            print("file", path, "same" if current else "differs")
        elif current:
            print("file", path, "noop")
        else:
            write(path, data, mode, *ids)
            print("file", path, "changed")


def stamp(req):
    state = req["state_dir"]
    parent, name = split(state)
    dfd = open_dir(parent)
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=dfd)
        except FileExistsError:
            pass
    finally:
        os.close(dfd)
    ids = {}
    for kind, ref in req["ids"]:
        value = host_id(kind, ref)
        if value is None:
            raise Fail("no " + kind + " " + ref + " on this host")
        ids[kind + ":" + ref] = value
    document = dict(req["stamp"], ids=ids)
    write(state + "/applied.json", (json.dumps(document, sort_keys=True) + "\n").encode(), 0o600, os.geteuid(), os.getegid())
    dfd = open_dir(state)
    try:
        os.unlink("pending", dir_fd=dfd)
    except FileNotFoundError:
        pass
    finally:
        os.close(dfd)
    print("stamp written")


def substituted(value, key):
    if value == "{value}":
        return key
    if isinstance(value, dict):
        return {k: substituted(v, key) for k, v in value.items()}
    if isinstance(value, list):
        return [substituted(v, key) for v in value]
    return value


def source_key(req):
    content, _ = read(req["source"])
    if content is None:
        return None
    try:
        data = json.loads(content.decode("utf-8"))
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    for name in req["keys"]:
        value = data.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def copy(req, apply):
    key = source_key(req)
    deadline = time.monotonic() + req["wait"]
    while apply and key is None and time.monotonic() < deadline:
        time.sleep(1)
        key = source_key(req)
    if key is None:
        if not apply:
            print("waiting")
            return
        raise Fail("no key in " + req["source"] + " after " + str(req["wait"]) + " s")
    data = (json.dumps(substituted(req["template"], key), indent=4) + "\n").encode()
    mode = int(req["mode"], 8)
    ids = required_owner(req["owner"], req["group"]) if apply else owner_ids(req["owner"], req["group"])
    current = same(req["dest"], data, mode, ids)
    if not apply:
        print("same" if current else "differs")
    elif current:
        print("noop")
    else:
        write(req["dest"], data, mode, *ids)
        print("changed")


def main():
    mode = sys.argv[1]
    req = request()
    try:
        if mode in ("render-probe", "render-apply"):
            render(req, mode == "render-apply")
        elif mode == "stamp":
            stamp(req)
        elif mode in ("copy-probe", "copy-apply"):
            copy(req, mode == "copy-apply")
        else:
            raise Fail("unknown mode " + mode)
    except Fail as exc:
        sys.stderr.write("compose_app: " + str(exc) + "\n")
        sys.exit(1)


main()
