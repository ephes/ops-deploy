"""Sessions filesystem primitives; no application, activation or data-body calls.

Only declared configuration contents may be compared/written. Log/state/auth
metadata probes do not open their bodies. Declarations arrive over protected
stdin in the eventual resource stage, never argv or diagnostic output.
"""

import contextlib
import grp
import hmac
import os
import pathlib
import pwd
import secrets
import stat
import sys


class ResourceError(RuntimeError):
    pass


def resource_path(name):
    path = pathlib.Path(name)
    if path.anchor == "//":
        path = pathlib.Path("/", *path.parts[1:])
    if any(c in str(name) for c in "\x00\r\n") or not path.is_absolute() or path == pathlib.Path("/") or ".." in path.parts:
        raise ResourceError("sessions_resource_path_invalid")
    # Preserve original /etc and /var declarations on Darwin without granting
    # arbitrary ancestor symlinks. Only the standard, root-owned system aliases
    # are translated; their canonical destinations still undergo fd traversal.
    if sys.platform == "darwin":
        for alias in ("etc", "var", "tmp"):
            public = pathlib.Path("/") / alias
            if path == public or public in path.parents:
                target = pathlib.Path("/private") / alias
                info = public.lstat()
                if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or public.resolve() != target:
                    raise ResourceError("sessions_system_alias_invalid")
                path = target / path.relative_to(public)
                break
    return path


@contextlib.contextmanager
def directory_fd(path):
    path = pathlib.Path(path)
    if path != pathlib.Path("/"):
        path = resource_path(str(path))
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = following
        yield current
    finally:
        os.close(current)


def ids(spec):
    return pwd.getpwnam(spec["owner"]).pw_uid, grp.getgrnam(spec["group"]).gr_gid


def directory_matches(spec):
    path = resource_path(spec["path"])
    # Validate every existing ancestor, including when the declared leaf is new.
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ResourceError("sessions_resource_linked_directory")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    uid, gid = ids(spec)
    if not stat.S_ISDIR(info.st_mode):
        raise ResourceError("sessions_resource_directory_invalid")
    if spec.get("strict_existing") and (info.st_uid != uid or stat.S_IMODE(info.st_mode) != spec["mode"]):
        raise ResourceError("sessions_existing_private_directory_unsafe")
    return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, spec["mode"])


def ensure_directory(spec):
    directory_matches(spec)  # refuse unsafe existing private objects before work
    path = resource_path(spec["path"])
    uid, gid = ids(spec)
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for number, component in enumerate(path.parts[1:], 1):
            created = False
            try:
                following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=current)
                following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                created = True
            os.close(current)
            current = following
            if created or number == len(path.parts) - 1:
                info = os.fstat(current)
                if (info.st_uid, info.st_gid) != (uid, gid):
                    os.fchown(current, uid, gid)
                if stat.S_IMODE(info.st_mode) != spec["mode"]:
                    os.fchmod(current, spec["mode"])
    finally:
        os.close(current)


def file_matches(spec, *, content=False, strict=False):
    path = resource_path(spec["path"])
    try:
        with directory_fd(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        return False
    try:
        info = os.fstat(fd)
        uid, gid = ids(spec)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ResourceError("sessions_resource_file_invalid")
        if strict and (info.st_uid != uid or stat.S_IMODE(info.st_mode) != spec["mode"]):
            raise ResourceError("sessions_existing_private_file_unsafe")
        same = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, spec["mode"])
        if content:
            expected = spec["content"].encode()
            # Read only the configured resource's bounded expected length plus
            # one mismatch byte. No credential digest is emitted or persisted.
            chunks, remaining = [], len(expected) + 1
            while remaining:
                piece = os.read(fd, min(remaining, 65536))
                if not piece:
                    break
                chunks.append(piece)
                remaining -= len(piece)
            same = hmac.compare_digest(b"".join(chunks), expected) and same
        return same
    finally:
        os.close(fd)


def put_resource(spec):
    if file_matches(spec, content=True):
        return
    put_bytes(spec, spec["content"].encode())


def put_bytes(spec, body, *, replace=True):
    """Private atomic publication; auth seeding uses no-replace link semantics."""
    path = resource_path(spec["path"])
    uid, gid = ids(spec)
    with directory_fd(path.parent) as parent:
        temporary = ".daybook-sessions-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchown(stream.fileno(), uid, gid)
                os.fchmod(stream.fileno(), spec["mode"])
            if replace:
                os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            else:
                try:
                    os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                except FileExistsError:
                    # A refresh/another original seeder won publication. Never
                    # replace that auth merely to make this deployment current.
                    pass
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass


def ensure_log(spec):
    if file_matches(spec):
        return
    path = resource_path(spec["path"])
    uid, gid = ids(spec)
    with directory_fd(path.parent) as parent:
        try:
            # Existing log: preserve inode and timestamps; no truncate/read/touch.
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ResourceError("sessions_resource_log_invalid")
            if (info.st_uid, info.st_gid) != (uid, gid):
                os.fchown(fd, uid, gid)
            if stat.S_IMODE(info.st_mode) != spec["mode"]:
                os.fchmod(fd, spec["mode"])
        finally:
            os.close(fd)


def remove_declared_file(name):
    path = resource_path(name)
    try:
        with directory_fd(path.parent) as parent:
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise ResourceError("sessions_resource_remove_type_invalid")
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise ResourceError("sessions_resource_remove_type_invalid")
            os.unlink(path.name, dir_fd=parent)
    except FileNotFoundError:
        pass
