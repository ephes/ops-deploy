"""Bounded metadata reads only: never import or execute anything from the inspected venv."""

import contextlib
import email.parser
import errno
import hashlib
import json
import os
import re
import stat
import sys

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
VERSION = re.compile(
    r"(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?"
    r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*)?\Z"
)
PYTHON = re.compile(r"3\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
MAX_ENTRIES = 8192
MAX_DISTRIBUTIONS = 4096
MAX_METADATA = 256 * 1024
MAX_TOTAL = 32 * 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class ObservationError(Exception):
    def __init__(self, reason, status="unknown"):
        self.reason = reason
        self.status = status


def trusted(st, uid, *, symlink=False):
    if st.st_uid not in (0, uid) or (not symlink and st.st_mode & 0o022):
        raise ObservationError("unsafe_owner_or_mode", "refused_untrusted")


@contextlib.contextmanager
def directory(parent, name, uid):
    fd = os.open(name, DIR_FLAGS, dir_fd=parent)
    try:
        trusted(os.fstat(fd), uid)
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def venv_root(path, uid):
    # Every component is opened relative to its already checked parent. Renames
    # cannot redirect a subsequent read through a symlink or a replacement path.
    with contextlib.ExitStack() as stack:
        fd = stack.enter_context(directory(None, "/", uid))
        for part in path.split("/")[1:]:
            fd = stack.enter_context(directory(fd, part, uid))
        yield fd


def read_metadata(parent, name, uid, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        trusted(before, uid)
        if not stat.S_ISREG(before.st_mode):
            raise ObservationError("unsafe_path", "refused_untrusted")
        if before.st_size > limit:
            raise ObservationError("limits_exceeded")
        chunks = []
        remaining = limit + 1
        while remaining:
            data = os.read(fd, min(65536, remaining))
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise ObservationError("changed_during_read")
        body = b"".join(chunks)
        if len(body) > limit:
            raise ObservationError("limits_exceeded")
        return body.decode("utf-8")
    finally:
        os.close(fd)


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def numeric(version):
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
        parts = [int(p) for p in version.split(".")]
        while parts and parts[-1] == 0:
            parts.pop()
        return parts
    return None


def inspect_metadata(root, request):
    uid = request["owner_uid"]
    cfg = {}
    for line in read_metadata(root, "pyvenv.cfg", uid, 16384).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or key in cfg:
            raise ObservationError("malformed_metadata")
        cfg[key] = value.strip()
    versions = {cfg[k] for k in ("version", "version_info") if k in cfg}
    if len(versions) != 1 or cfg.get("include-system-site-packages", "").lower() != "false":
        raise ObservationError("unsupported_layout")
    version = versions.pop()
    if len(version) > 32 or not PYTHON.fullmatch(version):
        raise ObservationError("malformed_metadata")
    observed = {"declared_python": version}
    with directory(root, "bin", uid) as binary:
        entry = os.stat("python", dir_fd=binary, follow_symlinks=False)
        link = stat.S_ISLNK(entry.st_mode)
        trusted(entry, uid, symlink=link)
        if not link and (not stat.S_ISREG(entry.st_mode) or not entry.st_mode & 0o111):
            raise ObservationError("unsupported_layout")
        observed["python_entry"] = "symlink" if link else "regular"
    found = {}
    total = 0
    unsupported = False
    with contextlib.ExitStack() as stack:
        lib = stack.enter_context(directory(root, "lib", uid))
        python = stack.enter_context(directory(lib, "python" + ".".join(version.split(".")[:2]), uid))
        site = stack.enter_context(directory(python, "site-packages", uid))
        # scandir is incremental, unlike listdir: over-limit trees stay bounded.
        with os.scandir(site) as entries:
            for count, entry in enumerate(entries, 1):
                if count > MAX_ENTRIES:
                    raise ObservationError("limits_exceeded")
                if entry.name.endswith((".pth", ".egg-info", ".egg-link")) or any(
                    entry.name == hook or entry.name.startswith(hook + ".")
                    for hook in ("sitecustomize", "usercustomize")
                ):
                    unsupported = True
                if not entry.name.endswith(".dist-info"):
                    continue
                if len(found) >= MAX_DISTRIBUTIONS:
                    raise ObservationError("limits_exceeded")
                with directory(site, entry.name, uid) as metadata:
                    text = read_metadata(metadata, "METADATA", uid, min(MAX_METADATA, MAX_TOTAL - total))
                total += len(text.encode("utf-8"))
                message = email.parser.Parser().parsestr(text, headersonly=True)
                names = message.get_all("Name", [])
                versions = message.get_all("Version", [])
                if message.defects or len(names) != 1 or len(versions) != 1:
                    raise ObservationError("malformed_metadata")
                name, installed = str(names[0]), str(versions[0])
                if not NAME.fullmatch(name) or canonical(name) in found:
                    raise ObservationError("malformed_metadata")
                if len(installed) > 128 or not VERSION.fullmatch(installed):
                    raise ObservationError("uncomparable_version")
                found[canonical(name)] = installed
    identity = hashlib.sha256(json.dumps(sorted(found.items()), separators=(",", ":")).encode()).hexdigest()
    observed.update(distribution_count=len(found), inventory_identity=identity)
    if unsupported:
        return dict(observed, status="unknown", reason="unsupported_layout")
    expected = {canonical(k): v for k, v in request["distributions"].items()}
    uncomparable = False
    newer_distribution = False
    for name in sorted(found.keys() & expected.keys()):
        if found[name] == expected[name]:
            continue
        actual, intended = numeric(found[name]), numeric(expected[name])
        if actual is None or intended is None:
            uncomparable = True
            continue
        if actual > intended:
            newer_distribution = True
    if uncomparable:
        return dict(observed, status="unknown", reason="uncomparable_version")
    if version != request["python_version"]:
        newer = numeric(version) > numeric(request["python_version"])
        return dict(observed, status="recognizable_newer" if newer else "different_inventory", reason="different_python")
    if found == expected:
        return dict(observed, status="matching_candidate", reason="metadata_matches")
    if newer_distribution:
        return dict(observed, status="recognizable_newer", reason="different_distributions")
    return dict(observed, status="different_inventory", reason="different_distributions")


def observe(request):
    try:
        with venv_root(request["venv"], request["owner_uid"]) as root:
            try:
                return inspect_metadata(root, request)
            except FileNotFoundError:
                raise ObservationError("unsupported_layout") from None
    except FileNotFoundError:
        return {"status": "absent", "reason": "absent"}
    except ObservationError as exc:
        return {"status": exc.status, "reason": exc.reason}
    except UnicodeDecodeError:
        return {"status": "unknown", "reason": "malformed_metadata"}
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return {"status": "refused_untrusted", "reason": "unsafe_path"}
        return {"status": "unknown", "reason": "unreadable"}


if __name__ == "__main__":
    print(json.dumps(observe(json.loads(sys.argv[1]))))
