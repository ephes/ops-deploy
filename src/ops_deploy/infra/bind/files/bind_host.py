"""Host side of ``ops_deploy.infra.bind``; shipped as ``python3 -I -c <source> probe|apply``.

Self-contained (standard library, Python 3.8+). Both commands read one JSON
request on stdin: the candidate files (base64), what to remove and where
named.conf is. The request carries the TSIG key file, so it never travels on a
command line, and nothing here prints file contents or digests.

``probe`` (read-only, while planning) compares each candidate with the host in
memory and prints JSON: per path ``missing``, ``same``, ``differs`` or
``other`` (not a regular file), whether owner and mode match, whether a
``<file>.jnl`` journal exists, and the UFW state. A dynamic zone's file and journal are only looked up, never read.

``apply`` is one transaction under an exclusive lock on the config directory:

1. Decide again what differs (a dynamic zone's file is never replaced: it is
   seeded only when neither it nor its journal exists; a journal without the
   file, or a journal next to a static zone that would change, refuses).
2. Check every new zone file with ``named-checkzone <zone> <file>`` in a
   private temp directory, and refuse a changed static zone whose serial is
   not greater (RFC 1982) than the serial of the file it replaces.
3. Stage the files in a private 0700 directory next to each destination
   (owner, mode, fsync), keep a hard link to every file being replaced, then
   rename them into place in the role's order (keys, options, local, zones,
   seeds, named.conf) and move a keys file that is no longer wanted aside.
4. ``named-checkconf <named.conf>`` on the result. On failure, or on any error
   during 3-4, every replaced file is restored, every new file removed, and
   the command fails: named is not reloaded and keeps its files. SIGHUP,
   SIGINT and SIGTERM are blocked from the first change to the last restore
   and take effect afterwards. A file that cannot be restored keeps its
   backup in the staging directory, which is left in place and refuses every
   later run until it is checked and removed by hand (as does one a killed
   run left behind).

Output of ``named-checkconf`` that names the keys file is withheld.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import grp
import json
import os
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Any, NoReturn

STAGE_PREFIX = ".ops-deploy-bind."
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
SERIAL = re.compile(r"loaded serial ([0-9]+)")
LEFTOVER = (
    "{} holds backups of an interrupted or unrestored run; check the configuration against them "
    "(named-checkconf), then remove the directory by hand"
)


class Refused(Exception):
    pass


def _on_signal(signum: int, frame: Any) -> NoReturn:
    raise SystemExit(128 + signum)


def read_request() -> dict[str, Any]:
    request: dict[str, Any] = json.loads(sys.stdin.read())
    for item in request["files"]:
        item["bytes"] = base64.b64decode(item.pop("data"), validate=True)
    return request


def ids(user: str, group: str) -> tuple[int, int] | None:
    try:
        return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError:
        return None


def lexists(path: str) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def regular_content(path: str) -> tuple[str, os.stat_result | None, bytes | None]:
    """("missing" | "file" | "other", stat, content); never follows a symlink."""

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return "missing", None, None
    except OSError:
        return "other", None, None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return "other", info, None
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return "file", info, b"".join(chunks)
    finally:
        os.close(fd)


def attrs_match(info: os.stat_result, item: dict[str, Any]) -> bool:
    owner = ids(item["user"], item["group"])
    return (
        owner is not None and (info.st_uid, info.st_gid) == owner and stat.S_IMODE(info.st_mode) == int(item["mode"], 8)
    )


def file_state(item: dict[str, Any]) -> dict[str, Any]:
    path = item["path"]
    journal = lexists(path + ".jnl")
    if item["kind"] == "seed":
        # Looked up only: named owns this file and its journal once it exists.
        return {"state": "present" if lexists(path) else "missing", "attrs": True, "journal": journal}
    kind, info, content = regular_content(path)
    if kind != "file" or info is None:
        return {"state": kind, "attrs": False, "journal": journal}
    return {
        "state": "same" if content == item["bytes"] else "differs",
        "attrs": attrs_match(info, item),
        "journal": journal,
    }


def ufw_state() -> str:
    if shutil.which("ufw") is None:
        return "absent"
    result = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, check=False)
    if "Status: inactive" in result.stdout:
        return "inactive"
    if "Status: active" in result.stdout:
        return "active" if ("53/tcp" in result.stdout or "53/udp" in result.stdout) else "active-no-53"
    return "unknown"


def probe(request: dict[str, Any]) -> dict[str, Any]:
    removals = {}
    for path in request["remove"]:
        kind, _, _ = regular_content(path)
        removals[path] = kind
    return {
        "files": {item["path"]: file_state(item) for item in request["files"]},
        "remove": removals,
        "leftovers": leftover_backups(request),
        "ufw": ufw_state() if request.get("ufw") else "unchecked",
    }


# -- apply ------------------------------------------------------------------------


def serial_newer(new: int, old: int) -> bool:
    """RFC 1982 serial number arithmetic: ``new`` is greater than ``old``."""

    difference = (new - old) % (1 << 32)
    return 0 < difference < (1 << 31)


def checkzone(zone: str, path: str) -> tuple[bool, str, int | None]:
    result = subprocess.run(["named-checkzone", zone, path], capture_output=True, text=True, check=False)
    output = (result.stdout + result.stderr).strip()
    match = SERIAL.search(result.stdout)
    return result.returncode == 0, output, int(match.group(1)) if match else None


def decide(request: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """The files to write and the paths to remove; refuses what must not be written."""

    writes = []
    for item in request["files"]:
        state = file_state(item)
        path = item["path"]
        if item["kind"] == "seed":
            if state["state"] == "present":
                continue
            if state["journal"]:
                raise Refused(f"{path} is missing but {path}.jnl exists; seeding it would desynchronise the journal")
            writes.append(item)
            continue
        if state["state"] == "other":
            raise Refused(f"{path} is not a regular file")
        if state["state"] == "same" and state["attrs"]:
            continue
        if item["kind"] == "zone" and state["state"] != "same" and state["journal"]:
            raise Refused(f"{path}.jnl exists; refusing to replace a zone file that has a journal")
        writes.append(item)
    removals = []
    for path in request["remove"]:
        kind, _, _ = regular_content(path)
        if kind == "other":
            raise Refused(f"{path} is not a regular file")
        if kind == "file":
            removals.append(path)
    return writes, removals


def check_zones(writes: list[dict[str, Any]]) -> None:
    """named-checkzone on every new zone file, and the serial rule for static zones."""

    with tempfile.TemporaryDirectory(prefix="ops-deploy-bind-") as scratch:
        for index, item in enumerate(writes):
            if item["kind"] not in ("zone", "seed"):
                continue
            candidate = os.path.join(scratch, str(index))
            with open(candidate, "wb") as handle:
                handle.write(item["bytes"])
            ok, output, new = checkzone(item["zone"], candidate)
            if not ok:
                raise Refused(f"named-checkzone {item['zone']} failed for {item['path']}:\n{output}")
            if item["kind"] != "zone":
                continue
            kind, _, content = regular_content(item["path"])
            if kind != "file" or content == item["bytes"]:
                continue
            ok, _, old = checkzone(item["zone"], item["path"])
            if ok and old is not None and (new is None or not serial_newer(new, old)):
                raise Refused(
                    f"{item['path']}: the new serial {new} is not greater than the current {old}; "
                    "bump the serial (secondaries would not transfer the change)"
                )


def open_directory(path: str) -> int:
    """Descriptor for absolute ``path``, refusing symlinks in every component."""

    fd = os.open("/", DIR_FLAGS)
    try:
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                raise Refused("directory must not contain '..'")
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


def private_dir(dir_fd: int, name: str) -> int | None:
    try:
        fd = os.open(name, DIR_FLAGS, dir_fd=dir_fd)
    except OSError:
        return None
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        os.close(fd)
        return None
    return fd


def remove_stage(dir_fd: int, name: str) -> None:
    fd = private_dir(dir_fd, name)
    if fd is None:
        return
    try:
        for child in os.listdir(fd):
            with contextlib.suppress(OSError):
                os.unlink(child, dir_fd=fd)
    finally:
        os.close(fd)
    with contextlib.suppress(OSError):
        os.rmdir(name, dir_fd=dir_fd)


def leftover_backups(request: dict[str, Any]) -> list[str]:
    """Staging directories next to the managed files that still hold backups (``old-*``)."""

    directories = sorted(
        {os.path.dirname(item["path"]) for item in request["files"]}
        | {os.path.dirname(path) for path in request["remove"]}
    )
    found = []
    for directory in directories:
        try:
            dir_fd = open_directory(directory)
        except (OSError, Refused):
            continue
        try:
            for entry in os.listdir(dir_fd):
                if not entry.startswith(STAGE_PREFIX):
                    continue
                stage_fd = private_dir(dir_fd, entry)
                if stage_fd is None:
                    continue
                try:
                    if any(name.startswith("old-") for name in os.listdir(stage_fd)):
                        found.append(f"{directory}/{entry}")
                finally:
                    os.close(stage_fd)
        finally:
            os.close(dir_fd)
    return found


class Transaction:
    """Stage, swap and (on failure) restore; see the module docstring.

    The caller blocks SIGHUP, SIGINT and SIGTERM for the whole transaction, so
    no change happens without its undo entry. Each undo entry is recorded
    right next to its change, with nothing that can fail in between. A
    staging directory that still holds backups (``old-*``) after a failed
    restore, or after a run that was killed, is kept and refuses the next run.
    """

    def __init__(self) -> None:
        self.dirs: dict[str, tuple[int, str, int]] = {}
        self.undo: list[tuple[str, int, str, str, int]] = []
        self.counter = 0
        self.keep = False

    def stage_dir(self, directory: str) -> tuple[int, str, int]:
        if directory not in self.dirs:
            dir_fd = open_directory(directory)
            try:
                for entry in os.listdir(dir_fd):
                    if not entry.startswith(STAGE_PREFIX):
                        continue
                    leftover = private_dir(dir_fd, entry)
                    if leftover is not None:
                        try:
                            backups = [name for name in os.listdir(leftover) if name.startswith("old-")]
                        finally:
                            os.close(leftover)
                        if backups:
                            raise Refused(LEFTOVER.format(f"{directory}/{entry}"))
                    remove_stage(dir_fd, entry)
                name = STAGE_PREFIX + secrets.token_hex(8)
                os.mkdir(name, 0o700, dir_fd=dir_fd)
                stage_fd = private_dir(dir_fd, name)
                if stage_fd is None or os.listdir(stage_fd):
                    raise Refused(f"staging directory in {directory} was replaced")
            except BaseException:
                os.close(dir_fd)
                raise
            self.dirs[directory] = (dir_fd, name, stage_fd)
        return self.dirs[directory]

    def name(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}{self.counter}"

    def stage(self, item: dict[str, Any]) -> tuple[str, int]:
        """The staged file's name and inode (a rename or link keeps the inode)."""

        directory = os.path.dirname(item["path"])
        _, _, stage_fd = self.stage_dir(directory)
        owner = ids(item["user"], item["group"])
        if owner is None:
            raise Refused(f"{item['user']}:{item['group']} does not exist")
        staged = self.name("new-")
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=stage_fd)
        try:
            view = memoryview(item["bytes"])
            while view:
                view = view[os.write(fd, view) :]
            os.fchown(fd, *owner)
            os.fchmod(fd, int(item["mode"], 8))
            os.fsync(fd)
            inode = os.fstat(fd).st_ino
        finally:
            os.close(fd)
        return staged, inode

    def commit(self, item: dict[str, Any], staged: str, inode: int) -> bool:
        directory, base = os.path.split(item["path"])
        dir_fd, _, stage_fd = self.dirs[directory]
        if item["kind"] == "seed":
            # link() never replaces: a file that appeared meanwhile stays named's.
            try:
                os.link(staged, base, src_dir_fd=stage_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
            except FileExistsError:
                return False
            self.undo.append(("created", dir_fd, base, "", inode))
            return True
        backup = self.name("old-")
        try:
            os.link(base, backup, src_dir_fd=dir_fd, dst_dir_fd=stage_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(staged, base, src_dir_fd=stage_fd, dst_dir_fd=dir_fd)
            self.undo.append(("created", dir_fd, base, "", inode))
            return True
        os.rename(staged, base, src_dir_fd=stage_fd, dst_dir_fd=dir_fd)
        self.undo.append(("replaced", dir_fd, base, backup, inode))
        return True

    def remove(self, path: str) -> None:
        directory, base = os.path.split(path)
        dir_fd, _, stage_fd = self.stage_dir(directory)
        backup = self.name("old-")
        os.rename(base, backup, src_dir_fd=dir_fd, dst_dir_fd=stage_fd)
        self.undo.append(("removed", dir_fd, base, backup, 0))

    def rollback(self) -> list[str]:
        """Undo every change; entries that cannot be undone stay, and their backups are kept."""

        problems = []
        failed = []
        for entry in reversed(self.undo):
            action, dir_fd, base, backup, inode = entry
            stage_fd = next(item[2] for item in self.dirs.values() if item[0] == dir_fd)
            try:
                if action in ("replaced", "removed"):
                    os.rename(backup, base, src_dir_fd=stage_fd, dst_dir_fd=dir_fd)
                elif os.stat(base, dir_fd=dir_fd, follow_symlinks=False).st_ino == inode:
                    os.unlink(base, dir_fd=dir_fd)
            except OSError as exc:
                problems.append(f"{base}: {exc.strerror}")
                failed.append(entry)
        self.undo = list(reversed(failed))
        if failed:
            self.keep = True
        return problems

    def kept(self) -> list[str]:
        """Staging directories left in place for recovery."""

        return [f"{directory}/{name}" for directory, (_, name, _) in self.dirs.items()] if self.keep else []

    def close(self) -> None:
        for dir_fd, name, stage_fd in self.dirs.values():
            with contextlib.suppress(OSError):
                os.fsync(dir_fd)
            os.close(stage_fd)
            if not self.keep:
                remove_stage(dir_fd, name)
            os.close(dir_fd)
        self.dirs.clear()


def checkconf(named_conf: str, keys_file: str) -> tuple[bool, str]:
    result = subprocess.run(["named-checkconf", named_conf], capture_output=True, text=True, check=False)
    lines = (result.stdout + result.stderr).splitlines()
    shown = [line for line in lines if keys_file not in line]
    if len(shown) != len(lines):
        shown.append(f"(output about {keys_file} withheld: it holds key material)")
    return result.returncode == 0, "\n".join(shown)


HANDLED = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


def apply(request: dict[str, Any]) -> dict[str, Any]:
    lock_fd = open_directory(request["lock_dir"])
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Refused(f"another deploy holds the lock on {request['lock_dir']}") from None
        leftovers = leftover_backups(request)
        if leftovers:
            raise Refused(LEFTOVER.format(", ".join(leftovers)))
        writes, removals = decide(request)
        if not writes and not removals:
            return {"written": [], "removed": []}
        check_zones(writes)
        # From the first change to the last restore: a signal waits until the
        # transaction is committed or undone (it is delivered afterwards).
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED)
        try:
            return transact(request, writes, removals)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    finally:
        os.close(lock_fd)


def transact(request: dict[str, Any], writes: list[dict[str, Any]], removals: list[str]) -> dict[str, Any]:
    transaction = Transaction()
    written = []
    try:
        staged = [(item, *transaction.stage(item)) for item in writes]
        for item, name, inode in staged:
            if transaction.commit(item, name, inode):
                written.append(item["path"])
        for path in removals:
            transaction.remove(path)
        ok, output = checkconf(request["named_conf"], request["keys_file"])
        if not ok:
            problems = transaction.rollback()
            if problems:
                raise Refused(
                    "named-checkconf failed and some files could not be restored ("
                    + "; ".join(problems)
                    + "); backups kept in "
                    + ", ".join(transaction.kept())
                    + "; named is not reloaded:\n"
                    + output
                )
            raise Refused(
                "named-checkconf failed; the previous files are restored and named is not reloaded:\n" + output
            )
    except BaseException:
        problems = transaction.rollback()
        if problems:
            sys.stderr.write(
                "bind: restore problems: "
                + "; ".join(problems)
                + "; backups kept in "
                + ", ".join(transaction.kept())
                + "\n"
            )
        raise
    finally:
        transaction.close()
    return {"written": written, "removed": removals}


def main(argv: list[str]) -> int:
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, _on_signal)
    try:
        request = read_request()
        if argv == ["probe"]:
            result = probe(request)
        elif argv == ["apply"]:
            result = apply(request)
        else:
            raise Refused("usage: probe|apply (request on stdin)")
    except Refused as exc:
        sys.stderr.write(f"bind: {exc}\n")
        return 1
    except (OSError, ValueError, KeyError) as exc:
        sys.stderr.write(f"bind: {type(exc).__name__}: {exc}\n")
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
