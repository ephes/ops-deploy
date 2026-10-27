"""ssh_guard transactions: every sshd/fail2ban change under one lock, with a timed revert (host side).

Standard library only, run as root under ``/usr/bin/python3 -I``. The deploy
(``ops_deploy.base.ssh_guard`` with ``timed_revert_seconds``) sends a bundle:
the managed files, directories and services and the ordered steps that the
plain deploy would run as pyinfra operations (write a file, install a package,
run a restart, gate, ``sshd -t`` check or reload). Nothing else on the host
writes those files while a transaction is open, so no operation of a pyinfra
run can interleave with the revert.

Commands (``--state-dir`` defaults to ``/var/lib/ops-deploy/ssh-guard-tx``):

``plan --bundle-b64 B``
    Read-only: which steps would run now (JSON). The deploy calls it while
    planning, with this program on stdin.
``run --bundle-b64 B --caller SSH_CONNECTION``
    Under the lock: refuse while a transaction is open or when the generation
    differs from the bundle's ``expect_generation`` (the host changed since
    planning); stage the bundle and a copy of this program, start ``apply`` in
    a transient unit (it survives a lost SSH session), wait for it and print
    its result.
``apply TXID`` (inside ``ssh-guard-tx-apply-<id>.service``)
    Under the lock: snapshot every managed file, directory and service, record
    ``applying`` and start the one-shot revert timer
    ``ssh-guard-tx-revert-<id>.timer`` (``revert TXID`` after the bundle's
    ``revert_after`` seconds) before the first change; then run the steps. A
    failing step reverts at once; success leaves the transaction ``armed``
    with the digests of what it wrote.
``confirm --generation N``
    Under the lock, over an SSH connection opened after the transaction was
    armed: the nearest ``sshd``/``sshd-session`` process above it (that
    connection's own process) must have started after the apply finished, and
    ``SSH_CONNECTION`` must be set and differ from the one that ran ``run``, so
    neither the deploy's session nor a multiplexed older one counts. Then
    ``armed`` -> ``confirmed`` if generation N is the open transaction, on the
    same boot and before its deadline; then stop the timer.
``revert TXID [--reason R]``
    Under the lock: only if TXID is still the open transaction (``applying``,
    ``armed`` or ``reverting``); otherwise nothing. An ``armed`` transaction
    whose files no longer have the digests it recorded was changed by someone
    else since: ``superseded``, nothing restored. Otherwise ``reverting``
    (recorded first), every file back byte for byte with owner and mode (or
    removed), directories the transaction created removed when empty, services
    back to their enabled and active state, then ``reverted`` or, if anything
    failed, ``revert-failed`` (the unit fails). A final status never changes
    again, so a revert fires at most once.
``status``
    The state (JSON), read-only.

Packages a transaction installed stay installed after a revert (their service
is stopped and disabled when it was not there before); ssh is reloaded after
its files were restored and ``sshd -t`` passes, never stopped or started.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

SCHEMA = 1
STATE_DIR = "/var/lib/ops-deploy/ssh-guard-tx"
PYTHON = "/usr/bin/python3"
# Open statuses block every other transaction and every plain deploy.
OPEN = ("staged", "applying", "armed", "reverting")
FINAL = ("unchanged", "aborted", "confirmed", "reverted", "revert-failed", "superseded")
REVERT_MIN, REVERT_MAX = 60, 3600
APPLY_RUNTIME_MAX = 1800
STEP_TIMEOUT = 900
QUIESCE_WAIT = 60
# Where the kernel's views are; options only so that tests can point them at fixtures.
ROOTS = {"proc": Path("/proc"), "cgroup": Path("/sys/fs/cgroup")}
COMMAND_TIMEOUT = 120
KEEP_TRANSACTIONS = 5
STEP_KINDS = ("dir", "file", "absent", "package", "service", "shell")
_ID = re.compile(r"^[a-z0-9-]{1,40}$")
_UNIT = re.compile(r"^[A-Za-z0-9_.@:-]+$")
_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
_TXID = re.compile(r"^[0-9a-f]{32}$")


class TxError(Exception):
    """A refusal or failure with a message for the operator."""


# --- bundle -----------------------------------------------------------------


def _path(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or os.path.normpath(value) != value or value == "/":
        raise TxError(f"bundle: {what} must be a normalised absolute path")
    return value


def _owner(entry: dict[str, Any], what: str) -> None:
    for key in ("uid", "gid", "mode"):
        if not isinstance(entry.get(key), int) or isinstance(entry.get(key), bool) or entry[key] < 0:
            raise TxError(f"bundle: {what} needs an integer {key}")
    if entry["mode"] > 0o7777:
        raise TxError(f"bundle: {what} has an invalid mode")


def validate_bundle(bundle: Any) -> dict[str, Any]:
    """The bundle, checked; anything unexpected is refused before the lock is taken."""

    if not isinstance(bundle, dict) or bundle.get("schema") != SCHEMA:
        raise TxError("bundle: unknown schema")
    after = bundle.get("revert_after")
    if not isinstance(after, int) or isinstance(after, bool) or not REVERT_MIN <= after <= REVERT_MAX:
        raise TxError(f"bundle: revert_after must be {REVERT_MIN}..{REVERT_MAX} seconds")
    generation = bundle.get("expect_generation")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
        raise TxError("bundle: expect_generation must be an integer >= 0")
    files = bundle.get("files")
    dirs = bundle.get("dirs")
    services = bundle.get("services")
    steps = bundle.get("steps")
    if not isinstance(files, list) or not isinstance(dirs, list) or not isinstance(services, list):
        raise TxError("bundle: files, dirs and services must be lists")
    if not isinstance(steps, list) or not steps:
        raise TxError("bundle: no steps")
    managed: dict[str, dict[str, Any]] = {}
    for entry in files:
        if not isinstance(entry, dict):
            raise TxError("bundle: a file entry is not an object")
        path = _path(entry.get("path"), "a file")
        _owner(entry, path)
        if path in managed:
            raise TxError(f"bundle: {path} listed twice")
        managed[path] = entry
    seen_dirs: set[str] = set()
    for entry in dirs:
        if not isinstance(entry, dict):
            raise TxError("bundle: a directory entry is not an object")
        path = _path(entry.get("path"), "a directory")
        _owner(entry, path)
        if path in seen_dirs or path in managed:
            raise TxError(f"bundle: {path} listed twice")
        seen_dirs.add(path)
    roles: set[str] = set()
    for entry in services:
        if not isinstance(entry, dict) or entry.get("role") not in ("fail2ban", "ssh"):
            raise TxError("bundle: a service needs the role fail2ban or ssh")
        if entry["role"] in roles:
            raise TxError(f"bundle: service role {entry['role']} listed twice")
        roles.add(entry["role"])
        if not isinstance(entry.get("unit"), str) or not _UNIT.fullmatch(entry["unit"]):
            raise TxError("bundle: invalid unit name")
        if not isinstance(entry.get("files"), list) or not all(path in managed for path in entry["files"]):
            raise TxError("bundle: a service lists a file that is not managed")
        if entry["role"] == "ssh" and not isinstance(entry.get("check"), str):
            raise TxError("bundle: the ssh service needs its check command")
    ids: set[str] = set()
    for step in steps:
        if not isinstance(step, dict) or step.get("kind") not in STEP_KINDS:
            raise TxError("bundle: unknown step kind")
        step_id = step.get("id")
        if not isinstance(step_id, str) or not _ID.fullmatch(step_id) or step_id in ids:
            raise TxError("bundle: step ids must be unique short names")
        if not isinstance(step.get("name"), str) or not step["name"]:
            raise TxError(f"bundle: step {step_id} has no name")
        kind = step["kind"]
        if kind in ("file", "absent") and _path(step.get("path"), step_id) not in managed:
            raise TxError(f"bundle: step {step_id} writes a file outside the managed set")
        if kind == "file" and not isinstance(step.get("content"), str):
            raise TxError(f"bundle: step {step_id} has no content")
        if kind == "dir" and _path(step.get("path"), step_id) not in seen_dirs:
            raise TxError(f"bundle: step {step_id} creates a directory outside the managed set")
        if kind == "package":
            if not isinstance(step.get("package"), str) or not _PACKAGE.fullmatch(step["package"]):
                raise TxError(f"bundle: step {step_id} has an invalid package")
            if not isinstance(step.get("no_recommends"), bool):
                raise TxError(f"bundle: step {step_id} needs no_recommends")
        if kind == "service" and step.get("unit") not in {entry["unit"] for entry in services}:
            raise TxError(f"bundle: step {step_id} ensures a service outside the managed set")
        if kind == "shell":
            when = step.get("when")
            if not isinstance(step.get("command"), str) or not isinstance(step.get("always"), bool):
                raise TxError(f"bundle: step {step_id} needs command and always")
            if not isinstance(when, list) or not all(isinstance(ref, str) and ref in ids for ref in when):
                raise TxError(f"bundle: step {step_id} may only depend on earlier steps")
            limit = step.get("timeout", STEP_TIMEOUT)
            if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= STEP_TIMEOUT:
                raise TxError(f"bundle: step {step_id} has an invalid timeout")
        ids.add(step_id)
    return bundle


def decode_bundle(encoded: str) -> dict[str, Any]:
    try:
        bundle = json.loads(base64.b64decode(encoded.encode(), validate=True))
    except (binascii.Error, ValueError) as exc:
        raise TxError(f"bundle: unreadable ({type(exc).__name__})") from None
    return validate_bundle(bundle)


# --- host reads ---------------------------------------------------------------


def run(argv: list[str], *, timeout: int = COMMAND_TIMEOUT) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(argv, 125, "", f"{type(exc).__name__}: {exc}")


def run_tree(argv: list[str], *, timeout: int, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run a step in its own process group and kill the whole group afterwards.

    On a timeout, and also after a normal exit, every process left in the
    group (a backgrounded child, a hung dpkg) is killed, so nothing a step
    started keeps changing the host after the step has ended. Processes that
    leave the group (``setsid``) are caught by :func:`quiesce` before a revert.
    """

    # Output goes to files, not pipes: waiting for a pipe's end would also wait
    # for a backgrounded child that holds it.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.Popen(argv, stdout=out, stderr=err, env=env, start_new_session=True)
        except OSError as exc:
            return subprocess.CompletedProcess(argv, 125, "", f"{type(exc).__name__}: {exc}")
        try:
            code = proc.wait(timeout=timeout)
            note = ""
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            code, note = 124, f"\ntimed out after {timeout} s"
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        out.seek(0)
        err.seek(0)
        text = out.read().decode(errors="replace"), err.read().decode(errors="replace") + note
    return subprocess.CompletedProcess(argv, code, *text)


def unit_running(unit: str) -> bool:
    return run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def uptime() -> float:
    """Seconds since boot on the clock ``/proc/<pid>/stat`` start times use."""

    return time.clock_gettime(getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC))


def session_started(proc: Path) -> float | None:
    """Seconds after boot at which this process's SSH connection process started, or None outside SSH.

    The nearest ancestor named ``sshd`` or ``sshd-session`` is forked for this
    connection (OpenSSH 9: the per-connection ``sshd``; 10: ``sshd-session``),
    never earlier than the connection itself.
    """

    tick = os.sysconf("SC_CLK_TCK")
    pid = os.getppid()
    for _ in range(64):
        if pid <= 1:
            return None
        try:
            raw = (proc / str(pid) / "stat").read_text()
            comm = raw[raw.index("(") + 1 : raw.rindex(")")]
            fields = raw[raw.rindex(")") + 2 :].split()
            parent, start = int(fields[1]), int(fields[19])
        except (OSError, ValueError, IndexError):
            return None
        if comm in ("sshd", "sshd-session"):
            return start / tick
        pid = parent
    return None


def boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "unknown"


def file_state(path: str) -> dict[str, Any]:
    """``{"present": False}`` or content (base64), digest, owner and mode of a regular file."""

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {"present": False}
    if not stat.S_ISREG(info.st_mode):
        raise TxError(f"{path} exists but is not a regular file")
    data = Path(path).read_bytes()
    return {
        "present": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "content_b64": base64.b64encode(data).decode(),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }


def fingerprint(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key != "content_b64"}


def dir_ok(entry: dict[str, Any]) -> bool:
    try:
        info = os.lstat(entry["path"])
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        raise TxError(f"{entry['path']} exists but is not a directory")
    return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (entry["uid"], entry["gid"], entry["mode"])


def package_installed(name: str) -> bool:
    result = run(["dpkg-query", "-W", "-f=${Status}", name])
    return result.returncode == 0 and result.stdout.strip() == "install ok installed"


def unit_state(unit: str) -> dict[str, str]:
    active = run(["systemctl", "is-active", unit]).stdout.strip()
    enabled = run(["systemctl", "is-enabled", unit]).stdout.strip()
    load = run(["systemctl", "show", "-p", "LoadState", "--value", unit]).stdout.strip()
    return {"active": active, "enabled": enabled, "load": load}


def file_differs(path: str, content: str, entry: dict[str, Any]) -> bool:
    current = file_state(path)
    if not current["present"]:
        return True
    return (current["sha256"], current["uid"], current["gid"], current["mode"]) != (
        hashlib.sha256(content.encode()).hexdigest(),
        entry["uid"],
        entry["gid"],
        entry["mode"],
    )


def predicted(bundle: dict[str, Any]) -> list[str]:
    """Names of the steps that would run now, as the plain deploy's operations would."""

    files = {entry["path"]: entry for entry in bundle["files"]}
    dirs = {entry["path"]: entry for entry in bundle["dirs"]}
    changed: set[str] = set()
    names = []
    for step in bundle["steps"]:
        kind = step["kind"]
        if kind == "dir":
            hit = not dir_ok(dirs[step["path"]])
        elif kind == "file":
            hit = file_differs(step["path"], step["content"], files[step["path"]])
        elif kind == "absent":
            hit = os.path.lexists(step["path"])
        elif kind == "package":
            hit = not package_installed(step["package"])
        elif kind == "service":
            current = unit_state(step["unit"])
            hit = current["active"] != "active" or current["enabled"] != "enabled"
        else:
            hit = step["always"] or bool(changed.intersection(step["when"]))
        if hit:
            changed.add(step["id"])
            names.append(step["name"])
    return names


# --- state --------------------------------------------------------------------


class Store:
    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self.state_path = self.root / "state.json"

    def tx_dir(self, txid: str) -> Path:
        return self.root / "tx" / txid

    def load(self) -> dict[str, Any]:
        try:
            state = json.loads(self.state_path.read_text())
        except FileNotFoundError:
            return {"status": "none", "generation": 0}
        except ValueError:
            raise TxError(f"{self.state_path} is unreadable; inspect it before any further ssh_guard change") from None
        if not isinstance(state, dict) or not isinstance(state.get("generation"), int):
            raise TxError(f"{self.state_path} is malformed; inspect it before any further ssh_guard change")
        return state

    def save(self, state: dict[str, Any]) -> None:
        """state.json and the one-line ``status`` file the deploy's probe reads, each replaced atomically."""

        state["updated"] = time.time()
        write_atomic(self.state_path, json.dumps(state, indent=1, sort_keys=True).encode(), 0, 0, 0o600)
        line = f"{state['status']} {state['generation']} {state.get('txid', '-')}\n"
        write_atomic(self.root / "status", line.encode(), 0, 0, 0o644)

    @contextlib.contextmanager
    def lock(self, *, wait: float | None) -> Iterator[None]:
        """The transaction lock; ``wait`` None blocks until it is free."""

        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.root / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            deadline = None if wait is None else time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | (0 if deadline is None else fcntl.LOCK_NB))
                    break
                except BlockingIOError:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise TxError("another ssh_guard transaction step holds the lock") from None
                    time.sleep(0.5)
            yield
        finally:
            os.close(fd)


def write_atomic(path: Path, data: bytes, uid: int, gid: int, mode: int) -> None:
    """Write ``data`` next to ``path`` and rename it over; owner and mode set before the rename."""

    temp = path.with_name(f".{path.name}.ssh-guard-tx-{uuid.uuid4().hex[:8]}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            if os.geteuid() == 0 or (uid, gid) != (0, 0):
                os.fchown(handle.fileno(), uid, gid)
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


# --- snapshot and revert ------------------------------------------------------


def snapshot(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "files": {entry["path"]: file_state(entry["path"]) for entry in bundle["files"]},
        "dirs": {entry["path"]: os.path.isdir(entry["path"]) for entry in bundle["dirs"]},
        "services": {entry["unit"]: unit_state(entry["unit"]) for entry in bundle["services"]},
        "packages": {
            step["package"]: package_installed(step["package"]) for step in bundle["steps"] if step["kind"] == "package"
        },
    }


def applied_digests(bundle: dict[str, Any]) -> dict[str, Any]:
    return {entry["path"]: fingerprint(file_state(entry["path"])) for entry in bundle["files"]}


def restore_file(path: str, before: dict[str, Any]) -> bool:
    """Put ``path`` back as it was; True when that changed the file."""

    current = fingerprint(file_state(path))
    if current == fingerprint(before):
        return False
    if before["present"]:
        data = base64.b64decode(before["content_b64"])
        write_atomic(Path(path), data, before["uid"], before["gid"], before["mode"])
    else:
        os.unlink(path)
    return True


def restore_service(unit: str, before: dict[str, str], *, files_changed: bool, errors: list[str]) -> None:
    """fail2ban back to its enabled and active state; restarted onto restored files when it ran before."""

    now = unit_state(unit)
    was_enabled = before["enabled"] == "enabled"
    if was_enabled and now["enabled"] != "enabled":
        action = run(["systemctl", "enable", unit])
    elif not was_enabled and now["enabled"] == "enabled":
        action = run(["systemctl", "disable", unit])
    else:
        action = None
    if action is not None and action.returncode != 0:
        errors.append(f"systemctl enable/disable {unit} failed")
    if before["active"] == "active":
        restart = files_changed or now["active"] != "active"
        if restart and run(["systemctl", "restart", unit]).returncode != 0:
            errors.append(f"systemctl restart {unit} failed")
    elif now["active"] in ("active", "activating", "reloading") and run(["systemctl", "stop", unit]).returncode != 0:
        errors.append(f"systemctl stop {unit} failed")


def stop_timer(state: dict[str, Any]) -> None:
    unit = state.get("timer")
    if isinstance(unit, str) and _UNIT.fullmatch(unit):
        run(["systemctl", "stop", f"{unit}.timer"])


def unit_procs(unit: str) -> Path:
    """``cgroup.procs`` of this process's cgroup, which must be ``unit``'s on the unified (v2) hierarchy.

    Raises TxError otherwise (cgroup v1 or hybrid, or not running in that
    unit): the apply refuses before any change, because it could not find the
    processes a step left behind.
    """

    try:
        lines = (ROOTS["proc"] / "self" / "cgroup").read_text().splitlines()
    except OSError:
        lines = []
    path = next((line[3:] for line in lines if line.startswith("0::")), "")
    procs = ROOTS["cgroup"] / path.lstrip("/") / "cgroup.procs"
    unified = (ROOTS["cgroup"] / "cgroup.controllers").is_file() and len(lines) == 1
    if not (unified and path.endswith(f"/{unit}.service") and procs.is_file()):
        raise TxError(f"not running in {unit}.service on the unified cgroup hierarchy (cgroup v2); unsupported")
    return procs


def quiesce(state: dict[str, Any], *, inside: bool) -> None:
    """Make sure nothing the apply started still runs before anything is restored.

    ``inside`` the apply (a failing step; each step's process group is already
    killed): kill every other process of the apply unit's cgroup, which also
    holds children that left a step's process group. From the timer or by
    hand: kill the apply unit if it is still there and wait until systemd
    reports it gone. Raises TxError when that does not happen.
    """

    unit = state.get("apply_unit")
    if not isinstance(unit, str) or not _UNIT.fullmatch(unit):
        raise TxError("the transaction names no apply unit")
    deadline = time.monotonic() + QUIESCE_WAIT
    if inside:
        procs = unit_procs(unit)
        while True:
            try:
                others = [int(pid) for pid in procs.read_text().split() if int(pid) != os.getpid()]
            except (OSError, ValueError):
                raise TxError(f"cannot read {procs}") from None
            if not others:
                return
            if time.monotonic() > deadline:
                raise TxError("processes the apply started do not end")
            for pid in others:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(pid, signal.SIGKILL)
            time.sleep(0.2)
    while True:
        # Only a successful answer naming a stopped state counts (a gone unit reads "inactive").
        shown = run(["systemctl", "show", "-p", "ActiveState", "--value", f"{unit}.service"])
        if shown.returncode == 0 and shown.stdout.strip() in ("inactive", "failed"):
            return
        if time.monotonic() > deadline:
            raise TxError(f"cannot show that {unit}.service has ended")
        if shown.returncode == 0 and shown.stdout.strip() in ("active", "activating", "deactivating", "reloading"):
            run(["systemctl", "kill", "--signal=SIGKILL", f"{unit}.service"])
        time.sleep(0.5)


def do_revert(store: Store, state: dict[str, Any], bundle: dict[str, Any], reason: str, *, inside: bool = False) -> int:
    """Restore the snapshot; the caller holds the lock and has checked ownership."""

    try:
        quiesce(state, inside=inside)
    except TxError as exc:
        # Nothing restored and the status left as it was: a later revert retries.
        print(f"ssh_guard tx revert: {exc}; nothing restored yet", file=sys.stderr)
        return 1
    txdir = store.tx_dir(state["txid"])
    if state["status"] == "armed":
        try:
            now = applied_digests(bundle)
        except TxError as exc:
            now = {"error": str(exc)}
        if now != state.get("applied"):
            state.update(status="superseded", reason=reason, finished=time.time())
            store.save(state)
            stop_timer(state)
            print("ssh_guard tx: the managed files changed after this transaction; nothing restored", file=sys.stderr)
            return 2
    state.update(status="reverting", reason=reason)
    store.save(state)
    before = json.loads((txdir / "snapshot.json").read_text())
    errors: list[str] = []
    changed: set[str] = set()
    failed: set[str] = set()
    for path, entry in before["files"].items():
        try:
            if restore_file(path, entry):
                changed.add(path)
        except (OSError, TxError, ValueError) as exc:
            failed.add(path)
            errors.append(f"restoring {path}: {type(exc).__name__}")
    for path, existed in sorted(before["dirs"].items(), key=lambda item: -len(item[0])):
        if not existed and os.path.isdir(path):
            with contextlib.suppress(OSError):
                os.rmdir(path)
    for entry in bundle["services"]:
        unit, files = entry["unit"], set(entry["files"])
        if entry["role"] == "fail2ban":
            if files & failed:
                # Files not restored: stop it (removes its bans) rather than load them.
                if run(["systemctl", "stop", unit]).returncode != 0:
                    errors.append(f"systemctl stop {unit} failed")
                continue
            restore_service(unit, before["services"][unit], files_changed=bool(files & changed), errors=errors)
        elif files & failed:
            errors.append(f"{unit} not reloaded: its files were not restored")
        elif files & changed:
            if run(["sh", "-c", entry["check"]]).returncode != 0:
                errors.append(f"{unit} not reloaded: the restored configuration fails its check")
            elif unit_running(unit) and run(["systemctl", "reload", unit]).returncode != 0:
                errors.append(f"systemctl reload {unit} failed")
    left = sorted(name for name, was in before["packages"].items() if not was and package_installed(name))
    state.update(
        status="revert-failed" if errors else "reverted",
        errors=errors,
        packages_left_installed=left,
        finished=time.time(),
    )
    store.save(state)
    stop_timer(state)
    for line in errors:
        print(f"ssh_guard tx revert: {line}", file=sys.stderr)
    return 1 if errors else 0


# --- steps --------------------------------------------------------------------


def apt_install(package: str, no_recommends: bool) -> subprocess.CompletedProcess[str]:
    argv = ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
    argv += ["install", *(["--no-install-recommends"] if no_recommends else []), package]
    return run_tree(argv, timeout=STEP_TIMEOUT, env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"))


def run_step(step: dict[str, Any], bundle: dict[str, Any], changed: set[str]) -> bool:
    """Run one step if needed; True when it ran (changed something). Raises TxError on failure."""

    kind = step["kind"]
    if kind == "dir":
        entry = next(item for item in bundle["dirs"] if item["path"] == step["path"])
        if dir_ok(entry):
            return False
        # Parents as ``mkdir -p`` makes them (umask), the directory itself as configured.
        os.makedirs(entry["path"], mode=0o755, exist_ok=True)
        if os.geteuid() == 0 or (entry["uid"], entry["gid"]) != (0, 0):
            os.chown(entry["path"], entry["uid"], entry["gid"])
        os.chmod(entry["path"], entry["mode"])
        return True
    if kind == "file":
        entry = next(item for item in bundle["files"] if item["path"] == step["path"])
        if not file_differs(step["path"], step["content"], entry):
            return False
        write_atomic(Path(step["path"]), step["content"].encode(), entry["uid"], entry["gid"], entry["mode"])
        return True
    if kind == "absent":
        if not os.path.lexists(step["path"]):
            return False
        os.unlink(step["path"])
        return True
    if kind == "package":
        if package_installed(step["package"]):
            return False
        result = apt_install(step["package"], step["no_recommends"])
        if result.returncode != 0:
            raise TxError(f"{step['name']}: apt-get failed ({result.returncode})")
        return True
    if kind == "service":
        current = unit_state(step["unit"])
        acted = False
        if current["enabled"] != "enabled":
            if run(["systemctl", "enable", step["unit"]]).returncode != 0:
                raise TxError(f"{step['name']}: systemctl enable failed")
            acted = True
        if current["active"] != "active":
            if run(["systemctl", "start", step["unit"]]).returncode != 0:
                raise TxError(f"{step['name']}: systemctl start failed")
            acted = True
        return acted
    if not (step["always"] or changed.intersection(step["when"])):
        return False
    result = run_tree(["sh", "-c", step["command"]], timeout=step.get("timeout", STEP_TIMEOUT))
    if result.returncode != 0:
        sys.stderr.write(result.stderr[-2000:])
        raise TxError(f"{step['name']}: failed ({result.returncode})")
    return True


# --- commands -----------------------------------------------------------------


def program_argv(store: Store, txdir: Path, *args: str) -> list[str]:
    roots = ["--proc-root", str(ROOTS["proc"]), "--cgroup-root", str(ROOTS["cgroup"])]
    return [PYTHON, "-I", str(txdir / "ssh-guard-tx.py"), "--state-dir", str(store.root), *roots, *args]


def cmd_plan(args: argparse.Namespace) -> int:
    bundle = decode_bundle(args.bundle_b64)
    names = predicted(bundle)
    print(json.dumps({"pending": bool(names), "steps": names}))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    bundle = decode_bundle(args.bundle_b64)
    store = Store(args.state_dir)
    with store.lock(wait=60):
        state = store.load()
        if state["status"] in OPEN:
            raise TxError(f"transaction generation {state['generation']} is {state['status']}; confirm or revert it")
        if state["generation"] != bundle["expect_generation"]:
            raise TxError("the host's transaction generation changed since planning; plan again")
        if not predicted(bundle):
            print(json.dumps({"status": "unchanged", "generation": state["generation"]}))
            return 0
        txid = uuid.uuid4().hex
        txdir = store.tx_dir(txid)
        txdir.mkdir(mode=0o700, parents=True)
        write_atomic(txdir / "bundle.json", json.dumps(bundle).encode(), 0, 0, 0o600)
        write_atomic(txdir / "ssh-guard-tx.py", Path(__file__).read_bytes(), 0, 0, 0o700)
        state = {
            "status": "staged",
            "generation": state["generation"] + 1,
            "txid": txid,
            "caller": args.caller,
            "revert_after": bundle["revert_after"],
            "apply_unit": f"ssh-guard-tx-apply-{txid[:12]}",
            "created": time.time(),
        }
        store.save(state)
    unit = state["apply_unit"]
    started = run(
        [
            "systemd-run",
            f"--unit={unit}",
            "--collect",
            f"--property=RuntimeMaxSec={APPLY_RUNTIME_MAX}",
            *program_argv(store, txdir, "apply", txid),
        ]
    )
    if started.returncode != 0:
        with store.lock(wait=60):
            current = store.load()
            if current.get("txid") == txid and current["status"] == "staged":
                current.update(status="aborted", reason="the apply unit did not start", finished=time.time())
                store.save(current)
        raise TxError("systemd-run could not start the apply unit; nothing was changed")
    deadline = time.monotonic() + APPLY_RUNTIME_MAX + 60
    while True:
        current = store.load()
        if current.get("txid") != txid or current["status"] not in ("staged", "applying", "reverting"):
            break
        if time.monotonic() > deadline:
            raise TxError(f"the apply unit {unit} still runs; check 'status' later")
        if current["status"] in ("applying", "reverting") and not unit_running(unit):
            break
        if current["status"] == "staged" and not unit_running(unit):
            # The unit ended (or never ran) without getting past staging: nothing was changed.
            time.sleep(2)
            with store.lock(wait=60):
                current = store.load()
                if current.get("txid") == txid and current["status"] == "staged" and not unit_running(unit):
                    current.update(status="aborted", reason="the apply unit ended before applying")
                    current["finished"] = time.time()
                    store.save(current)
            continue
        time.sleep(1)
    report = {key: current.get(key) for key in ("status", "generation", "txid", "deadline_wall", "changed", "reason")}
    print(json.dumps(report))
    if current["status"] in ("armed", "unchanged"):
        return 0
    if current["status"] in ("applying", "reverting"):
        print(
            "ssh_guard tx: the apply ended without finishing; the revert timer restores the snapshot", file=sys.stderr
        )
    else:
        print(f"ssh_guard tx: transaction ended {current['status']}: {current.get('reason', '')}", file=sys.stderr)
    return 1


def cmd_apply(args: argparse.Namespace) -> int:
    store = Store(args.state_dir)
    with store.lock(wait=120):
        state = store.load()
        if state.get("txid") != args.txid or state["status"] != "staged":
            print("ssh_guard tx apply: not the staged transaction; nothing done", file=sys.stderr)
            return 1
        txdir = store.tx_dir(args.txid)
        bundle = validate_bundle(json.loads((txdir / "bundle.json").read_text()))
        try:
            unit_procs(state["apply_unit"])
            before = snapshot(bundle)
        except TxError as exc:
            state.update(status="aborted", reason=str(exc), finished=time.time())
            store.save(state)
            return 1
        write_atomic(txdir / "snapshot.json", json.dumps(before).encode(), 0, 0, 0o600)
        timer = f"ssh-guard-tx-revert-{args.txid[:12]}"
        state.update(
            status="applying",
            boot_id=boot_id(),
            deadline_monotonic=time.monotonic() + bundle["revert_after"],
            deadline_wall=time.time() + bundle["revert_after"],
            timer=timer,
        )
        store.save(state)
        armed = run(
            [
                "systemd-run",
                f"--unit={timer}",
                f"--on-active={bundle['revert_after']}",
                "--timer-property=AccuracySec=1s",
                *program_argv(store, txdir, "revert", args.txid, "--reason", "timer"),
            ]
        )
        if armed.returncode != 0 or not unit_running(f"{timer}.timer"):
            stop_timer(state)
            state.update(status="aborted", reason="the revert timer could not be armed", finished=time.time())
            store.save(state)
            return 1
        changed: set[str] = set()
        names: list[str] = []
        for step in bundle["steps"]:
            try:
                if run_step(step, bundle, changed):
                    changed.add(step["id"])
                    names.append(step["name"])
            except Exception as exc:  # any failure reverts at once, still under this lock
                state["changed"] = names
                print(f"ssh_guard tx apply: {exc}", file=sys.stderr)
                do_revert(store, state, bundle, f"step failed: {step['name']}", inside=True)
                return 1
        state["changed"] = names
        if not names:
            stop_timer(state)
            state.update(status="unchanged", finished=time.time())
            store.save(state)
            return 0
        if time.monotonic() >= state["deadline_monotonic"]:
            do_revert(store, state, bundle, "the apply outlasted the revert window", inside=True)
            return 1
        state.update(status="armed", applied=applied_digests(bundle), armed_uptime=uptime())
        store.save(state)
    return 0


def cmd_confirm(args: argparse.Namespace) -> int:
    caller = os.environ.get("SSH_CONNECTION", "")
    store = Store(args.state_dir)
    with store.lock(wait=30):
        state = store.load()
        if state["status"] != "armed" or state["generation"] != args.generation:
            raise TxError(f"generation {args.generation} is not armed (now: {state['generation']} {state['status']})")
        if state.get("boot_id") != boot_id():
            raise TxError("the host rebooted since the transaction was armed; its timer is gone: revert it")
        if time.monotonic() >= state["deadline_monotonic"]:
            raise TxError("the revert deadline has passed; the revert runs or ran")
        if not caller or caller == state.get("caller"):
            raise TxError("confirm needs a new SSH connection (SSH_CONNECTION unset or that of the apply)")
        started = session_started(ROOTS["proc"])
        if started is None:
            raise TxError("confirm must run in an SSH session (no sshd process above it)")
        if started <= state["armed_uptime"]:
            raise TxError(
                "this SSH connection was opened before the change; confirm over a new one "
                "(ssh -o ControlMaster=no -o ControlPath=none)"
            )
        state.update(status="confirmed", confirmed_by=caller, finished=time.time())
        store.save(state)
        stop_timer(state)
        prune(store, state)
    print(json.dumps({"status": "confirmed", "generation": state["generation"]}))
    return 0


def cmd_revert(args: argparse.Namespace) -> int:
    store = Store(args.state_dir)
    with store.lock(wait=None):
        state = store.load()
        if state.get("txid") == args.txid and state["status"] == "staged":
            # Staged but never applied (the caller died before starting it): nothing to restore.
            state.update(status="aborted", reason=f"revert ({args.reason}) before apply", finished=time.time())
            store.save(state)
            return 0
        if state.get("txid") != args.txid or state["status"] not in ("applying", "armed", "reverting"):
            print(f"ssh_guard tx revert: nothing to do ({state['status']})")
            return 0
        bundle = validate_bundle(json.loads((store.tx_dir(args.txid) / "bundle.json").read_text()))
        code = do_revert(store, state, bundle, args.reason)
        prune(store, state)
    return code


def cmd_status(args: argparse.Namespace) -> int:
    state = Store(args.state_dir).load()
    hidden = ("applied", "caller", "confirmed_by")
    print(json.dumps({key: value for key, value in state.items() if key not in hidden}, sort_keys=True))
    return 0


def prune(store: Store, state: dict[str, Any]) -> None:
    """Keep the newest transaction directories; the open one is never removed."""

    root = store.root / "tx"
    if not root.is_dir():
        return
    entries = sorted((path for path in root.iterdir() if path.is_dir()), key=lambda path: path.stat().st_mtime)
    for path in entries[:-KEEP_TRANSACTIONS]:
        if path.name != state.get("txid"):
            shutil.rmtree(path, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ssh-guard-tx")
    parser.add_argument("--state-dir", default=STATE_DIR)
    parser.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--bundle-b64", required=True)
    start = sub.add_parser("run")
    start.add_argument("--bundle-b64", required=True)
    start.add_argument("--caller", default="")
    apply = sub.add_parser("apply")
    apply.add_argument("txid")
    confirm = sub.add_parser("confirm")
    confirm.add_argument("--generation", type=int, required=True)
    revert = sub.add_parser("revert")
    revert.add_argument("txid")
    revert.add_argument("--reason", default="manual")
    sub.add_parser("status")
    args = parser.parse_args(argv)
    ROOTS.update(proc=Path(args.proc_root), cgroup=Path(args.cgroup_root))
    if getattr(args, "txid", None) is not None and not _TXID.fullmatch(args.txid):
        parser.error("invalid transaction id")
    handler = {
        "plan": cmd_plan,
        "run": cmd_run,
        "apply": cmd_apply,
        "confirm": cmd_confirm,
        "revert": cmd_revert,
        "status": cmd_status,
    }[args.command]
    try:
        return handler(args)
    except TxError as exc:
        print(f"ssh_guard tx: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
