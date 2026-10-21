#!/usr/bin/env python3
"""The Python guard as the oracle for its Rust port (PLAN.md 7.2, 7.3).

Two uses:

- a module: ``gen_fixtures.py`` and the Python tests import it to run the
  Python guard's ``check()``, ``Policy`` loading, ``shlex.split`` and
  ``os.path.realpath`` against an injected, virtual environment;
- a long-running process speaking JSON lines on stdin/stdout, which the Rust
  property tests call (``python3 -I oracle.py``). One request per line, one
  response per line, in order. Requests::

    {"op": "ping"}
    {"op": "check", "policy": {...} | "policy_ref": "staging",
     "command": "..." | "command_hex": "...", "env": {...}}
    {"op": "split", "command": "..."}
    {"op": "check_policy", "text": "..." | "hex": "..."}
    {"op": "realpath", "path": "/...", "fs": {"/path": {...}, ...}}

  Every response carries ``"ok"`` (false only for a malformed request, with
  ``"error"``) and echoes ``"id"`` when the request had one.

The environment of a ``check`` (the ``env`` of a fixture case) is::

    {"euid": 0,
     "users": {"postgres": 110, "nobody-here": null},
     "lstat": {"/path": {"kind": "dir", "mode": 448, "uid": 0, "nlink": 2}
                         | {"absent": true}
                         | {"errno": "EACCES", "strerror": "Permission denied"}},
     "realpath": {"/path": "/resolved"}}

Paths missing from ``lstat`` are absent, paths missing from ``realpath``
resolve to ``os.path.normpath(path)`` (the tests' ``identity``), and users
missing from ``users`` (or null) do not exist. ``mode`` holds the permission
bits only; ``kind`` is one of ``reg dir lnk fifo sock chr blk``.

Stdlib only; runs under the hosts' Pythons (3.12 on production, 3.13 on
staging) without a virtualenv.
"""

from __future__ import annotations

import dataclasses
import errno
import hashlib
import importlib.util
import json
import os
import posixpath
import shlex
import stat
import sys
import tempfile
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent
REPO = CRATE.parents[1]
GUARD_PATH = REPO / "roles" / "echoport_remote_command_guard" / "files" / "echoport-remote-command-guard.py"
FIXTURES = CRATE / "fixtures"
POLICY_DIR = FIXTURES / "policies"

DEFAULT_EUID = 0
# Synthetic uids of the users the policies name. Only the guard's own euid
# (root, 0) is meaningful; the others just have to differ from each other.
USERS: dict[str, int] = {
    "root": 0,
    "postgres": 110,
    "gotosocial": 120,
    "homepage": 1004,
    "marina": 1001,
    "python-podcast": 1003,
    "villakunterbunt": 1002,
}
OTHER_UID = 4242  # a uid that belongs to nobody in USERS

# glibc's texts, so fixtures do not depend on the generating machine's libc.
STRERROR: dict[str, str] = {
    "EACCES": "Permission denied",
    "EINVAL": "Invalid argument",
    "EIO": "Input/output error",
    "ELOOP": "Too many levels of symbolic links",
    "ENAMETOOLONG": "File name too long",
    "ENOENT": "No such file or directory",
    "ENOTDIR": "Not a directory",
}

KINDS: dict[str, int] = {
    "reg": stat.S_IFREG,
    "dir": stat.S_IFDIR,
    "lnk": stat.S_IFLNK,
    "fifo": stat.S_IFIFO,
    "sock": stat.S_IFSOCK,
    "chr": stat.S_IFCHR,
    "blk": stat.S_IFBLK,
}
_KIND_BY_FMT = {fmt: name for name, fmt in KINDS.items()}


def load_guard() -> types.ModuleType:
    """Import guard.py from the role, as the tests do."""
    spec = importlib.util.spec_from_file_location("echoport_remote_command_guard_oracle", GUARD_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up
    spec.loader.exec_module(module)
    return module


GUARD: Any = load_guard()


def guard_sha256() -> str:
    return hashlib.sha256(GUARD_PATH.read_bytes()).hexdigest()


# --- encoding -----------------------------------------------------------------


def encode_stat(st: os.stat_result) -> dict[str, Any]:
    kind = _KIND_BY_FMT.get(stat.S_IFMT(st.st_mode))
    if kind is None:
        raise ValueError(f"unknown file type in mode {st.st_mode:o}")
    return {"kind": kind, "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "nlink": st.st_nlink}


def make_stat(kind: str, mode: int, uid: int, nlink: int = 1) -> os.stat_result:
    return os.stat_result((KINDS[kind] | mode, 1, 1, nlink, uid, 0, 0, 0, 0, 0))


def lstat_error(name: str) -> OSError:
    code = getattr(errno, name)
    if code == errno.ENOENT:
        return FileNotFoundError(code, STRERROR[name])
    return OSError(code, STRERROR[name])


def decode_lstat(entry: dict[str, Any]) -> os.stat_result:
    """An lstat entry of an env as a result (or the exception it raises)."""
    if entry.get("absent"):
        raise lstat_error("ENOENT")
    if "errno" in entry:
        raise lstat_error(entry["errno"])
    return make_stat(entry["kind"], entry["mode"], entry["uid"], entry["nlink"])


def encode_lstat_outcome(call: Callable[[], os.stat_result]) -> dict[str, Any]:
    try:
        return encode_stat(call())
    except FileNotFoundError:
        return {"absent": True}
    except OSError as exc:
        name = errno.errorcode.get(exc.errno or 0)
        if name is None or name not in STRERROR:
            raise ValueError(f"lstat raised an errno the fixtures cannot express: {exc!r}") from exc
        return {"errno": name, "strerror": exc.strerror}


def encode_redirect(redirect: Any) -> dict[str, Any] | None:
    if redirect is None:
        return None
    return {"directory": redirect.directory, "name": redirect.name, "owners": list(redirect.owners)}


def encode_decision(decision: Any) -> dict[str, Any]:
    return {
        "verdict": "allowed",
        "argv": list(decision.argv),
        "umask": decision.umask,
        "stdin": encode_redirect(decision.stdin),
        "stdout": encode_redirect(decision.stdout),
    }


def normalize_policy(policy: Any) -> dict[str, Any]:
    """A Policy (of any loaded guard module) as plain, ordered JSON."""
    out: dict[str, Any] = {}
    for f in dataclasses.fields(policy):
        value = getattr(policy, f.name)
        if isinstance(value, (set, frozenset)):
            out[f.name] = sorted(value)
        elif isinstance(value, dict):
            out[f.name] = {k: value[k] for k in sorted(value)}
        elif f.name == "path_roots":
            out[f.name] = [[root, owner] for root, owner in value]
        elif f.name == "sqlite_snapshots":
            out[f.name] = [{"database": s.database, "owner": s.owner, "temp_dir": s.temp_dir} for s in value]
        else:
            out[f.name] = list(value)
    return out


def decode_command(request: dict[str, Any]) -> str:
    """The command as main() sees it: SSH_ORIGINAL_COMMAND, surrogateescape-decoded."""
    if "command_hex" in request:
        return bytes.fromhex(request["command_hex"]).decode("utf-8", "surrogateescape")
    return request["command"]


# --- the virtual environment ----------------------------------------------------


@dataclasses.dataclass
class Scenario:
    """What the guard sees of a host: its euid, users, lstat and realpath."""

    euid: int = DEFAULT_EUID
    users: dict[str, int | None] = dataclasses.field(default_factory=lambda: dict(USERS))
    lstat: Callable[[str], os.stat_result] | None = None
    realpath: Callable[[str], str] | None = None

    @classmethod
    def from_env(cls, env: dict[str, Any] | None) -> Scenario:
        """The scenario a fixture env describes (defaults for everything unlisted)."""
        env = env or {}
        lstat_map = env.get("lstat") or {}
        realpath_map = env.get("realpath") or {}

        def lstat(path: str) -> os.stat_result:
            return decode_lstat(lstat_map.get(path, {"absent": True}))

        def realpath(path: str) -> str:
            return realpath_map.get(path, os.path.normpath(path))

        return cls(euid=env.get("euid", DEFAULT_EUID), users=dict(env.get("users") or {}), lstat=lstat,
                   realpath=realpath)


class Recorder:
    """Runs check() in a scenario and records every query it makes."""

    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.lstat_seen: dict[str, dict[str, Any]] = {}
        self.realpath_seen: dict[str, str] = {}
        self.users_seen: dict[str, int | None] = {}

    def lstat(self, path: str) -> os.stat_result:
        base = self.scenario.lstat or (lambda p: decode_lstat({"absent": True}))
        outcome = encode_lstat_outcome(lambda: base(path))
        previous = self.lstat_seen.setdefault(path, outcome)
        assert previous == outcome, f"lstat({path!r}) is not a function of the path"
        return decode_lstat(outcome)

    def realpath(self, path: str) -> str:
        base = self.scenario.realpath or os.path.normpath
        resolved = base(path)
        assert isinstance(resolved, str)
        previous = self.realpath_seen.setdefault(path, resolved)
        assert previous == resolved, f"realpath({path!r}) is not a function of the path"
        return resolved

    def getpwnam(self, name: str) -> Any:
        uid = self.scenario.users.get(name)
        self.users_seen[name] = uid
        if uid is None:
            raise KeyError(f"getpwnam(): name not found: {name!r}")
        return types.SimpleNamespace(pw_name=name, pw_uid=uid)

    def geteuid(self) -> int:
        return self.scenario.euid

    def env(self) -> dict[str, Any]:
        return {
            "euid": self.scenario.euid,
            "users": dict(sorted(self.users_seen.items())),
            "lstat": dict(sorted(self.lstat_seen.items())),
            "realpath": dict(sorted(self.realpath_seen.items())),
        }


class _OsProxy:
    """The guard's `os`: the real module, except for a recorded `geteuid`."""

    def __init__(self, geteuid: Callable[[], int]) -> None:
        self.geteuid = geteuid

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)


class _GuardPatch:
    """Point the oracle guard's `os.geteuid` and `pwd.getpwnam` at a Recorder.

    Only the guard module's globals change; the real os and pwd modules stay
    as they are.
    """

    def __init__(self, recorder: Recorder) -> None:
        self.recorder = recorder

    def __enter__(self) -> None:
        self.saved = (GUARD.os, GUARD.pwd)
        GUARD.os = _OsProxy(self.recorder.geteuid)
        GUARD.pwd = types.SimpleNamespace(getpwnam=self.recorder.getpwnam)

    def __exit__(self, *exc: object) -> None:
        GUARD.os, GUARD.pwd = self.saved


def run_check(policy: Any, command: str, scenario: Scenario) -> tuple[dict[str, Any], dict[str, Any]]:
    """(expected, env): the guard's decision and every query it made."""
    recorder = Recorder(scenario)
    with _GuardPatch(recorder):
        try:
            expected = encode_decision(GUARD.check(command, policy, realpath=recorder.realpath, lstat=recorder.lstat))
        except GUARD.Refused as exc:
            expected = {"verdict": "refused", "reason": str(exc)}
        except OSError as exc:
            # main() refuses these too ("refused from ...: <exc>").
            expected = {"verdict": "refused", "reason": str(exc)}
        except Exception as exc:  # noqa: BLE001 - main() would crash: no exec
            expected = {"verdict": "error", "error_type": type(exc).__name__, "message": str(exc)}
    return expected, recorder.env()


def check_policy_bytes(data: bytes) -> dict[str, Any]:
    """`--check-policy` on a file with these bytes (load_policy, as main() calls it)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "policy.json")
        with open(path, "wb") as handle:
            handle.write(data)
        try:
            policy = GUARD.load_policy(path)
        except GUARD._POLICY_ERRORS as exc:
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}
    return {"ok": True, "normalized": normalize_policy(policy)}


def load_policy_ref(name: str) -> Any:
    return GUARD.load_policy(str(POLICY_DIR / f"{name}.json"))


def split(command: str) -> dict[str, Any]:
    try:
        return {"tokens": shlex.split(command)}
    except ValueError as exc:
        return {"error": str(exc)}


# --- realpath over a virtual filesystem ---------------------------------------


class _FsPatch:
    """Point os.lstat/os.readlink (as posixpath uses them) at a virtual tree."""

    def __init__(self, fs: dict[str, dict[str, Any]]) -> None:
        self.fs = fs

    def lstat(self, path: Any) -> os.stat_result:
        path = os.fsdecode(path)
        entry = self.fs.get(path)
        if entry is None:
            # A missing parent is ENOENT; a parent that is not a directory is ENOTDIR.
            parent = posixpath.dirname(path)
            while parent not in ("", "/"):
                parent_entry = self.fs.get(parent)
                if parent_entry is not None and parent_entry.get("kind") not in (None, "dir", "lnk"):
                    raise lstat_error("ENOTDIR")
                parent = posixpath.dirname(parent)
            if path == "/":
                return make_stat("dir", 0o755, 0, 2)
            raise lstat_error("ENOENT")
        return decode_lstat(entry)

    def readlink(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        raw = path
        path = os.fsdecode(path)
        entry = self.fs.get(path)
        if entry is None:
            raise lstat_error("ENOENT")
        if entry.get("kind") != "lnk":
            raise lstat_error("EINVAL")
        target = entry["target"]
        return os.fsencode(target) if isinstance(raw, bytes) else target

    def __enter__(self) -> None:
        self.saved = (os.lstat, os.readlink)
        os.lstat = self.lstat  # type: ignore[assignment]
        os.readlink = self.readlink  # type: ignore[assignment]

    def __exit__(self, *exc: object) -> None:
        os.lstat, os.readlink = self.saved  # type: ignore[assignment]


def realpath(path: str, fs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """os.path.realpath (non-strict) of this Python over a virtual tree."""
    if not path.startswith("/"):
        raise ValueError("realpath needs an absolute path")
    with _FsPatch(fs):
        try:
            return {"resolved": os.path.realpath(path)}
        except OSError as exc:
            return {"error": {"errno": errno.errorcode.get(exc.errno or 0, "?"), "strerror": exc.strerror}}


# --- server ---------------------------------------------------------------------


def handle(request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    if op == "ping":
        return {"guard_sha256": guard_sha256(), "python": list(sys.version_info[:3])}
    if op == "check":
        if "policy_ref" in request:
            policy = load_policy_ref(request["policy_ref"])
        else:
            policy = GUARD.Policy.from_dict(request["policy"])
        expected, env = run_check(policy, decode_command(request), Scenario.from_env(request.get("env")))
        return {"expected": expected, "env": env}
    if op == "split":
        return split(request["command"])
    if op == "check_policy":
        data = bytes.fromhex(request["hex"]) if "hex" in request else request["text"].encode("utf-8")
        return {"expected": check_policy_bytes(data)}
    if op == "realpath":
        return realpath(request["path"], request.get("fs") or {})
    raise ValueError(f"unknown op: {op!r}")


def serve(stdin: Any = None, stdout: Any = None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        if not line.strip():
            continue
        request: dict[str, Any] = {}
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise TypeError("a request is a JSON object")
            response = {"ok": True, **handle(request)}
        except Exception as exc:  # noqa: BLE001 - report, keep serving
            response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        if isinstance(request, dict) and "id" in request:
            response["id"] = request["id"]
        stdout.write(json.dumps(response, ensure_ascii=True) + "\n")
        stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(serve())
