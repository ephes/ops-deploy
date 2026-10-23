"""Retention of the Traefik transaction engine's local rollback set.

Every ``binary`` transaction leaves a directory ``/var/lib/traefik-transactions/<id>``
with the rollback artifact (``original``, ``request.json``, ``backup.json``), the
``candidate`` executable and, unless the policy has an external ``rollback_archive``,
the full ``prechange.tar.gz``. A rollback needs only the artifact; the two large files
add up on ``/`` with every update. This program keeps:

- the ``keep_minimal`` newest transactions with their artifact (``candidate`` removed),
- of those, the ``keep_full`` newest with ``prechange.tar.gz`` as well,
- the transaction the host record names, always, with at least its artifact;

and removes older transaction directories. It never touches anything but transaction
directories (named by a UUID, real directories) and, in them, ``candidate`` and
``prechange.tar.gz``; external archives are listed, never removed.

It runs on the host as root, with the standard library only, under
``/usr/bin/python3 -I`` 3.11 or newer, next to the engine (``engine.py``, whose state
directory, lock and record it uses)::

    python3 -I retention.py --request request.json

``request.json``: ``{"keep_minimal": 1-20, "keep_full": 0-keep_minimal, "apply": bool,
"policy": {...}}`` (only the policy's ``rollback_archive`` is read). Without ``apply`` it
is a read-only listing: it takes no lock and writes nothing. With ``apply`` it takes the
engine's lock (a held lock is refused), requires a ``clear`` host record, plans again
under the lock and removes what the plan says, recording ``retention.json`` in each
transaction directory it kept but trimmed. It prints one JSON object; exit 0, or 2 with
``error`` when refused.
"""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

UUID_NAME = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
CANDIDATE, ARCHIVE, MARKER = "candidate", "prechange.tar.gz", "retention.json"
LIMITS = (1, 20)


class Refused(RuntimeError):
    """Retention was refused; nothing was removed."""


def require(ok: object, message: str) -> None:
    if not ok:
        raise Refused(message)


def load_engine() -> ModuleType:
    """The engine next to this program, never one from the import path."""

    path = Path(__file__).resolve().parent / "engine.py"
    spec = importlib.util.spec_from_file_location("traefik_tx_engine", path)
    if spec is None or spec.loader is None:
        raise Refused("cannot load the engine")
    module = importlib.util.module_from_spec(spec)
    # No __pycache__ next to the engine.
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def settings(request: dict[str, Any]) -> tuple[int, int, bool]:
    keep_minimal, keep_full, apply = request.get("keep_minimal"), request.get("keep_full"), request.get("apply")
    if not (type(keep_minimal) is int and LIMITS[0] <= keep_minimal <= LIMITS[1]):
        raise Refused("keep_minimal must be an integer from 1 to 20")
    if not (type(keep_full) is int and 0 <= keep_full <= keep_minimal):
        raise Refused("keep_full must be an integer from 0 to keep_minimal")
    if type(apply) is not bool:
        raise Refused("apply must be true or false")
    return keep_minimal, keep_full, apply


def created_at(directory: Path) -> int:
    """When the transaction began: its ``request.json``, written first and never changed."""

    try:
        info = (directory / "request.json").lstat()
        if stat.S_ISREG(info.st_mode):
            return int(info.st_mtime)
    except FileNotFoundError:
        pass
    return int(directory.lstat().st_mtime)


def transactions(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Transaction directories, newest first, and the names of everything else in ``root``."""

    found: list[dict[str, Any]] = []
    other: list[str] = []
    for path in sorted(root.iterdir()):
        info = path.lstat()
        if not (UUID_NAME.fullmatch(path.name) and stat.S_ISDIR(info.st_mode)):
            other.append(path.name)
            continue
        files: dict[str, int] = {}
        for item in sorted(path.iterdir()):
            entry = item.lstat()
            files[item.name] = entry.st_size if stat.S_ISREG(entry.st_mode) else -1
        found.append({"id": path.name, "created_at": created_at(path), "files": files})
    found.sort(key=lambda item: (item["created_at"], item["id"]), reverse=True)
    return found, other


def plan(found: list[dict[str, Any]], keep_minimal: int, keep_full: int, protected: str | None) -> None:
    """Mark each transaction ``full``, ``minimal`` or ``remove`` and what goes, in place."""

    for index, item in enumerate(found):
        files = item["files"]
        if index < keep_full:
            keep, remove = "full", [name for name in (CANDIDATE,) if files.get(name, -1) >= 0]
        elif index < keep_minimal or item["id"] == protected:
            keep, remove = "minimal", [name for name in (CANDIDATE, ARCHIVE) if files.get(name, -1) >= 0]
        else:
            keep, remove = "remove", sorted(files)
        item["keep"], item["remove"] = keep, remove
        item["protected"] = item["id"] == protected
        if keep == "remove":
            item["free_bytes"] = sum(max(size, 0) for size in files.values())
        else:
            item["free_bytes"] = sum(files[name] for name in remove)


def protected_transaction(engine: ModuleType, record: dict[str, Any] | None) -> str | None:
    """The transaction directory the host record names, if it is one of ours."""

    value = None if record is None else record.get("transaction")
    if not isinstance(value, str):
        return None
    path = Path(value)
    if str(path.parent) != str(engine.STATE_ROOT) or not UUID_NAME.fullmatch(path.name):
        return None
    return path.name


def external(engine: ModuleType, policy: dict[str, Any]) -> dict[str, Any]:
    """The external archives, listed read-only; never created, never removed."""

    found = engine.archive_settings(policy)
    if found is None:
        return {"status": "not_configured", "archives": []}
    root, mount = found
    if not engine.archive_mounted(mount):
        return {"status": "not_mounted", "archives": []}
    if not root.is_dir() or root.is_symlink():
        return {"status": "mounted", "archives": []}
    archives = []
    for path in sorted(root.iterdir()):
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and path.name.endswith(".tar.gz"):
            archives.append({"name": path.name, "bytes": info.st_size, "created_at": int(info.st_mtime)})
    return {"status": "mounted", "archives": archives}


def trim(engine: ModuleType, directory: Path, names: list[str]) -> None:
    """Remove ``names`` (regular files only) from a kept transaction and record it."""

    removed = []
    for name in names:
        path = directory / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode), f"not a regular file: {name}")
        path.unlink()
        removed.append(name)
    marker = directory / MARKER
    before: list[str] = []
    if os.path.lexists(marker):
        value = json.loads(marker.read_text())
        before = value.get("removed", []) if isinstance(value, dict) else []
    record = {"schema": 1, "removed": sorted(set(before) | set(removed)), "updated_at": int(time.time())}
    engine.save(marker, record)


def remove_transaction(directory: Path) -> None:
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode), f"not a directory: {directory.name}")
    require(shutil.rmtree.avoids_symlink_attacks, "safe recursive removal is unavailable")
    shutil.rmtree(directory)


def retention(engine: ModuleType, request: dict[str, Any]) -> dict[str, Any]:
    keep_minimal, keep_full, apply = settings(request)
    policy = request.get("policy")
    if not isinstance(policy, dict):
        raise Refused("policy is required")
    require(os.geteuid() == 0, "root is required")
    root = engine.STATE_ROOT
    outside = external(engine, policy)
    if not os.path.lexists(root):
        return report(apply, None, [], [], outside, root, applied=[] if apply else None)
    require(
        not root.is_symlink() and root.stat().st_uid == 0 and stat.S_IMODE(root.stat().st_mode) == 0o700,
        "unsafe state directory",
    )
    if not apply:
        record = engine.load_state(root / "state.json")
        found, other = transactions(root)
        plan(found, keep_minimal, keep_full, protected_transaction(engine, record))
        return report(apply, record, found, other, outside, root, applied=None)
    with engine.LOCK.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("the transaction lock is held") from None
        record = engine.load_state(root / "state.json")
        require(record is not None, "missing host enrollment")
        require(record["phase"] == "clear", "retention requires a clear host record")
        protected = protected_transaction(engine, record)
        found, other = transactions(root)
        plan(found, keep_minimal, keep_full, protected)
        applied = []
        for item in found:
            directory = root / item["id"]
            if item["keep"] == "remove":
                require(item["id"] != protected, "refusing to remove the recorded transaction")
                remove_transaction(directory)
            elif item["remove"]:
                trim(engine, directory, item["remove"])
            else:
                continue
            applied.append(item["id"])
        return report(apply, record, found, other, outside, root, applied=applied)


def report(
    apply: bool,
    record: dict[str, Any] | None,
    found: list[dict[str, Any]],
    other: list[str],
    outside: dict[str, Any],
    root: Path,
    *,
    applied: list[str] | None,
) -> dict[str, Any]:
    try:
        usage = os.statvfs(root if root.exists() else root.parent)
        available: int | None = usage.f_bavail * usage.f_frsize
    except OSError:
        available = None
    return {
        "schema": 1,
        "apply": apply,
        "phase": None if record is None else record.get("phase"),
        "transactions": found,
        "other": other,
        "external": outside,
        "local_bytes": sum(max(size, 0) for item in found for size in item["files"].values()),
        "free_bytes": sum(item["free_bytes"] for item in found),
        "available_bytes": available,
        "applied": applied,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Retention of the Traefik transaction rollback set.")
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        engine = load_engine()
        request = json.loads(args.request.read_text())
        require(isinstance(request, dict), "invalid request")
        result = retention(engine, request)
    except Exception as exc:  # every failure is reported, none is a traceback
        refused = isinstance(exc, Refused) or type(exc).__name__ == "Refused"
        print(json.dumps({"failed": True, "error": str(exc) if refused else type(exc).__name__}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
