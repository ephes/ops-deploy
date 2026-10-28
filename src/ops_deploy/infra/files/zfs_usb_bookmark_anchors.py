#!/usr/bin/env python3
"""Keep a per-drive incremental anchor for rotating USB replicas as ZFS bookmarks.

After a drive of the rotation replicated successfully, the newest snapshot on
each of its target datasets is the base the next incremental send to that
drive needs. The matching source snapshot is usually pruned by sanoid long
before a rotated drive comes back, so this helper keeps a bookmark of it on the
source (bookmarks hold no data) and records it per drive. syncoid falls back to
a source bookmark whose GUID matches a target snapshot when no common snapshot
remains.

Bookmarks are pruned only when every drive of the rotation has a recorded
anchor for that source dataset, and never an anchor any drive still needs.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Callable, Iterable


ZFS = "zfs"


class AnchorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Entry:
    name: str
    guid: str
    createtxg: int


Runner = Callable[[list[str]], str]


def run_zfs(args: list[str]) -> str:
    result = subprocess.run([ZFS, *args], check=True, capture_output=True, text=True)
    return result.stdout


def _entries(dataset: str, kind: str, separator: str, runner: Runner) -> list[Entry]:
    output = runner(
        ["list", "-H", "-p", "-t", kind, "-o", "name,guid,createtxg", "-d", "1", dataset]
    )
    prefix = f"{dataset}{separator}"
    entries: list[Entry] = []
    for line in output.splitlines():
        try:
            full_name, guid, createtxg = line.split("\t", 2)
        except ValueError:
            continue
        if not full_name.startswith(prefix):
            continue
        try:
            entries.append(Entry(full_name[len(prefix) :], guid, int(createtxg)))
        except ValueError:
            continue
    return sorted(entries, key=lambda entry: entry.createtxg)


def list_snapshots(dataset: str, runner: Runner = run_zfs) -> list[Entry]:
    return _entries(dataset, "snapshot", "@", runner)


def list_bookmarks(dataset: str, runner: Runner = run_zfs) -> list[Entry]:
    return _entries(dataset, "bookmark", "#", runner)


def list_datasets(root: str, recursive: bool, runner: Runner = run_zfs) -> list[str]:
    args = ["list", "-H", "-o", "name", "-t", "filesystem,volume"]
    if recursive:
        args.append("-r")
    args.append(root)
    return [line for line in runner(args).splitlines() if line]


def ensure_anchor(
    source: str, target: str, runner: Runner = run_zfs
) -> dict[str, str] | None:
    """Return the anchor for ``target``, bookmarking its source snapshot if needed.

    The anchor is the newest target snapshot the source still knows as a
    snapshot or bookmark: the base syncoid picks for the next incremental send
    (newer target-only snapshots are rolled back by that send). After a normal
    sync it is simply the newest target snapshot.
    """
    target_snapshots = list_snapshots(target, runner)
    if not target_snapshots:
        print(f"no snapshots on {target}; nothing to anchor", file=sys.stderr)
        return None
    source_snapshots = list_snapshots(source, runner)
    bookmarks = list_bookmarks(source, runner)
    if not source_snapshots and not bookmarks:
        print(f"no snapshots on {source}; nothing to anchor", file=sys.stderr)
        return None

    bookmark_by_guid = {bookmark.guid: bookmark for bookmark in bookmarks}
    snapshot_by_guid = {snapshot.guid: snapshot for snapshot in source_snapshots}
    for candidate in reversed(target_snapshots):
        bookmark = bookmark_by_guid.get(candidate.guid)
        if bookmark is not None:
            return {"guid": candidate.guid, "bookmark": bookmark.name, "snapshot": candidate.name}
        snapshot = snapshot_by_guid.get(candidate.guid)
        if snapshot is not None:
            taken = {existing.name for existing in bookmarks}
            name = snapshot.name
            if name in taken:
                name = f"{snapshot.name}_{snapshot.guid[:6]}"
            runner(["bookmark", f"{source}@{snapshot.name}", f"{source}#{name}"])
            print(f"bookmarked {source}@{snapshot.name} as {source}#{name}")
            return {"guid": candidate.guid, "bookmark": name, "snapshot": candidate.name}

    raise AnchorError(
        f"no snapshot on {target} has a snapshot or bookmark on {source}; "
        "the next incremental send to this drive would fail"
    )


def select_prunable_bookmarks(
    bookmarks: Iterable[Entry], keep_guids: set[str], prefixes: tuple[str, ...]
) -> list[Entry]:
    return [
        bookmark
        for bookmark in bookmarks
        if bookmark.guid not in keep_guids and bookmark.name.startswith(prefixes)
    ]


def load_state(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": 1, "devices": {}}
    if not isinstance(payload, dict) or not isinstance(payload.get("devices"), dict):
        # Refuse to guess: an unreadable anchor record must not enable pruning.
        raise AnchorError(f"anchor state {path} is not a valid anchor record")
    return payload


def write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def sync_anchors(
    *,
    state_path: Path,
    device_name: str,
    rotation: list[str],
    jobs: list[tuple[str, str, bool]],
    prune_prefixes: tuple[str, ...],
    prune: bool = True,
    runner: Runner = run_zfs,
    now: str | None = None,
) -> dict[str, Any]:
    if device_name not in rotation:
        raise AnchorError(f"device {device_name} is not part of the rotation {rotation}")
    if prune and (not prune_prefixes or not all(prune_prefixes)):
        raise AnchorError("prune prefixes must be non-empty strings")

    state = load_state(state_path)
    timestamp = now or datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    device_state = state["devices"].setdefault(device_name, {})
    anchors = device_state.setdefault("datasets", {})

    pairs: list[tuple[str, str]] = []
    for source_root, target_root, recursive in jobs:
        for target in list_datasets(target_root, recursive, runner):
            pairs.append((source_root + target[len(target_root) :], target))

    for source, target in pairs:
        anchor = ensure_anchor(source, target, runner)
        if anchor is None:
            continue
        anchors[source] = {**anchor, "target": target, "recorded_at": timestamp}
    device_state["recorded_at"] = timestamp
    # Record before pruning so a failed prune never loses a fresh anchor.
    write_state(state_path, state)

    if not prune:
        return state
    for source, _target in pairs:
        keep: set[str] = set()
        missing = []
        for name in rotation:
            anchor = state["devices"].get(name, {}).get("datasets", {}).get(source)
            if isinstance(anchor, dict) and anchor.get("guid"):
                keep.add(str(anchor["guid"]))
            else:
                missing.append(name)
        if missing:
            print(
                f"keeping all bookmarks on {source}: no recorded anchor yet for "
                f"{', '.join(missing)}"
            )
            continue
        for bookmark in select_prunable_bookmarks(
            list_bookmarks(source, runner), keep, prune_prefixes
        ):
            runner(["destroy", f"{source}#{bookmark.name}"])
            print(f"destroyed obsolete bookmark {source}#{bookmark.name}")
    return state


def _parse_bool(value: str) -> bool:
    if value in {"true", "false"}:
        return value == "true"
    raise argparse.ArgumentTypeError("expected true or false")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-path", required=True, type=Path)
    parser.add_argument("--device-name", required=True)
    parser.add_argument(
        "--rotation-device",
        action="append",
        required=True,
        dest="rotation",
        help="every drive name of the rotation (repeat)",
    )
    parser.add_argument(
        "--job",
        action="append",
        nargs=3,
        required=True,
        metavar=("SOURCE", "TARGET", "RECURSIVE"),
    )
    parser.add_argument("--prune-prefix", action="append", default=[], dest="prune_prefixes")
    parser.add_argument("--no-prune", action="store_true")
    args = parser.parse_args()
    jobs = [(source, target, _parse_bool(recursive)) for source, target, recursive in args.job]
    try:
        sync_anchors(
            state_path=args.state_path,
            device_name=args.device_name,
            rotation=args.rotation,
            jobs=jobs,
            prune_prefixes=tuple(args.prune_prefixes),
            prune=not args.no_prune,
        )
    except (AnchorError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
