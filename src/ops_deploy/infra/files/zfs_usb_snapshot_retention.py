#!/usr/bin/env python3
"""Prune old managed target-only snapshots before USB replication.

Target snapshots whose GUID is still held by a source snapshot or bookmark are
incremental anchors (for example of a rotated drive) and are never pruned.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import subprocess
import time
from typing import Iterable


@dataclass(frozen=True)
class Snapshot:
    name: str
    creation_epoch: int
    guid: str


def _snapshot_name(dataset: str, full_name: str, separator: str = "@") -> str | None:
    prefix = f"{dataset}{separator}"
    return full_name[len(prefix) :] if full_name.startswith(prefix) else None


def dataset_exists(dataset: str) -> bool:
    result = subprocess.run(
        ["zfs", "list", "-H", "-o", "name", dataset],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def list_snapshots(dataset: str, kind: str = "snapshot") -> list[Snapshot]:
    separator = "#" if kind == "bookmark" else "@"
    result = subprocess.run(
        [
            "zfs",
            "list",
            "-H",
            "-p",
            "-t",
            kind,
            "-o",
            "name,creation,guid",
            "-s",
            "creation",
            "-d",
            "1",
            dataset,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    snapshots: list[Snapshot] = []
    for line in result.stdout.splitlines():
        try:
            full_name, creation_raw, guid = line.split("\t", 2)
            name = _snapshot_name(dataset, full_name, separator)
            if name is not None:
                snapshots.append(
                    Snapshot(name=name, creation_epoch=int(creation_raw), guid=guid)
                )
        except (TypeError, ValueError):
            continue
    return snapshots


def select_prunable_snapshots(
    *,
    source_names: set[str],
    target_snapshots: Iterable[Snapshot],
    cutoff_epoch: int,
    prefixes: tuple[str, ...],
    anchor_guids: frozenset[str] = frozenset(),
) -> list[Snapshot]:
    return [
        snapshot
        for snapshot in target_snapshots
        if snapshot.creation_epoch < cutoff_epoch
        and snapshot.name not in source_names
        and snapshot.guid not in anchor_guids
        and snapshot.name.startswith(prefixes)
    ]


def prune(
    *,
    source: str,
    target: str,
    keep_days: int,
    prefixes: tuple[str, ...],
    now_epoch: int | None = None,
    dry_run: bool = False,
) -> list[Snapshot]:
    if not prefixes or any(
        not isinstance(prefix, str) or not prefix for prefix in prefixes
    ):
        raise ValueError("retention prefixes must be non-empty strings")

    if not dataset_exists(target):
        # Nothing to prune before the first (re)seed creates the target.
        print(f"retention skipped for {target}: target does not exist yet")
        return []

    source_snapshots = list_snapshots(source)
    source_bookmarks = list_snapshots(source, kind="bookmark")
    target_snapshots = list_snapshots(target)
    source_names = {snapshot.name for snapshot in source_snapshots}
    bookmark_guids = frozenset(bookmark.guid for bookmark in source_bookmarks)
    source_anchors = {(snapshot.name, snapshot.guid) for snapshot in source_snapshots}
    target_anchors = {(snapshot.name, snapshot.guid) for snapshot in target_snapshots}
    common = (source_anchors & target_anchors) | {
        anchor for anchor in target_anchors if anchor[1] in bookmark_guids
    }
    if not common:
        raise RuntimeError(
            f"refusing retention for {target}: no common snapshot with {source}"
        )

    current_epoch = now_epoch if now_epoch is not None else int(time.time())
    cutoff_epoch = current_epoch - (keep_days * 86400)
    selected = select_prunable_snapshots(
        source_names=source_names,
        target_snapshots=target_snapshots,
        cutoff_epoch=cutoff_epoch,
        prefixes=prefixes,
        anchor_guids=bookmark_guids,
    )
    for snapshot in selected:
        full_name = f"{target}@{snapshot.name}"
        if dry_run:
            print(f"would destroy {full_name}")
        else:
            subprocess.run(["zfs", "destroy", full_name], check=True)
            print(f"destroyed {full_name}")
    print(
        f"retention complete for {target}: keep_days={keep_days}, "
        f"common={len(common)}, pruned={len(selected)}, dry_run={dry_run}"
    )
    return selected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--keep-days", required=True, type=int)
    parser.add_argument("--prefix", action="append", dest="prefixes", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.keep_days < 1:
        parser.error("--keep-days must be at least 1")
    prune(
        source=args.source,
        target=args.target,
        keep_days=args.keep_days,
        prefixes=tuple(args.prefixes),
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
