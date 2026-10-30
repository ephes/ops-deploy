#!/usr/bin/env python3
"""Preserve one quiesced restore target; never retire a preservation copy."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def check_layout(mutable, sources):
    paths = []
    for value in mutable:
        requested = Path(value)
        resolved = requested.resolve()
        if (
            not requested.is_absolute()
            or resolved == Path("/")
            or requested.is_symlink()
        ):
            raise ValueError(
                "mutable restore paths must be absolute directories, not / or symlinks"
            )
        if any(".pre-restore-" in part for part in resolved.parts):
            raise ValueError("restore must never mutate a pre-restore copy")
        paths.append(resolved)
    for index, path in enumerate(paths):
        for other in paths[index + 1 :] + [Path(value).resolve() for value in sources]:
            if path == other or path in other.parents or other in path.parents:
                raise ValueError(
                    "restore live, staging and source paths must be disjoint"
                )


def mounts():
    result = subprocess.run(
        ["findmnt", "--json", "--output", "TARGET"],
        check=True,
        capture_output=True,
        text=True,
    )

    def targets(entries):
        for entry in entries:
            yield os.path.realpath(entry["target"])
            yield from targets(entry.get("children", []))

    return set(targets(json.loads(result.stdout)["filesystems"]))


def raise_walk_error(error):
    raise error


def size(path):
    # Count apparent and allocated bytes: sparse files and small files both
    # need a conservative space estimate when copied to another filesystem.
    apparent = 0
    capacity = 0
    for root, dirs, files in os.walk(path, followlinks=False, onerror=raise_walk_error):
        for name in (
            ["."] + [name for name in dirs if (Path(root) / name).is_symlink()] + files
        ):
            info = os.lstat(os.path.join(root, name))
            apparent += info.st_size
            capacity += max(info.st_size, info.st_blocks * 512)
    return apparent, capacity


def preflight(live, empty=True):
    requested = Path(live)
    if not requested.is_absolute() or requested == Path("/") or requested.is_symlink():
        raise ValueError(
            "restore target must be an absolute directory, not / or a symlink"
        )
    check_layout([live], [])
    live = requested.resolve()
    if live == Path("/"):
        raise ValueError("resolved restore target must not be /")
    if not live.exists():
        return live, 0, False, 0
    if not live.is_dir():
        raise ValueError("restore target is not a directory")
    mounted = mounts()
    if any(str(target).startswith(str(live) + "/") for target in mounted):
        raise ValueError("nested mounts in restore target; refusing to touch live data")
    apparent, amount = size(live)
    copy = (
        not empty
        or str(live) in mounted
        or live.stat().st_dev != live.parent.stat().st_dev
    )
    if copy and shutil.disk_usage(live.parent).free < amount + max(
        amount // 10, 16 * 1024 * 1024
    ):
        raise ValueError("insufficient free space for verified pre-restore copy")
    return live, amount, copy, apparent


def preserve(live, empty=True):
    live, amount, copy, apparent = preflight(live, empty=empty)
    if not live.exists():
        report = {"path": None, "size_bytes": 0, "method": "absent"}
        print("RESTORE_PRESERVED " + json.dumps(report), flush=True)
        return report
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    saved = Path(
        tempfile.mkdtemp(
            prefix=live.name + ".pre-restore-" + stamp + "-", dir=live.parent
        )
    )
    # The reserved empty sibling is ours. os.replace is atomic on the same FS;
    # there is deliberately no cross-device move fallback.
    if copy:
        subprocess.run(["cp", "-a", str(live) + "/.", str(saved)], check=True)
        check = subprocess.run(
            [
                "rsync",
                "-aHAXnc",
                "--delete",
                "--itemize-changes",
                str(live) + "/",
                str(saved) + "/",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        if check.stdout.strip() or not saved.is_dir():
            raise ValueError("pre-restore copy verification failed: " + str(saved))
    else:
        os.replace(live, saved)
    report = {
        "path": str(saved),
        "size_bytes": apparent,
        "method": "copy" if copy else "rename",
    }
    # Report even if clearing later fails. No error path removes saved.
    print("RESTORE_PRESERVED " + json.dumps(report), flush=True)
    if empty:
        if copy:
            # Copy is verified. Keep the mount itself and delete only its
            # contents; the nested-mount refusal above protects child mounts.
            with tempfile.TemporaryDirectory(
                prefix="restore-empty-", dir=live.parent
            ) as blank:
                subprocess.run(
                    ["rsync", "-a", "--delete", blank + "/", str(live) + "/"],
                    check=True,
                )
        else:
            live.mkdir(mode=0o700)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("live", nargs="?")
    parser.add_argument("--keep-live", action="store_true")
    parser.add_argument("--validate-layout", nargs="+")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--source", action="append", default=[])
    args = parser.parse_args()
    if args.validate_layout:
        check_layout(args.validate_layout, args.source)
    elif args.live and args.preflight:
        preflight(args.live, empty=not args.keep_live)
    elif args.live:
        preserve(args.live, empty=not args.keep_live)
    else:
        parser.error("live directory or --validate-layout is required")
