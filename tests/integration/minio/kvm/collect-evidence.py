"""Bound Docker's owned evidence tar stream before copying bodies onto the host."""

from __future__ import annotations

import re
import sys
import tarfile
from pathlib import Path
from typing import BinaryIO


def collect(stream: BinaryIO, destination: Path) -> None:
    total = count = 0
    seen: set[str] = set()
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            name = member.name.removeprefix("./").rstrip("/")
            if name in ("", ".") and member.isdir():
                continue
            parts = name.split("/")
            if any(
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", part) or part in (".", "..") for part in parts
            ):
                raise RuntimeError("unsafe owned evidence path")
            count += 1
            if count > 2048 or name in seen or not (member.isdir() or member.isfile()):
                raise RuntimeError("invalid owned evidence member")
            seen.add(name)
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            total += member.size
            if member.size < 0 or total > 256 * 1024 * 1024:
                raise RuntimeError("owned evidence exceeds copy-out bound")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            assert source is not None
            with source, target.open("xb") as output:
                remaining = member.size
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise RuntimeError("truncated owned evidence stream")
                    output.write(block)
                    remaining -= len(block)


if __name__ == "__main__":
    collect(sys.stdin.buffer, Path(sys.argv[1]))
