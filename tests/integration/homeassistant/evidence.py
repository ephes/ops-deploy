"""Bound and hash only flat owned evidence before copying it off the guest."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path


def manifest(root: Path) -> dict[str, object]:
    paths = list(root.iterdir())
    if len(paths) > 512:
        raise ValueError("owned evidence file count exceeds limit")
    total = 0
    files = {}
    for path in sorted(paths):
        metadata = path.lstat()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", path.name) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("owned evidence contains an unexpected path type")
        if metadata.st_size > 40 * 1024 * 1024:
            raise ValueError("owned evidence file exceeds limit")
        total += metadata.st_size
        if total > 1024 * 1024 * 1024:
            raise ValueError("owned evidence total exceeds limit")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        files[path.name] = {"size": metadata.st_size, "sha256": digest}
    return {"files": files, "total_size": total}


if __name__ == "__main__":
    print(json.dumps(manifest(Path("/var/tmp/homeassistant-evidence")), sort_keys=True))
