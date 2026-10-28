"""Retained original PostgreSQL fresh-repository failure and owned fixture recovery."""

from __future__ import annotations

import hashlib
import re
import stat
import subprocess
from itertools import islice
from pathlib import Path
from typing import Any

SOURCES = Path("/etc/apt/sources.list.d/postgresql.sources")
LISTS = Path("/var/lib/apt/lists")
MISSING = "[ERROR]: Task failed: Module failed: No package matching 'postgresql-17' is available"


def cache_diagnostic(harness: Any) -> dict[str, Any]:
    """Only the declared public PGDG source and bounded apt-list metadata."""
    info = SOURCES.lstat()
    assert stat.S_ISREG(info.st_mode)
    assert info.st_size <= 65536
    with SOURCES.open("rb") as stream:
        source = stream.read(65537)
    assert len(source) <= 65536
    entries = sorted(islice(LISTS.glob("*postgresql*"), 33))
    assert len(entries) <= 32
    metadata = {}
    for path in entries:
        item = path.lstat()
        assert stat.S_ISREG(item.st_mode)
        metadata[path.name] = {"size": item.st_size, "mtime_ns": item.st_mtime_ns}
    policy = harness.command("apt-cache", "policy", "postgresql-17", timeout=30, check=False)
    assert policy.returncode == 0
    assert len(policy.stdout.encode()) <= 65536
    assert len(policy.stderr.encode()) <= 65536
    return {
        "source": source.decode(),
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "list_metadata": metadata,
        "policy": policy.stdout,
        "policy_stderr": policy.stderr,
    }


def original_install(harness: Any, version: str) -> None:
    code = harness.ansible("00-original-install", version=version, allow_failure=True)
    if code == 0:
        return
    log = (harness.EVIDENCE / "00-original-install.log").read_text()
    # Never turn an auth/network/repository/other original failure into recovery.
    errors = [line for line in log.splitlines() if line.startswith("[ERROR]")]
    assert errors == [MISSING], "unrecognised original bootstrap failure; no fixture recovery"
    assert re.search(r"localhost\s*:\s*ok=\d+\s+changed=\d+\s+unreachable=0\s+failed=1\s", log)
    before = cache_diagnostic(harness)
    harness.write("original-bootstrap-cache-before.json", before)
    argv = ("apt-get", "-o", "APT::Update::Error-Mode=any", "update")
    classification = "explicit owned fixture apt cache recovery after original failure; not original bootstrap success"
    harness.write("original-bootstrap-cache-update-started.json", {"argv": argv, "timeout_seconds": 300})
    try:
        result = harness.command(*argv, timeout=300, check=False)
    except subprocess.TimeoutExpired as error:
        parts = [
            part.decode(errors="replace") if isinstance(part, bytes) else part or ""
            for part in (error.stdout, error.stderr)
        ]
        retain_update(harness, "".join(parts), {"exit": None, "timed_out": True, "classification": classification})
        raise
    retain_update(
        harness,
        result.stdout + result.stderr,
        {"exit": result.returncode, "timed_out": False, "classification": classification},
    )
    harness.write(
        "original-bootstrap-cache-recovery.json",
        {
            "classification": classification,
            "exit": result.returncode,
            "before": before,
            "after": cache_diagnostic(harness),
        },
    )
    assert result.returncode == 0, "owned fixture apt update failed; no original retry"
    harness.ansible("00b-original-install-after-fixture-cache-recovery", version=version)


def retain_update(harness: Any, output: str, result: dict[str, Any]) -> None:
    body = harness.sanitize(output).encode()
    limit = 20 * 1024 * 1024
    truncated = len(body) > limit
    harness.write("original-bootstrap-cache-update-result.json", {**result, "output_truncated": truncated})
    # Preserve the bounded prefix even on overflow; the result records the limit.
    (harness.EVIDENCE / "original-bootstrap-cache-update.log").write_bytes(body[:limit])
    assert not truncated, "owned apt output exceeded bound; no retry"
