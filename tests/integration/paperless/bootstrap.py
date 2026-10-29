"""Retained original PostgreSQL fresh-repository failure and owned fixture recovery."""

from __future__ import annotations

import hashlib
import json
import pwd
import re
import stat
import subprocess
from itertools import islice
from pathlib import Path
from typing import Any

SOURCES = Path("/etc/apt/sources.list.d/postgresql.sources")
LISTS = Path("/var/lib/apt/lists")
SSH_RUNTIME = Path("/run/sshd")
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
    if errors != [MISSING]:
        recover_original_index(harness, "00-original-install", version)
        return
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
    label = "00b-original-install-after-fixture-cache-recovery"
    if harness.ansible(label, version=version, allow_failure=True):
        recover_original_index(harness, label, version)


def retain_update(harness: Any, output: str, result: dict[str, Any]) -> None:
    body = harness.sanitize(output).encode()
    limit = 20 * 1024 * 1024
    truncated = len(body) > limit
    harness.write("original-bootstrap-cache-update-result.json", {**result, "output_truncated": truncated})
    # Preserve the bounded prefix even on overflow; the result records the limit.
    (harness.EVIDENCE / "original-bootstrap-cache-update.log").write_bytes(body[:limit])
    assert not truncated, "owned apt output exceeded bound; no retry"


def ssh_state(harness: Any) -> dict[str, Any]:
    result = harness.command("systemctl", "show", "ssh.service", "--property=ActiveState,SubState,MainPID", timeout=30)
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert set(fields) == {"ActiveState", "SubState", "MainPID"}
    try:
        info = SSH_RUNTIME.lstat()
    except FileNotFoundError:
        directory = None
    else:
        directory = {
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "is_directory": stat.S_ISDIR(info.st_mode),
        }
    return {"unit": fields, "runtime_directory": directory}


def prepare_ssh(harness: Any) -> None:
    before = ssh_state(harness)
    harness.write(
        "owned-ssh-prerequisite-started.json", {"before": before, "completion_receipt": "owned-ssh-prerequisite.json"}
    )
    result = harness.command("systemctl", "start", "ssh.service", timeout=30, check=False)
    harness.write("owned-ssh-start-result.json", {"exit": result.returncode})
    assert result.returncode == 0, "owned SSH prerequisite failed"
    after = ssh_state(harness)
    harness.write(
        "owned-ssh-prerequisite.json",
        {
            "classification": (
                "owned guest SSH prerequisite before original-role baseline; not an original deployment effect"
            ),
            "before": before,
            "after": after,
        },
    )
    assert after["unit"]["ActiveState"] == "active"
    assert after["unit"]["SubState"] == "running"
    assert after["unit"]["MainPID"].isdigit()
    assert int(after["unit"]["MainPID"]) > 0
    assert after["runtime_directory"] == {"mode": 0o755, "uid": 0, "gid": 0, "is_directory": True}


def recover_original_index(harness: Any, label: str, version: str) -> None:
    """One declared owned prerequisite after the retained upstream mkdir gap."""
    log = (harness.EVIDENCE / (label + ".log")).read_text()
    errors = [line for line in log.splitlines() if line.startswith("[ERROR]")]
    assert errors == ["[ERROR]: Task failed: Module failed: The command exited with a non-zero return code."]
    assert re.search(r"localhost\s*:\s*ok=\d+\s+changed=\d+\s+unreachable=0\s+failed=1\s", log)
    fatal = [line for line in log.splitlines() if line.startswith("fatal: [localhost]: FAILED! => ")]
    assert len(fatal) == 1
    failure = json.loads(fatal[0].split(" => ", 1)[1])
    index = Path(harness.CFG.external_storage_root) / "data/index"
    stderr = failure.get("stderr", "")
    assert failure.get("rc") == 1
    assert stderr.splitlines()[-1] == f"FileNotFoundError: [Errno 2] No such file or directory: '{index}'"
    assert f"paperless-ngx-v{version}/src/documents/search/_schema.py" in stderr
    assert "in wipe_index" in stderr
    assert "manage.py document_index reindex" in failure.get("cmd", "")
    assert not index.exists()
    assert not index.is_symlink()
    assert index.parent.resolve(strict=True) == index.parent
    parent = index.parent.lstat()
    user = pwd.getpwnam(harness.CFG.username)
    assert stat.S_ISDIR(parent.st_mode)
    assert parent.st_uid == user.pw_uid
    before = {"index_absent": True, "parent_uid": parent.st_uid, "parent_gid": parent.st_gid}
    harness.write("owned-original-index-prerequisite-started.json", {"before": before, "failed_original": label})
    result = harness.command(
        "runuser", "-u", harness.CFG.username, "--", "mkdir", "-m", "0755", "--", str(index), check=False
    )
    harness.write("owned-original-index-prerequisite-result.json", {"exit": result.returncode})
    assert result.returncode == 0, "owned original index prerequisite failed"
    after = index.lstat()
    assert stat.S_ISDIR(after.st_mode)
    assert after.st_uid == user.pw_uid
    harness.write(
        "owned-original-index-prerequisite.json",
        {
            "classification": (
                "explicit service-user owned missing-index prerequisite after original failure; "
                "not pristine original bootstrap"
            ),
            "before": before,
            "after": {"uid": after.st_uid, "gid": after.st_gid, "mode": stat.S_IMODE(after.st_mode)},
        },
    )
    harness.ansible("00c-original-install-after-fixture-index-prerequisite", version=version)
