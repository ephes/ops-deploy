#!/usr/bin/python3
"""Owned maintenance fixture fault injector; every non-targeted call uses exact mc.

This file is not a product helper. Admission and paths are confined to the fresh
KVM fixture. It never prints command arguments, stdin or credential values.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path("/srv/ops-owned-minio-policy")
REAL = "/opt/minio-artifacts/mc"
MODES = {"none", "detach-before", "detach-after", "remove-before", "info-after-remove", "info-before"}


def selected_action(argv: list[str], policy: str) -> str | None:
    """Only exact admin policy command positions; never a substring match."""
    try:
        position = argv.index("admin")
    except ValueError:
        return None
    if len(argv) < position + 5 or argv[position + 1] != "policy":
        return None
    action = argv[position + 2]
    if action not in {"info", "detach", "remove"} or argv[position + 4] != policy:
        return None
    return action


def injected_error() -> int:
    print(json.dumps({"status": "error", "error": {"cause": {"error": {"Code": "OwnedSyntheticFailure"}}}}))
    return 1


def main() -> int:
    marker = json.loads(Path("/var/tmp/minio-owned-guest.json").read_text())
    assert marker["run"] == Path("/etc/ops-minio-owned-id").read_text().strip()
    assert marker["machine"] == Path("/etc/machine-id").read_text().strip()
    assert ROOT.is_dir()
    assert not ROOT.is_symlink()
    fault = json.loads((ROOT / "fault.json").read_text())
    assert set(fault) == {"mode", "policy"}
    assert fault["mode"] in MODES
    assert fault["policy"].startswith("owned-policy-")
    action = selected_action(sys.argv[1:], fault["policy"])
    mode = fault["mode"]
    if (
        (action == "detach" and mode == "detach-before")
        or (action == "remove" and mode == "remove-before")
        or (action == "info" and mode == "info-before")
        or (action == "info" and mode == "info-after-remove" and (ROOT / "removed").exists())
    ):
        return injected_error()
    # stdin is passed through in memory, including alias-import JSON. It is not
    # persisted in this fault wrapper or appended to command argv/log output.
    result = subprocess.run([REAL, *sys.argv[1:]], stdin=sys.stdin.buffer, capture_output=True, timeout=60)
    if result.returncode == 0 and action == "remove":
        (ROOT / "removed").write_text("removed\n")
    if result.returncode == 0 and action == "detach" and mode == "detach-after":
        return injected_error()
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
