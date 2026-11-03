#!/usr/bin/env python3
"""Pull the OS lifecycle reports of hosts without a monitoring endpoint (ops-deploy ``services.os_lifecycle``).

Run as root by ``os-lifecycle-pull.service`` on the monitoring host, with
``python3 -I``: ``os_lifecycle_pull.py --config FILE --out FILE``.

For each host in the config it opens one SSH session with the dedicated
collector key, which the host's ``authorized_keys`` restricts
(``restrict,command="..."``) to printing its cached report. The session sends
no command, allocates no terminal and forwards nothing; the host key must
match the pinned key (``StrictHostKeyChecking=yes`` against the deploy's own
known_hosts file, under the alias ``os-lifecycle-<name>``).

The combined file ``{"schema_version": 1, "generated_at_epoch": ...,
"hosts": {<name>: {...}}}`` keeps the last good report of a host whose pull
failed, next to ``pull_ok: false``, the error, and ages computed now:
``last_pull_success_age_hours`` and ``report_age_hours`` (since the host
wrote its report). Nyxmon reads the file through the metrics endpoint.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 1 << 20

Fetch = Callable[[dict[str, Any], dict[str, Any]], tuple[int, bytes, bytes]]


def ssh_argv(config: dict[str, Any], target: dict[str, Any]) -> list[str]:
    """The ssh command line for ``target``: no config file, only the collector key, the pinned host key."""

    return [
        "ssh",
        "-F",
        "/dev/null",
        "-T",
        "-i",
        str(config["identity_file"]),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={config['known_hosts']}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        f"HostKeyAlias=os-lifecycle-{target['name']}",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ConnectTimeout=20",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=3",
        "-p",
        str(int(target["port"])),
        "-l",
        str(target["user"]),
        str(target["address"]),
    ]


def ssh_fetch(config: dict[str, Any], target: dict[str, Any]) -> tuple[int, bytes, bytes]:
    try:
        done = subprocess.run(
            ssh_argv(config, target),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=int(config.get("timeout", 60)),
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        return 124, b"", b"timed out"
    except OSError as error:
        return 127, b"", str(error).encode()
    return done.returncode, done.stdout, done.stderr


def _hours(since: Any, now: float) -> float | None:
    if isinstance(since, bool) or not isinstance(since, (int, float)):
        return None
    return round(max(0.0, now - since) / 3600, 1)


def parse_report(name: str, stdout: bytes) -> dict[str, Any]:
    """The host's report, refused unless it is a schema-1 object naming ``name``."""

    if len(stdout) > MAX_REPORT_BYTES:
        raise ValueError("report larger than 1 MiB")
    report = json.loads(stdout.decode("utf-8"))
    if not isinstance(report, dict):
        raise ValueError("report is not a JSON object")
    if report.get("error"):
        raise ValueError(f"host reported: {str(report['error'])[:200]}")
    if report.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version {report.get('schema_version')!r}")
    if report.get("host") != name:
        raise ValueError(f"report names host {str(report.get('host'))[:64]!r}, expected {name!r}")
    return report


def pull(config: dict[str, Any], previous: dict[str, Any], *, now: float, fetch: Fetch = ssh_fetch) -> dict[str, Any]:
    """The combined file: one entry per configured host, the previous report kept on failure."""

    hosts: dict[str, Any] = {}
    for target in config["hosts"]:
        name = target["name"]
        before = previous.get(name) if isinstance(previous.get(name), dict) else {}
        entry: dict[str, Any] = {
            "pull_ok": False,
            "pull_error": None,
            "last_attempt_epoch": int(now),
            "last_pull_success_epoch": before.get("last_pull_success_epoch"),
            "report": before.get("report"),
        }
        code, stdout, stderr = fetch(config, target)
        try:
            if code != 0:
                tail = stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
                raise ValueError(f"ssh exited {code}: {tail[0][:200]}")
            entry["report"] = parse_report(name, stdout)
            entry["pull_ok"] = True
            entry["last_pull_success_epoch"] = int(now)
        except (ValueError, UnicodeDecodeError) as error:
            entry["pull_error"] = str(error)
        report = entry["report"] if isinstance(entry["report"], dict) else {}
        entry["last_pull_success_age_hours"] = _hours(entry["last_pull_success_epoch"], now)
        entry["report_age_hours"] = _hours(report.get("generated_at_epoch"), now)
        hosts[name] = entry
    return {"schema_version": SCHEMA_VERSION, "generated_at_epoch": int(now), "hosts": hosts}


def write_atomic(path: Path, text: str, group: str) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o640)
    os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pull OS lifecycle reports over SSH")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text())
    try:
        previous = json.loads(args.out.read_text()).get("hosts") or {}
    except (OSError, ValueError, AttributeError):
        previous = {}
    combined = pull(config, previous if isinstance(previous, dict) else {}, now=time.time())
    write_atomic(args.out, json.dumps(combined, sort_keys=True) + "\n", str(config.get("state_group") or "root"))
    failed = [name for name, entry in combined["hosts"].items() if not entry["pull_ok"]]
    for name in failed:
        print(f"{name}: {combined['hosts'][name]['pull_error']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
