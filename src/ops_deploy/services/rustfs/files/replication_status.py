#!/usr/bin/env python3
"""Loopback status endpoint of the RustFS replica's lag/parity probe.

``rustfs-replication-status BIND PORT STATE_ROOT JOBS STALE_SECONDS`` answers
``GET /.well-known/rustfs-replication`` with a summary that it computes from
``<STATE_ROOT>/<job>/{status.json,lag.marker,parity.marker}`` on every
request (the probe's files, written by ``rustfs-replication-monitor probe``),
so a Nyxmon json-metrics check on the same host alarms on the replica's own
verdict. A job is critical when it is required and its status file is
missing, unreadable or older than STALE_SECONDS, when the probe's level is
critical, or when its lag or parity marker is older than the job's
``critical_hours`` or ``parity_critical_hours``. ``ok`` is false while any
required job is critical; ``warning`` is true while any job is at warning or
worse. The endpoint reads only those files; it has no credentials, no write
access and no other path.
"""

from __future__ import annotations

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PATH = "/.well-known/rustfs-replication"
MAX_STATUS_BYTES = 1024 * 1024
STATUS_FIELDS = ("level", "lag_seconds", "parity_ok", "queued_count", "object_delta", "size_diff_bytes", "error")


def age(path, now):
    """Seconds since ``path`` was modified, or None when it is absent."""
    try:
        return max(0, int(now - path.stat().st_mtime))
    except FileNotFoundError:
        return None


def read_status(path):
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_STATUS_BYTES + 1)
    except FileNotFoundError:
        return None, "status_missing"
    if len(raw) > MAX_STATUS_BYTES:
        return None, "status_unreadable"
    try:
        value = json.loads(raw)
    except ValueError:
        return None, "status_unreadable"
    return (value, None) if isinstance(value, dict) else (None, "status_unreadable")


def job_summary(job, state_root, stale_seconds, now):
    state = Path(state_root) / job["name"]
    status, problem = read_status(state / "status.json")
    status_age = age(state / "status.json", now)
    lag_age = age(state / "lag.marker", now)
    parity_age = age(state / "parity.marker", now)
    reasons = [] if problem is None else [problem]
    if status_age is not None and status_age > stale_seconds:
        reasons.append("status_stale")
    level = status.get("level") if status else None
    if status is not None and level not in ("ok", "warning", "critical"):
        reasons.append("status_unreadable")
    if level == "critical":
        reasons.append("probe_critical")
    if lag_age is None or lag_age >= job["critical_hours"] * 3600:
        reasons.append("lag_marker_stale")
    if parity_age is None or parity_age >= job["parity_critical_hours"] * 3600:
        reasons.append("parity_marker_stale")
    warning = bool(reasons) or level == "warning" or (lag_age is not None and lag_age >= job["warning_hours"] * 3600)
    summary = {
        "required": job["required"],
        "critical": bool(reasons),
        "warning": warning,
        "reasons": reasons,
        "status_age_seconds": status_age,
        "lag_marker_age_seconds": lag_age,
        "parity_marker_age_seconds": parity_age,
    }
    summary.update({field: (status or {}).get(field) for field in STATUS_FIELDS})
    return summary


def summary(state_root, jobs_path, stale_seconds, now=None):
    now = time.time() if now is None else now
    jobs = json.loads(Path(jobs_path).read_text(encoding="utf-8"))
    rows = {job["name"]: job_summary(job, state_root, stale_seconds, now) for job in jobs}
    critical = sorted(name for name, row in rows.items() if row["critical"] and row["required"])
    return {
        "ok": not critical,
        "warning": any(row["warning"] for row in rows.values()),
        "critical_jobs": critical,
        "job_count": len(rows),
        "stale_after_seconds": stale_seconds,
        "jobs": rows,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "rustfs-replication-status"
    sys_version = ""
    # One request at a time; a stalled client cannot hold the socket longer.
    timeout = 10

    def do_GET(self):  # noqa: N802 - http.server's name
        if self.path != PATH:
            self.send_error(404)
            return
        try:
            body = json.dumps(summary(*self.server.settings)).encode()
        except Exception:  # noqa: BLE001 - the jobs file is broken; say so without detail
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - http.server's signature
        return


def main(argv):
    if len(argv) != 6:
        print("usage: rustfs-replication-status BIND PORT STATE_ROOT JOBS STALE_SECONDS", file=sys.stderr)
        return 1
    bind, port, state_root, jobs_path, stale = argv[1:]
    server = HTTPServer((bind, int(port)), Handler)
    server.settings = (state_root, jobs_path, int(stale))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
