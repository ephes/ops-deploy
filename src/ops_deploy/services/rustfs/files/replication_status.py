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
from http.server import BaseHTTPRequestHandler
from pathlib import Path

PATH = "/.well-known/rustfs-replication"
MAX_STATUS_BYTES = 1024 * 1024
STATUS_FIELDS = ("level", "lag_seconds", "parity_ok", "queued_count", "object_delta", "size_diff_bytes", "error")


# --- bounded-httpd begin: keep identical to ops_deploy/services/_metrics_httpd/files/bounded_httpd.py ---
# One idle or slow client must not stall the endpoint (ops-control
# SECURITY_AUDIT_OPSLIB_ENDPOINTS_2026_11_12, E1). Every connection gets its own
# daemon thread, at most BOUNDED_HTTPD_MAX_CONNECTIONS at once (one more is closed
# when it is accepted); each read waits at most the handler's timeout, and the
# request line and headers must arrive within BOUNDED_HTTPD_HEADER_DEADLINE seconds
# in total, so a client that drips one byte just inside the read timeout is cut off
# too. The deadline is armed again for every request of a keep-alive connection.
import io as _bounded_io
import socket as _bounded_socket
import socketserver as _bounded_socketserver
import threading as _bounded_threading
import time as _bounded_time

BOUNDED_HTTPD_READ_TIMEOUT = 10
BOUNDED_HTTPD_HEADER_DEADLINE = 15
BOUNDED_HTTPD_MAX_CONNECTIONS = 32


class BoundedThreadingTCPServer(_bounded_socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self.connection_slots = _bounded_threading.BoundedSemaphore(BOUNDED_HTTPD_MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()


class _BoundedDeadlineReader(_bounded_io.RawIOBase):
    def __init__(self, handler):
        super().__init__()
        self._handler = handler

    def readable(self):
        return True

    def readinto(self, buffer):
        handler = self._handler
        timeout = handler.timeout
        deadline = handler.bounded_httpd_deadline
        if deadline is not None:
            remaining = deadline - _bounded_time.monotonic()
            if remaining <= 0:
                raise _bounded_socket.timeout("request header deadline passed")
            timeout = remaining if timeout is None else min(timeout, remaining)
        handler.connection.settimeout(timeout)
        return handler.connection.recv_into(buffer)


class BoundedRequestMixin:
    timeout = BOUNDED_HTTPD_READ_TIMEOUT
    bounded_httpd_deadline = None

    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = _bounded_io.BufferedReader(_BoundedDeadlineReader(self))

    def handle_one_request(self):
        self.bounded_httpd_deadline = _bounded_time.monotonic() + BOUNDED_HTTPD_HEADER_DEADLINE
        try:
            super().handle_one_request()
        finally:
            self.bounded_httpd_deadline = None

    def parse_request(self):
        try:
            return super().parse_request()
        finally:
            # The headers are in: the response and any body get the plain read timeout
            # again, not what was left of the deadline.
            self.bounded_httpd_deadline = None
            self.connection.settimeout(self.timeout)


# --- bounded-httpd end ---


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


class Handler(BoundedRequestMixin, BaseHTTPRequestHandler):
    server_version = "rustfs-replication-status"
    sys_version = ""

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
    server = BoundedThreadingTCPServer((bind, int(port)), Handler)
    server.settings = (state_root, jobs_path, int(stale))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
