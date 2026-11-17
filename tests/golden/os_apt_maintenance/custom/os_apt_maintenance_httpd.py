#!/usr/bin/env python3
"""Minimal authenticated HTTP server for os apt maintenance state."""
from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional, Tuple


FRESHNESS_MAX_AGE_SECONDS = 1209600
STATE_MAX_AGE_SECONDS = 1296000
REBOOT_REQUIRED_FLAG = "/var/run/reboot-required"


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


def reboot_state(state: dict, *, flag_present: bool, running_release: str) -> dict:
    """Reboot state served to monitoring: live marker plus persisted kernel signal.

    The marker file is re-read on every request so a reboot clears it at once.
    The kernel comparison is only evaluated by the maintenance run and lands in
    the state file as ``reboot_required_details``; it is served as long as the
    host is still running the kernel that run observed. Once ``uname -r``
    changes the persisted signal is obsolete and is dropped until the next run
    re-evaluates it - so a reboot into the new kernel clears it immediately,
    while a reboot back into the old kernel does not.

    Serving only the live marker here would silently discard the kernel signal
    on every host the marker file can never appear on, which is the false
    negative the kernel comparison exists to close.
    """
    reasons = []
    details: dict = {"flag_present": flag_present}
    if flag_present:
        reasons.append("reboot_required_flag")
    persisted = state.get("reboot_required_details")
    if (
        isinstance(persisted, dict)
        and "stale_kernel" in (persisted.get("reasons") or [])
        and persisted.get("running_kernel") == running_release
    ):
        reasons.append("stale_kernel")
        for key in ("running_kernel", "running_kernel_version", "newest_installed_kernel"):
            if key in persisted:
                details[key] = persisted[key]
    details["required"] = bool(reasons)
    details["reasons"] = reasons
    return details


class AptMaintenanceHandler(BoundedRequestMixin, http.server.BaseHTTPRequestHandler):
    server_version = "os-apt-maintenance-httpd/0.1"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        cfg = self.server.cfg  # type: ignore[attr-defined]
        if self.path != cfg["path"]:
            self._send_json_error(404, "not_found", "Endpoint not found")
            return

        ok, _message = self._check_auth(self.headers.get("Authorization"), cfg)
        if not ok:
            self.send_response(401, "Unauthorized")
            self.send_header("WWW-Authenticate", 'Basic realm="os-apt-maintenance"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        json_path = cfg["json_path"]
        if not os.path.isfile(json_path):
            self._send_json_error(503, "state_file_missing", "Apt maintenance state file not found")
            return

        try:
            stat = os.stat(json_path)
            generated_at_epoch = int(stat.st_mtime)
            served_at_epoch = int(datetime.now(tz=timezone.utc).timestamp())
            age_seconds = served_at_epoch - generated_at_epoch
            with open(json_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except json.JSONDecodeError as exc:
            self._send_json_error(502, "invalid_json", f"Invalid JSON in state file: {exc}")
            return
        except OSError as exc:
            self._send_json_error(503, "read_error", f"Cannot read state file: {exc}")
            return

        last_success_epoch = data.get("last_success_epoch")
        last_success_age_seconds = None
        if isinstance(last_success_epoch, int):
            last_success_age_seconds = max(0, served_at_epoch - last_success_epoch)

        last_status = data.get("last_status")
        state_reboot_required = bool(data.get("reboot_required"))
        reboot_details = reboot_state(
            data,
            flag_present=os.path.exists(REBOOT_REQUIRED_FLAG),
            running_release=os.uname().release,
        )
        reboot_required = reboot_details["required"]
        state_file_fresh = age_seconds <= STATE_MAX_AGE_SECONDS
        last_success_fresh = (
            last_success_age_seconds is not None
            and last_success_age_seconds <= FRESHNESS_MAX_AGE_SECONDS
        )
        currently_running = last_status == "running"
        last_run_ok = last_status == "success" or (currently_running and last_success_fresh)

        data["meta"] = {
            "generated_at": datetime.fromtimestamp(generated_at_epoch, tz=timezone.utc).isoformat(),
            "generated_at_epoch": generated_at_epoch,
            "served_at_epoch": served_at_epoch,
            "age_seconds": age_seconds,
            "state_file_fresh": state_file_fresh,
            "state_max_age_seconds": STATE_MAX_AGE_SECONDS,
            "state_reboot_required": state_reboot_required,
        }
        data["reboot_required"] = reboot_required
        data["reboot_required_details"] = reboot_details
        data["summary"] = {
            "last_run_ok": last_run_ok,
            "currently_running": currently_running,
            "last_success_fresh": last_success_fresh,
            "last_success_age_seconds": last_success_age_seconds,
            "freshness_max_age_seconds": FRESHNESS_MAX_AGE_SECONDS,
            "reboot_required": reboot_required,
            "overall_ok": last_run_ok and last_success_fresh and state_file_fresh,
        }

        payload = json.dumps(data, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_json_error(self, status: int, error_type: str, message: str) -> None:
        payload = json.dumps({
            "error": True,
            "error_type": error_type,
            "message": message,
        }).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(
            "%s - - [%s] %s\n"
            % (self.client_address[0], self.log_date_time_string(), fmt % args)
        )

    def _check_auth(self, header: Optional[str], cfg: dict) -> Tuple[bool, str]:
        if not header or not header.startswith("Basic "):
            return False, "missing"
        try:
            decoded = base64.b64decode(header.split()[1]).decode("utf-8")
            user, password = decoded.split(":", 1)
        except Exception:
            return False, "malformed"

        try:
            result = subprocess.run(
                ["htpasswd", "-vi", cfg["htpasswd_file"], user],
                input=password,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            return False, "timeout"
        return result.returncode == 0, result.stderr


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authenticated HTTP server for apt maintenance state")
    parser.add_argument("--bind", default="100.64.0.7", help="Bind address")
    parser.add_argument("--port", type=int, default=19106, help="Listen port")
    parser.add_argument("--path", default="/fixture/state", help="Endpoint path")
    parser.add_argument("--json-path", default="/srv/apt-state/custom.json", help="State JSON path")
    parser.add_argument(
        "--htpasswd-file",
        default="/etc/fixture-apt/htpasswd",
        help="htpasswd file for authentication",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    httpd = BoundedThreadingTCPServer((args.bind, args.port), AptMaintenanceHandler)
    httpd.cfg = {  # type: ignore[attr-defined]
        "path": args.path,
        "json_path": args.json_path,
        "htpasswd_file": args.htpasswd_file,
    }
    with httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
