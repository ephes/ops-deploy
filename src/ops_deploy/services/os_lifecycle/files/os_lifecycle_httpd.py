#!/usr/bin/env python3
"""Authenticated HTTP server for one cached JSON report (ops-deploy ``services.os_lifecycle``).

The Python fallback of metrics-httpd's ``json-file`` mode, with the same
command line: ``GET <path>`` with HTTP basic auth (checked by
``htpasswd -vi`` against the htpasswd file) answers the JSON file with a
``meta`` object (``generated_at``, ``generated_at_epoch``, ``served_at_epoch``,
``age_seconds``: the file's mtime and its age now) replacing any ``meta`` in
the file. Without valid credentials it answers 401 with the realm; a missing
or broken file is a JSON error (503/502).
"""

from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any


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


class Handler(BoundedRequestMixin, http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        cfg: dict[str, Any] = self.server.cfg  # type: ignore[attr-defined]
        if self.path != cfg["path"]:
            self._json(404, {"error": True, "error_type": "not_found", "message": "Endpoint not found"})
            return
        if not self._authorized(self.headers.get("Authorization"), cfg["htpasswd_file"]):
            self.send_response(401, "Unauthorized")
            self.send_header("WWW-Authenticate", f'Basic realm="{cfg["realm"]}"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            generated = int(os.stat(cfg["json_path"]).st_mtime)
            with open(cfg["json_path"], encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
        except FileNotFoundError:
            self._json(503, {"error": True, "error_type": "metrics_file_missing", "message": "Report not found"})
            return
        except (OSError, ValueError) as error:
            self._json(502, {"error": True, "error_type": "invalid_json", "message": str(error)})
            return
        served = int(time.time())
        data["meta"] = {
            "generated_at": datetime.fromtimestamp(generated, tz=timezone.utc).isoformat(),
            "generated_at_epoch": generated,
            "served_at_epoch": served,
            "age_seconds": served - generated,
        }
        self._json(200, data)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self, header: str | None, htpasswd_file: str) -> bool:
        if not header or not header.startswith("Basic "):
            return False
        try:
            user, password = base64.b64decode(header.split(None, 1)[1], validate=True).decode("utf-8").split(":", 1)
        except (ValueError, IndexError):
            return False
        if not user or "\n" in password or "\x00" in password:
            return False
        done = subprocess.run(
            ["htpasswd", "-vi", htpasswd_file, user], input=password, capture_output=True, text=True, check=False
        )
        return done.returncode == 0

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {fmt % args}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Authenticated HTTP server for one JSON report")
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--json-path", required=True)
    parser.add_argument("--htpasswd-file", required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--server-name", required=True)
    args = parser.parse_args()
    Handler.server_version = args.server_name
    Handler.sys_version = ""

    httpd = BoundedThreadingTCPServer((args.bind, args.port), Handler)
    httpd.cfg = {  # type: ignore[attr-defined]
        "path": args.path,
        "json_path": args.json_path,
        "htpasswd_file": args.htpasswd_file,
        "realm": args.realm,
    }
    with httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
