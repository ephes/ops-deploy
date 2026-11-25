#!/usr/bin/env python3
"""Loopback proxy between Home Assistant's voice bridge and the OpenClaw gateway.

Home Assistant's built-in ``llama_cpp`` conversation agent sends
``user = <HA conversation_id>``, a new value for every voice interaction, and
OpenClaw derives its session from ``user``. Every spoken question therefore
started a cold OpenClaw session (7-14 s). It also appends
"Current time is HH:MM:SS. Today's date is YYYY-MM-DD." to the system prompt,
which changes the prompt on every request.

This proxy rewrites chat completion requests so all voice turns of one day
share one warm OpenClaw session (about 3 s per answer):

- ``user`` becomes ``<prefix>-<YYYY-MM-DD>``; the day rolls over at
  ``rollover_hour`` local time;
- the volatile date/time line is removed from system messages (Clanky knows
  the date from OpenClaw itself);
- only the system messages and the last user message are forwarded, because
  the OpenClaw session already holds the earlier turns.

Everything else (``/v1/models``, headers, the Authorization header, streamed
responses) passes through unchanged. Standard library only; the request text
is never logged.
"""

from __future__ import annotations

import datetime as dt
import http.client
import json
import os
import re
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler
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

DATE_TIME_LINE = re.compile(
    r"Current time is \d{1,2}:\d{2}(?::\d{2})?\. Today's date is \d{4}-\d{2}-\d{2}\.\n?"
)
CHAT_PATH = "/v1/chat/completions"
PASS_REQUEST_HEADERS = ("authorization", "content-type", "accept", "user-agent")
DROP_RESPONSE_HEADERS = {"connection", "keep-alive", "transfer-encoding", "content-length"}


def session_user(prefix: str, now: dt.datetime, rollover_hour: int) -> str:
    """The shared voice session key for the voice day that contains ``now``."""

    day = (now - dt.timedelta(hours=rollover_hour)).date()
    return f"{prefix}-{day.isoformat()}"


def rewrite_chat_request(payload: dict[str, Any], user: str) -> dict[str, Any]:
    """Return the request OpenClaw should see; leave unusual shapes untouched."""

    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        return payload
    last = messages[-1]
    if not isinstance(last, dict) or last.get("role") != "user":
        return payload
    systems = []
    for message in messages[:-1]:
        if not isinstance(message, dict) or message.get("role") not in ("system", "developer"):
            continue
        content = message.get("content")
        if isinstance(content, str):
            content = DATE_TIME_LINE.sub("", content).strip()
            if not content:
                continue
            message = {**message, "content": content}
        systems.append(message)
    return {**payload, "user": user, "messages": [*systems, last]}


class Settings:
    def __init__(self, env: dict[str, str]) -> None:
        upstream = urllib.parse.urlsplit(env.get("VOICE_PROXY_UPSTREAM", "http://127.0.0.1:18789"))
        if upstream.scheme != "http" or not upstream.hostname:
            raise SystemExit("VOICE_PROXY_UPSTREAM must be an http:// URL")
        self.upstream_host = upstream.hostname
        self.upstream_port = upstream.port or 80
        self.listen_host = env.get("VOICE_PROXY_LISTEN_HOST", "127.0.0.1")
        self.listen_port = int(env.get("VOICE_PROXY_LISTEN_PORT", "18790"))
        self.prefix = env.get("VOICE_PROXY_SESSION_PREFIX", "voice-wohnzimmer")
        self.rollover_hour = int(env.get("VOICE_PROXY_ROLLOVER_HOUR", "4"))
        self.timeout = float(env.get("VOICE_PROXY_UPSTREAM_TIMEOUT", "300"))


class Handler(BoundedRequestMixin, BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # close-delimited responses stream without chunking
    server_version = "voice-session-proxy"
    settings: Settings

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return  # one structured line per request instead (see _forward)

    def do_GET(self) -> None:
        self._forward(None)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self._forward(self.rfile.read(length) if length else b"")

    def _forward(self, body: bytes | None) -> None:
        settings = self.settings
        started = time.monotonic()
        session = "-"
        if body is not None and self.path.split("?", 1)[0] == CHAT_PATH:
            try:
                payload = json.loads(body)
            except ValueError:
                payload = None
            if isinstance(payload, dict):
                session = session_user(settings.prefix, dt.datetime.now(), settings.rollover_hour)
                body = json.dumps(rewrite_chat_request(payload, session)).encode()
        headers = {name: value for name, value in self.headers.items() if name.lower() in PASS_REQUEST_HEADERS}
        if body is not None:
            headers["Content-Length"] = str(len(body))
        status = 503
        headers_sent = False
        try:
            conn = http.client.HTTPConnection(settings.upstream_host, settings.upstream_port, timeout=settings.timeout)
            conn.request(self.command, self.path, body=body, headers=headers)
            upstream = conn.getresponse()
            status = upstream.status
            self.send_response(status)
            for name, value in upstream.getheaders():
                if name.lower() not in DROP_RESPONSE_HEADERS:
                    self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            headers_sent = True
            while chunk := upstream.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
            conn.close()
        except (OSError, http.client.HTTPException) as err:
            if not headers_sent:
                status = 503
                self.send_error(503, f"upstream unavailable: {type(err).__name__}")
        finally:
            print(
                f"{self.command} {self.path.split('?', 1)[0]} status={status} "
                f"session={session} seconds={time.monotonic() - started:.2f}",
                file=sys.stderr,
                flush=True,
            )


def make_handler(settings: Settings) -> type[Handler]:
    return type("ConfiguredHandler", (Handler,), {"settings": settings})


def main() -> None:
    settings = Settings(dict(os.environ))
    server = BoundedThreadingTCPServer((settings.listen_host, settings.listen_port), make_handler(settings))
    print(
        f"voice-session-proxy listening on {settings.listen_host}:{settings.listen_port} "
        f"-> {settings.upstream_host}:{settings.upstream_port}",
        file=sys.stderr,
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
