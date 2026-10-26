"""UniFi HTTP200 startup responses must not satisfy deployment readiness."""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest


def health_module() -> Any:
    path = Path(__file__).parents[1] / "src/ops_deploy/services/unifi/files/health.py"
    spec = importlib.util.spec_from_file_location("unifi_health", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("status", "value", "expected"),
    [
        (200, {"meta": {"rc": "ok", "up": True}}, True),
        (200, {"meta": {"rc": "ok", "up": False}}, False),
        (200, {"meta": {"rc": "ok", "up": "true"}}, False),
        (200, {"meta": {"rc": "ok", "up": 1}}, False),
        (200, {"meta": {"rc": "error", "up": True}}, False),
        (200, {"meta": {"rc": "ok"}}, False),
        (200, {"meta": []}, False),
        (200, [], False),
        (200, None, False),
        (503, {"meta": {"rc": "ok", "up": True}}, False),
    ],
)
def test_exact_ready_signal(status: int, value: Any, expected: bool) -> None:
    assert health_module().ready(status, value) is expected


@pytest.mark.parametrize("mode", ["startup_then_ready", "never_ready", "redirect"])
def test_real_http_wait_and_deadline(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    module = health_module()
    paths: list[str] = []
    clock = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            paths.append(self.path)
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "/unexpected")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            if mode == "never_ready" or len(paths) == 1:
                self.wfile.write(json.dumps({"meta": {"rc": "ok", "up": False}}).encode())
            elif len(paths) == 2:
                self.wfile.write(b"<html>Controller starting</html>")
            else:
                self.wfile.write(json.dumps({"meta": {"rc": "ok", "up": True}}).encode())

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01))
    thread.start()
    try:
        assert module.wait_ready(3, f"http://127.0.0.1:{server.server_port}/status") is (mode == "startup_then_ready")
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert paths == ["/status"] * 3
    assert clock[0] == (2 if mode == "startup_then_ready" else 3)


def test_stalled_http_body_respects_total_timeout() -> None:
    import time

    module = health_module()
    started = threading.Event()
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b'{"meta":')
            self.wfile.flush()
            started.set()
            release.wait(5)

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01))
    thread.start()
    try:
        before = time.monotonic()
        assert not module.wait_ready(0.2, f"http://127.0.0.1:{server.server_port}/status")
        assert time.monotonic() - before < 1.5
        assert started.is_set()
    finally:
        release.set()
        server.shutdown()
        thread.join()
        server.server_close()
