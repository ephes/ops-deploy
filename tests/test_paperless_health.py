"""Real owned loopback status/redirect checks; no application or inventory data."""

from __future__ import annotations

import importlib.util
import inspect
import io
import json
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.helpers import http_check
from ops_deploy.services.paperless import PaperlessConfig, operations
from ops_deploy.testing import run_deploy_fake

SPEC = importlib.util.spec_from_file_location(
    "paperless_health", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/health.py"
)
assert SPEC is not None
assert SPEC.loader is not None
HEALTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HEALTH)


@pytest.fixture
def endpoint() -> Iterator[Any]:
    requests: list[str] = []
    replies = {"/api/": (302, "schema/view/"), "/api/schema/view/": (200, None)}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            status, location = replies.get(self.path, (500, None))
            self.send_response(status)
            if location is not None:
                self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, replies, requests
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_actual_old_shared_check_refuses_expected_redirect_new_check_requires_final200(endpoint: Any) -> None:
    port, _, requests = endpoint
    old = run_deploy_fake(http_check, f"http://127.0.0.1:{port}/api/", retries=1, delay=0, timeout=1)
    assert len(old.executed_commands) == 1
    result = subprocess.run(old.executed_commands[0], shell=True, capture_output=True, text=True, timeout=5)
    assert result.returncode == 1
    assert "answered 302, expected 200" in result.stderr
    assert requests == ["/api/"]
    assert HEALTH.inspect_endpoint(port) == {
        "initial_status": 302,
        "location": "schema/view/",
        "redirect_target": "/api/schema/view/",
        "final_status": 200,
    }
    assert requests == ["/api/", "/api/", "/api/schema/view/"]


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1:1/api/schema/view/",
        "https://foreign.invalid/api/schema/view/",
        "//foreign.invalid/api/schema/view/",
        "/api/",
        "/accounts/login/",
        "schema/view/?unexpected=yes",
        "schema/view/#fragment",
        "schema/../schema/view/",
        "http://" + "owned-user:owned-password@" + "127.0.0.1:1/api/schema/view/",
    ],
)
def test_unknown_redirect_never_followed(endpoint: Any, location: str) -> None:
    port, replies, requests = endpoint
    replies["/api/"] = (302, location)
    with pytest.raises(ValueError, match="unexpected redirect"):
        HEALTH.inspect_endpoint(port)
    assert requests == ["/api/"]


@pytest.mark.parametrize("final", [(302, "schema/view/"), (500, None), (401, None), (200, "/foreign")])
def test_exact_redirect_without_final200_is_not_ready(endpoint: Any, final: Any) -> None:
    port, replies, requests = endpoint
    replies["/api/schema/view/"] = final
    with pytest.raises(ValueError, match="final200"):
        HEALTH.inspect_endpoint(port)
    assert requests == ["/api/", "/api/schema/view/"]


def test_direct200_and_same_origin_absolute_schema(endpoint: Any) -> None:
    port, replies, _ = endpoint
    replies["/api/"] = (302, f"http://127.0.0.1:{port}/api/schema/view/")
    assert HEALTH.inspect_endpoint(port)["final_status"] == 200
    replies["/api/"] = (200, None)
    assert HEALTH.inspect_endpoint(port) == {
        "initial_status": 200,
        "location": None,
        "redirect_target": None,
        "final_status": 200,
    }


def test_poll_attempt_deadline_interrupts_a_stalled_request(monkeypatch: pytest.MonkeyPatch) -> None:
    original_timer = signal.setitimer
    original_sleep = time.sleep
    previous_handler = signal.getsignal(signal.SIGALRM)
    attempts: list[int] = []

    def stalled(port: int) -> None:
        attempts.append(port)
        original_sleep(5)

    monkeypatch.setattr(HEALTH, "inspect_endpoint", stalled)
    monkeypatch.setattr(HEALTH.sys, "stdin", io.StringIO('{"port":10030}'))
    monkeypatch.setattr(HEALTH.time, "sleep", lambda delay: None)
    monkeypatch.setattr(HEALTH.signal, "setitimer", lambda which, delay: original_timer(which, min(delay, 0.02)))
    start = time.monotonic()
    try:
        assert HEALTH.main() == 1
        assert attempts == [10030] * 10
        assert time.monotonic() - start < 2
    finally:
        original_timer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


@pytest.mark.parametrize("shell", ["bash", "fish"])
def test_real_operation_encoded_command_and_stdin(endpoint: Any, shell: str) -> None:
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f"{shell} unavailable; native shell coverage remains separate")
    port, _, requests = endpoint
    cfg = PaperlessConfig(traefik_domain="home.example.test", app_port=port)
    commands = list(inspect.unwrap(operations.http_health)(cfg))
    assert len(commands) == 1
    command = commands[0]
    payload = "".join(command.connector_arguments["_stdin"])
    assert json.loads(payload) == {"port": port}
    assert command.connector_arguments["_get_pty"] is False
    result = subprocess.run(
        [executable, "-c", command.get_raw_value()], input=payload, capture_output=True, text=True, timeout=15
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "initial_status": 302,
        "location": "schema/view/",
        "redirect_target": "/api/schema/view/",
        "final_status": 200,
    }
    assert requests == ["/api/", "/api/schema/view/"]
