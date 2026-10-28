"""Real owned HTTPS fixture: monitor purpose, TLS, redirects and bounded body."""

from __future__ import annotations

import json
import ssl
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest

from ops_deploy.core.secrets import SecretContent
from ops_deploy.services.daybook_operations_runtime.status import MAX_STATUS_BYTES, StatusError, fetch_status

MONITOR = "fixture-monitor-not-real-" + "x" * 32
EXECUTOR = "fixture-executor-not-real-" + "y" * 32


@pytest.fixture
def endpoint(tmp_path: Path) -> Iterator[tuple[ThreadingHTTPServer, Path, list[str]]]:
    cert = tmp_path / "certificate.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            requests.append(self.path)  # Never capture authorization headers.
            if self.path != "/v1/status":
                self.send_error(404)
                return
            if self.headers.get("Authorization") != "Bearer " + MONITOR:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"PRIVATE-ERROR-BODY")
                return
            mode = getattr(self.server, "fixture_mode", "healthy")
            self.send_response(302 if mode == "redirect" else 200)
            if mode == "redirect":
                self.send_header("Location", "/v1/bindings/regular")
            self.end_headers()
            if mode == "large":
                self.wfile.write(b" " * (MAX_STATUS_BYTES + 1))
            elif mode == "healthy":
                self.wfile.write(
                    json.dumps(
                        {
                            "schema": 1,
                            "principal": "DROP-ME",
                            "bindings": [
                                {
                                    "binding": "regular",
                                    "enabled": True,
                                    "active_state": "assigned",
                                    "expiry_pending": True,
                                    "unapplied_receipts": 1,
                                    "needs_operator": False,
                                    "attention": [{"operation_id": "DROP-ME"}],
                                }
                            ],
                        }
                    ).encode()
                )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, cert, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_real_https_monitor_access_and_repeated_reads(endpoint: tuple[ThreadingHTTPServer, Path, list[str]]) -> None:
    server, cert, requests = endpoint
    origin = f"https://localhost:{server.server_port}"
    context = ssl.create_default_context(cafile=str(cert))
    with patch("ssl.create_default_context", return_value=context):
        for _ in range(2):
            result = fetch_status(origin, SecretContent(MONITOR), ["regular"])
            assert result[0].active_state == "assigned"
            assert result[0].expiry_pending is True
            assert "DROP-ME" not in repr(result)
        with pytest.raises(StatusError, match="monitor_http_failed"):
            fetch_status(origin, SecretContent(EXECUTOR), ["regular"])
    assert requests == ["/v1/status"] * 3


@pytest.mark.parametrize("mode", ["redirect", "large"])
def test_real_redirect_and_oversized_response_fail_once(
    endpoint: tuple[ThreadingHTTPServer, Path, list[str]], mode: str
) -> None:
    server, cert, requests = endpoint
    server.fixture_mode = mode  # type: ignore[attr-defined]
    context = ssl.create_default_context(cafile=str(cert))
    with patch("ssl.create_default_context", return_value=context), pytest.raises(StatusError):
        fetch_status(f"https://localhost:{server.server_port}", SecretContent(MONITOR), ["regular"])
    assert requests == ["/v1/status"]


def test_real_untrusted_tls_fails_before_http_request(endpoint: tuple[ThreadingHTTPServer, Path, list[str]]) -> None:
    server, _, requests = endpoint
    with pytest.raises(StatusError, match="monitor_transport_failed"):
        fetch_status(f"https://localhost:{server.server_port}", SecretContent(MONITOR), ["regular"])
    assert requests == []
