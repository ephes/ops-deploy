"""The Python HTTP endpoints stay responsive with idle, partial and dripping clients.

ops-control ``docs/SECURITY_AUDIT_OPSLIB_ENDPOINTS_2026_11_12.md`` E1: a single-threaded
``socketserver.TCPServer`` without a timeout let one idle tailnet connection stall every
Nyxmon check of the endpoint; a per-read timeout alone still let a client that drips a byte
just inside it hold a connection forever. Every Python endpoint now carries the same block
(``services/_metrics_httpd/files/bounded_httpd.py``): a thread per connection, a connection
cap, a per-read timeout and a total deadline for the request line and headers.

E2: ``metrics_httpd.py`` put the collector's stderr into the HTTP status line.
"""

from __future__ import annotations

import base64
import http.client
import json
import re
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jinja2
import pytest

import ops_deploy
from ops_deploy.helpers.traefik import hash_password

SRC = Path(ops_deploy.__file__).parent
CANONICAL_PATH = SRC / "services" / "_metrics_httpd" / "files" / "bounded_httpd.py"
CANONICAL = CANONICAL_PATH.read_text()
# The tests shorten the header deadline so a drip is cut off within seconds.
DEADLINE = 2
PROBE = "/probe"
# Collision-free stand-in values; never a real credential.
VALUE = "bounded-httpd-fixture-value"  # pragma: allowlist secret

TEMPLATE_VARS: dict[str, Any] = {
    "tailscale_metrics_endpoint_json_path": "/nonexistent",
    "tailscale_metrics_endpoint_htpasswd_path": "/nonexistent",
    "dns_metrics_endpoint_htpasswd_path": "/nonexistent",
    "dns_metrics_endpoint_json_path": "/nonexistent",
    "dns_metrics_endpoint_path": PROBE,
    "dns_metrics_endpoint_port": 9,
    "dns_metrics_endpoint_request_timeout": 15,
    "backup_metrics_endpoint_htpasswd_path": "/nonexistent",
    "backup_metrics_endpoint_json_path": "/nonexistent",
    "storage_metrics_endpoint_htpasswd_path": "/nonexistent",
    "storage_metrics_endpoint_json_path": "/nonexistent",
    "metrics_endpoint_htpasswd_path": "/nonexistent",
    "metrics_endpoint_script_path": "/nonexistent",
    "metrics_endpoint_script_timeout": 5,
    "openclaw_metrics_endpoint_htpasswd_path": "/nonexistent",
    "openclaw_metrics_endpoint_json_path": "/nonexistent",
    "os_apt_maintenance_freshness_max_age_seconds": 3600,
    "os_apt_maintenance_endpoint_state_max_age_seconds": 3600,
    "os_apt_maintenance_endpoint_bind": "127.0.0.1",
    "os_apt_maintenance_endpoint_port": 9,
    "os_apt_maintenance_endpoint_path": PROBE,
    "os_apt_maintenance_state_file": "/nonexistent",
    "os_apt_maintenance_endpoint_htpasswd_path": "/nonexistent",
    "thermal_metrics_endpoint_json_path": "/nonexistent",
    "thermal_metrics_endpoint_htpasswd_path": "/nonexistent",
    "torrent_vpn_metrics_endpoint_json_path": "/nonexistent",
    "torrent_vpn_metrics_endpoint_htpasswd_path": "/nonexistent",
}


def _json_args(port: int, tmp: Path) -> list[str]:
    return [
        *("--bind", "127.0.0.1", "--port", str(port), "--path", PROBE),
        *("--json-path", str(tmp / "data.json"), "--htpasswd-file", str(tmp / "htpasswd")),
    ]


def _obs_status_args(port: int, tmp: Path) -> list[str]:
    config = {
        "state_dir": str(tmp),
        "loki_url": "http://127.0.0.1:9",
        "loki_exclude_lines": [],
        "status_listen": f"127.0.0.1:{port}",
        "loop_window_seconds": 3600,
        "loop_events": 5,
        "cache_seconds": 60,
    }
    (tmp / "obs-config.json").write_text(json.dumps(config))
    # The endpoint imports obs_pack.py from its own directory, where the deploy puts both.
    (tmp / "obs_pack.py").write_text((SRC / "services/obs_daily/files/obs_pack.py").read_text())
    return ["--config", str(tmp / "obs-config.json")]


@dataclass(frozen=True)
class Server:
    path: str
    argv: Callable[[int, Path], list[str]] = _json_args
    env: Callable[[int], dict[str, str]] = field(default=lambda port: {})


SERVERS: dict[str, Server] = {
    "metrics_endpoint": Server(
        "services/metrics_endpoint/templates/metrics_httpd.py.j2",
        lambda port, tmp: [
            *("--bind", "127.0.0.1", "--port", str(port), "--path", PROBE, "--script", "/usr/bin/true"),
            *("--htpasswd-file", str(tmp / "htpasswd"), "--script-timeout", "5"),
        ],
    ),
    "torrent_vpn": Server("services/torrent_vpn_metrics_endpoint/templates/torrent_vpn_metrics_httpd.py.j2"),
    "thermal": Server("services/thermal_monitoring/templates/thermal_metrics_httpd.py.j2"),
    "fractal_storage": Server("services/fractal_monitoring/templates/storage_metrics_httpd.py.j2"),
    "fractal_backup": Server("services/fractal_monitoring/templates/backup_metrics_httpd.py.j2"),
    "tailscale": Server("infra/tailscale/templates/tailscale_metrics_httpd.py.j2"),
    "openclaw": Server("services/openclaw/templates/openclaw-metrics-httpd.py.j2"),
    "os_apt_maintenance": Server("services/os_apt_maintenance/templates/os_apt_maintenance_httpd.py.j2"),
    "dns_metrics": Server("services/dns_metrics_endpoint/templates/dns_metrics_httpd.py.j2"),
    "ddns_status": Server("services/dns/files/ddns_status_httpd.py"),
    "os_lifecycle": Server(
        "services/os_lifecycle/files/os_lifecycle_httpd.py",
        lambda port, tmp: [*_json_args(port, tmp), "--realm", "fixture", "--server-name", "fixture"],
    ),
    "rustfs_replication": Server(
        "services/rustfs/files/replication_status.py",
        lambda port, tmp: ["127.0.0.1", str(port), str(tmp), str(tmp / "jobs.json"), "600"],
    ),
    "logyard_health": Server(
        "services/logyard/files/logyard_health_httpd.py",
        lambda port, tmp: [],
        lambda port: {"LOGYARD_HEALTH_BIND": "127.0.0.1", "LOGYARD_HEALTH_PORT": str(port)},
    ),
    "static_site": Server("services/static_site/templates/static-site-httpd.py.j2", lambda port, tmp: []),
    "obs_daily_status": Server("services/obs_daily/files/obs_status.py", lambda port, tmp: _obs_status_args(port, tmp)),
}


def render(server: Server, port: int, tmp: Path) -> str:
    source = (SRC / server.path).read_text()
    if not server.path.endswith(".j2"):
        return source
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True, autoescape=False)
    env.filters["to_json"] = json.dumps
    site = SimpleNamespace(bind_host="127.0.0.1", port=port, site_path=str(tmp))
    return env.from_string(source).render(**TEMPLATE_VARS, cfg=site)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


def wait_listening(port: int, proc: subprocess.Popen[bytes], log: Path) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.fail(f"server exited with {proc.returncode}: {log.read_text()}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.05)
    pytest.fail(f"server never listened: {log.read_text()}")


def scrape(port: int, headers: dict[str, str] | None = None) -> http.client.HTTPResponse:
    """One request on its own connection; a stalled endpoint raises a timeout here."""

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request("GET", PROBE, headers={"Connection": "close", **(headers or {})})
    response = conn.getresponse()
    response.read()
    conn.close()
    return response


def closed_by_server(sock: socket.socket, within: float) -> bool:
    """Whether the server closes ``sock`` within ``within`` seconds (reading only)."""

    sock.settimeout(within)
    try:
        return sock.recv(1) == b""
    except ConnectionResetError:
        return True
    except TimeoutError:
        return False


def drip_until_closed(port: int, limit: float) -> float | None:
    """Send one byte every 0.5 s (well inside any read timeout); seconds until the server closes."""

    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    start = time.monotonic()
    try:
        while time.monotonic() - start < limit:
            try:
                sock.sendall(b"G")
            except OSError:
                return time.monotonic() - start
            if closed_by_server(sock, 0.5):
                return time.monotonic() - start
        return None
    finally:
        sock.close()


@pytest.fixture
def running(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[int]:
    server: Server = SERVERS[request.param]
    port = free_port()
    script = tmp_path / "server.py"
    # A shorter header deadline than production so the drip is cut off within seconds.
    script.write_text(
        render(server, port, tmp_path).replace(
            "BOUNDED_HTTPD_HEADER_DEADLINE = 15", f"BOUNDED_HTTPD_HEADER_DEADLINE = {DEADLINE}"
        )
    )
    log = tmp_path / "server.log"
    with log.open("wb") as sink:
        proc = subprocess.Popen(
            [sys.executable, "-I", str(script), *server.argv(port, tmp_path)],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", **server.env(port)},
            stdin=subprocess.DEVNULL,
            stdout=sink,
            stderr=sink,
        )
    try:
        wait_listening(port, proc, log)
        yield port
    finally:
        proc.kill()
        proc.wait(timeout=10)


@pytest.mark.parametrize("running", sorted(SERVERS), indirect=True)
def test_idle_partial_and_dripping_clients_do_not_stall_the_endpoint(running: int) -> None:
    port = running
    idle = socket.create_connection(("127.0.0.1", port), timeout=3)
    partial = socket.create_connection(("127.0.0.1", port), timeout=3)
    partial.sendall(b"GET " + PROBE.encode() + b" HTTP/1.1\r\nHost: fixture\r\n")
    try:
        time.sleep(0.2)
        # A scrape in parallel to the idle and the half-sent request still gets an answer.
        assert scrape(port).status in {200, 401, 404, 500, 503}
        # Both stalled clients are closed once the header deadline passes.
        assert closed_by_server(idle, DEADLINE + 3)
        assert closed_by_server(partial, DEADLINE + 3)
    finally:
        idle.close()
        partial.close()
    # A client that drips a byte every 0.5 s never hits a read timeout; the deadline cuts it.
    elapsed = drip_until_closed(port, DEADLINE + 6)
    assert elapsed is not None, "a dripping client held its connection past the header deadline"
    assert elapsed >= DEADLINE - 0.5
    assert scrape(port).status in {200, 401, 404, 500, 503}


def test_every_python_endpoint_carries_the_canonical_block() -> None:
    found = {
        str(path.relative_to(SRC))
        for path in SRC.rglob("*")
        if path.is_file()
        and path.suffix in {".py", ".j2"}
        and path != CANONICAL_PATH
        and re.search(r"serve_forever\(|HTTPServer|TCPServer", path.read_text())
    }
    assert found == {server.path for server in SERVERS.values()}
    begin, end = CANONICAL.splitlines()[0], CANONICAL.rstrip().splitlines()[-1]
    for name, server in SERVERS.items():
        text = (SRC / server.path).read_text()
        assert CANONICAL in text, f"{name}: the bounded-httpd block differs from {CANONICAL_PATH.name}"
        assert text.count(begin) == 1
        outside = text.replace(CANONICAL, "")
        assert end not in outside
        # No other server class: only the block's BoundedThreadingTCPServer serves.
        assert not re.search(r"\b(TCPServer|HTTPServer|ThreadingHTTPServer|ThreadingMixIn)\b", outside), name
        assert "BoundedThreadingTCPServer" in outside, name
        # Every handler class takes the deadline and the read timeout from the block.
        handlers = re.findall(r"^class (\w+)\(([^)]*)\):", outside, re.MULTILINE)
        handlers = [(cls, bases) for cls, bases in handlers if "Handler" in bases]
        assert handlers, name
        for cls, bases in handlers:
            assert bases.startswith("BoundedRequestMixin, "), f"{name}: {cls}({bases})"
        # The block sets the per-read timeout; a handler must not silently drop it.
        assert not re.search(r"^\s+timeout = None", outside, re.MULTILINE), name


def _canonical_scope(max_connections: int) -> dict[str, Any]:
    source = CANONICAL.replace("BOUNDED_HTTPD_HEADER_DEADLINE = 15", f"BOUNDED_HTTPD_HEADER_DEADLINE = {DEADLINE}")
    source = source.replace("BOUNDED_HTTPD_MAX_CONNECTIONS = 32", f"BOUNDED_HTTPD_MAX_CONNECTIONS = {max_connections}")
    scope: dict[str, Any] = {"__name__": "bounded_httpd_fixture"}
    exec(compile(source, str(CANONICAL_PATH), "exec"), scope)
    return scope


# The socket timeout each response of the canonical fixture server was written with.
RESPONSE_TIMEOUTS: list[float | None] = []


@pytest.fixture
def canonical_server() -> Iterator[int]:
    import http.server

    scope = _canonical_scope(max_connections=2)
    mixin: Any = scope["BoundedRequestMixin"]

    class Handler(mixin, http.server.BaseHTTPRequestHandler):  # type: ignore[misc]
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            RESPONSE_TIMEOUTS.append(self.connection.gettimeout())
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:
            return

    server = scope["BoundedThreadingTCPServer"](("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_connections_beyond_the_cap_are_closed_and_slots_come_back(canonical_server: int) -> None:
    port = canonical_server
    held = [socket.create_connection(("127.0.0.1", port), timeout=3) for _ in range(2)]
    time.sleep(0.2)
    extra = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        assert closed_by_server(extra, 1.5), "a connection beyond the cap was not closed at accept"
    finally:
        extra.close()
    for sock in held:
        sock.close()
    time.sleep(0.3)
    assert scrape(port).status == 200


def test_an_idle_keep_alive_connection_is_closed_after_its_deadline(canonical_server: int) -> None:
    port = canonical_server
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request("GET", PROBE)
    response = conn.getresponse()
    assert response.read() == b"ok"
    # The deadline is armed again for the next request on the same connection.
    sock = conn.sock
    assert sock is not None
    start = time.monotonic()
    assert closed_by_server(sock, DEADLINE + 3)
    assert time.monotonic() - start >= DEADLINE - 0.5
    conn.close()


def test_a_slow_but_steady_request_within_the_deadline_is_served(canonical_server: int) -> None:
    port = canonical_server
    RESPONSE_TIMEOUTS.clear()
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        for chunk in (b"GET /probe HTTP/1.1\r\n", b"Host: fixture\r\n", b"Connection: close\r\n", b"\r\n"):
            sock.sendall(chunk)
            time.sleep(0.3)
        data = sock.recv(4096)
        assert data.startswith(b"HTTP/1.1 200 ")
    finally:
        sock.close()
    # The response is written with the full read timeout, not the rest of the header deadline.
    assert RESPONSE_TIMEOUTS == [10]


def test_metrics_script_stderr_stays_out_of_the_status_line(tmp_path: Path) -> None:
    port = free_port()
    script = tmp_path / "server.py"
    script.write_text(render(SERVERS["metrics_endpoint"], port, tmp_path))
    collector = tmp_path / "collector.sh"
    collector.write_text("#!/bin/sh\nprintf 'first line /secret/path\\nsecond line \\303\\244\\n' >&2\nexit 3\n")
    collector.chmod(0o755)
    (tmp_path / "htpasswd").write_text(f"nyxmon:{hash_password(VALUE)}\n")
    log = tmp_path / "server.log"
    argv = [
        *("--bind", "127.0.0.1", "--port", str(port), "--path", PROBE, "--script", str(collector)),
        *("--htpasswd-file", str(tmp_path / "htpasswd"), "--script-timeout", "5"),
    ]
    with log.open("wb") as sink:
        proc = subprocess.Popen(
            [sys.executable, "-I", str(script), *argv],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            stdin=subprocess.DEVNULL,
            stdout=sink,
            stderr=sink,
        )
    try:
        wait_listening(port, proc, log)
        auth = "Basic " + base64.b64encode(f"nyxmon:{VALUE}".encode()).decode()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", PROBE, headers={"Authorization": auth, "Connection": "close"})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        assert response.status == 502
        assert response.reason == "Metrics script failed"
        assert b"secret" not in body
        assert b"second line" not in body
    finally:
        proc.kill()
        proc.wait(timeout=10)
    # The collector's stderr goes to the journal instead.
    logged = log.read_text(errors="replace")
    assert "first line /secret/path" in logged
    assert "second line" in logged
