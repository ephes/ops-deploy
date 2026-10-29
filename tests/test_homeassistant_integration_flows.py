"""Synthetic local HTTP and disposable registry only; prepared prototype proof."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "ha_flow_prototype", str(files("ops_deploy.services.homeassistant").joinpath("files/integration_flow.py"))
)
assert SPEC is not None
assert SPEC.loader is not None
flow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flow)


@pytest.fixture(autouse=True)
def owned_netrc_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Preserve original URI semantics without reading controller credentials.
    monkeypatch.setenv("NETRC", str(tmp_path / "owned-missing-netrc"))


def payload(tmp_path: Path, domain: str = "matter") -> dict[str, Any]:
    desired = {"host": "owned-wyoming", "port": 10300} if domain == "wyoming" else {"url": "ws://owned-matter:5580/ws"}
    return {
        "action": "inspect",
        "domain": domain,
        "config_path": str(tmp_path),
        "desired": desired,
        "api": {
            "url": "",
            "token": "synthetic-private-bearer",
            "timeout": 2,
            "retries": 0,
            "retry_delay": 0,
            "forwarded_for": "",
            "forwarded_proto": "http",
            "validate_certs": True,
        },
    }


def registry(tmp_path: Path, entries: list[dict[str, Any]]) -> None:
    folder = tmp_path / ".storage"
    folder.mkdir(exist_ok=True)
    (folder / "core.config_entries").write_text(json.dumps({"data": {"entries": entries}}))


@pytest.mark.parametrize("domain", ["matter", "otbr", "wyoming"])
def test_first_matching_original_selection_current_and_other_entries(tmp_path: Path, domain: str) -> None:
    value = payload(tmp_path, domain)
    registry(
        tmp_path,
        [
            {"domain": "unrelated", "data": {"private": "never export"}},
            {"domain": domain, "entry_id": "selected", "data": value["desired"]},
            {"domain": domain, "entry_id": "later", "data": {"url": "ws://other", "host": "other", "port": 1}},
        ],
    )
    result = flow.run(value)
    assert result["success"]
    assert not result["needed"]
    assert result["http_requests"] == 0
    assert not result["changed"]
    assert "never export" not in json.dumps(result)


def test_url_first_match_not_later_matching_entry(tmp_path: Path) -> None:
    value = payload(tmp_path)
    registry(
        tmp_path, [{"domain": "matter", "data": {"url": "ws://old"}}, {"domain": "matter", "data": value["desired"]}]
    )
    assert flow.run(value)["needed"]


def test_wyoming_port_equality_not_string_coercion(tmp_path: Path) -> None:
    value = payload(tmp_path, "wyoming")
    registry(tmp_path, [{"domain": "wyoming", "entry_id": "owned", "data": {"host": "owned-wyoming", "port": "10300"}}])
    assert flow.run(value)["needed"]


@pytest.mark.parametrize("body", ["invalid-private-json", "[]"])
def test_malformed_registry_fails_without_body(tmp_path: Path, body: str) -> None:
    folder = tmp_path / ".storage"
    folder.mkdir()
    (folder / "core.config_entries").write_text(body)
    result = flow.run(payload(tmp_path))
    assert not result["success"]
    assert result["http_requests"] == 0
    assert not result["changed"]
    assert body not in json.dumps(result)


@pytest.mark.parametrize("outcome", ["create", "already", "start-fail", "submit-fail", "post-redirect", "get-redirect"])
def test_actual_loopback_http_flow_and_partial_outcomes(tmp_path: Path, outcome: str) -> None:
    requests: list[tuple[str, str, Any, dict[str, str]]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def reply(self, status: int, value: dict[str, Any], location: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if location:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(json.dumps(value).encode())

        def do_GET(self) -> None:
            requests.append(("GET", self.path, None, dict(self.headers)))
            if outcome == "get-redirect" and self.path == "/api/":
                self.reply(302, {}, "/ready")
            else:
                self.reply(200, {"message": "synthetic-ready"})

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(("POST", self.path, body, dict(self.headers)))
            if self.path.endswith("/flow"):
                if outcome == "start-fail":
                    self.reply(200, {"type": "abort", "reason": "private-failure-detail"})
                elif outcome == "already":
                    self.reply(200, {"type": "abort", "reason": "already_configured"})
                elif outcome == "post-redirect":
                    self.reply(302, {}, "/must-not-follow")
                else:
                    self.reply(200, {"type": "form", "flow_id": "owned-id"})
            elif outcome == "submit-fail":
                self.reply(200, {"type": "form", "errors": {"base": "private-failure-detail"}})
            else:
                self.reply(200, {"type": "create_entry", "data": {"private": "never-output"}})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        value = payload(tmp_path)
        value["action"] = "apply"
        value["api"]["url"] = f"http://127.0.0.1:{server.server_port}"
        result = flow.run(value)
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
    assert result["success"] is (outcome in ("create", "already", "get-redirect"))
    assert result["changed"]
    assert result["mutation_attempts"] == (1 if outcome in ("already", "start-fail", "post-redirect") else 2)
    assert not any(r[1] == "/must-not-follow" for r in requests)
    assert all(r[3]["Authorization"] == "Bearer synthetic-private-bearer" for r in requests)
    assert all(r[3]["X-Forwarded-For"] == "127.0.0.1" for r in requests)
    assert all("private" not in str(v) and "owned-id" not in str(v) for v in result.values())
    if outcome == "get-redirect":
        assert requests[1][1] == "/ready"


@pytest.mark.parametrize("diff", [False, True])
def test_actual_sdk_plan_apply_shared_readiness_and_strict_repeat(
    tmp_path: Path, diff: bool, caplog: pytest.LogCaptureFixture
) -> None:
    from pydantic import SecretStr
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant.integration_flows import (
        ApiReadiness,
        HomeAssistantApiConfig,
        IntegrationSelection,
        integrate,
    )
    from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
    from ops_deploy.testing.harness import collect_ops

    calls: list[tuple[str, str]] = []
    entries: list[dict[str, Any]] = []
    registry(tmp_path, entries)
    path = tmp_path / ".storage/core.config_entries"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            calls.append(("GET", self.path))
            self.send_response(200)
            self.end_headers()

        def do_POST(self) -> None:
            calls.append(("POST", self.path))
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path.endswith("/flow"):
                result = {"type": "form", "flow_id": body["handler"]}
            else:
                domain = self.path.rsplit("/", 1)[-1]
                entries.append({"domain": domain, "entry_id": "owned-" + domain, "data": body})
                registry(tmp_path, entries)
                result = {"type": "create_entry"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    private_value = "owned-synthetic-long-lived-bearer-0123456789"
    api = HomeAssistantApiConfig(
        url=SecretStr(f"http://127.0.0.1:{server.server_port}"),
        token=SecretStr(private_value),
        timeout=2,
        retries=0,
        retry_delay=0,
    )
    runtime = HomeAssistantRuntimeConfig(config_path=str(tmp_path))
    selections = (
        IntegrationSelection(domain="matter", url=SecretStr("ws://owned-matter:5580/ws")),
        IntegrationSelection(domain="otbr", url=SecretStr("http://owned-otbr:8081")),
        IntegrationSelection(domain="wyoming", wyoming_host="owned-wyoming", wyoming_port=10300),
    )

    def snapshot() -> tuple[bytes, tuple[int, ...]]:
        stat = path.stat()
        return path.read_bytes(), (
            stat.st_mode,
            stat.st_uid,
            stat.st_gid,
            stat.st_ino,
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
        )

    try:
        for repeat in (False, True):
            readiness = ApiReadiness()
            state = State(Inventory(([("@local", {})], {})), Config(DIFF=diff))
            before = snapshot()
            count_before = len(calls)

            def deploy(readiness: ApiReadiness = readiness) -> None:
                for selection in selections:
                    integrate(runtime, api, selection, readiness)

            try:
                connect_all(state)
                add_deploy(state, deploy)
                assert len(calls) == count_before  # genuine plan never requests API
                assert snapshot() == before
                run_ops(state)
                ops = collect_ops(state, "@local")
                assert all(op.succeeded for op in ops)
                assert sum(op.changed for op in ops) == (0 if repeat else 3)
                if repeat:
                    assert snapshot() == before
                    assert len(calls) == count_before
                else:
                    assert [method for method, _ in calls] == ["GET", "POST", "POST", "POST", "POST", "POST", "POST"]
                    assert readiness.ready
            finally:
                disconnect_all(state)
        assert private_value not in caplog.text
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize("domain", ["matter", "otbr", "wyoming"])
@pytest.mark.parametrize("case", ["missing", "unrelated", "current", "later-current", "wrong-port-type"])
def test_original_task_selector_expression_matches_host_result(tmp_path: Path, domain: str, case: str) -> None:
    import base64

    import jinja2
    import yaml
    from jinja2.nativetypes import NativeEnvironment

    value = payload(tmp_path, domain)
    current = {"domain": domain, "entry_id": "current", "data": value["desired"]}
    other = {"domain": domain, "entry_id": "other", "data": {"url": "ws://old", "host": "old", "port": 1}}
    entries = {
        "missing": [],
        "unrelated": [{"domain": "other", "data": {"private": "never-export"}}],
        "current": [current],
        "later-current": [other, current],
        "wrong-port-type": [
            {"domain": domain, "entry_id": "wrong-type", "data": {"host": "owned-wyoming", "port": "10300"}}
        ],
    }[case]
    fixture = Path(__file__).parent / "parity/homeassistant/integration-flows"
    tasks = yaml.safe_load((fixture / f"{domain}.yml").read_text())
    expression = next(task["ansible.builtin.set_fact"] for task in tasks if task["name"].startswith("Extract existing"))
    template = next(iter(expression.values()))
    env = NativeEnvironment(undefined=jinja2.ChainableUndefined)
    env.filters["b64decode"] = lambda text: base64.b64decode(text).decode()
    env.filters["from_json"] = json.loads
    context = {
        "_ha_config_entries_raw": {
            "content": base64.b64encode(json.dumps({"data": {"entries": entries}}).encode()).decode()
        },
        "homeassistant_wyoming_host": "owned-wyoming",
        "homeassistant_wyoming_port": 10300,
    }
    selected = env.from_string(template).render(**context)
    expected = len(selected) == 0 if domain == "wyoming" else selected != value["desired"]["url"]
    registry(tmp_path, entries)
    result = flow.run(value)
    assert result["success"]
    assert result["needed"] is expected


def test_original_flow_source_hashes_and_ready_defaults() -> None:
    import hashlib
    import os

    import yaml

    from ops_deploy.services.homeassistant.integration_flows import HomeAssistantApiConfig

    fixture = Path(__file__).parent / "parity/homeassistant/integration-flows"
    manifest = json.loads((fixture / "source.json").read_text())
    for relative, row in manifest["files"].items():
        assert hashlib.sha256((fixture / row["fixture"]).read_bytes()).hexdigest() == row["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            original = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles/homeassistant_deploy" / relative
            assert hashlib.sha256(original.read_bytes()).hexdigest() == row["sha256"]
    defaults = yaml.safe_load((fixture / "defaults.yml").read_text())
    cfg = HomeAssistantApiConfig()
    for key in ("timeout", "validate_certs", "retries", "retry_delay", "forwarded_for", "forwarded_proto"):
        assert getattr(cfg, key) == defaults["homeassistant_api_" + key]
    assert cfg.url.get_secret_value() == "http://localhost:" + str(defaults["homeassistant_app_port"])


@pytest.mark.parametrize(
    "mode", ["netrc", "netrc-empty-url", "get-cookie", "gzip", "invalid-first", "text-first", "invalid-submit", "retry"]
)
def test_original_uri_transport_details_with_owned_endpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    import base64
    import gzip

    calls: list[tuple[str, str, dict[str, str]]] = []
    if mode in ("netrc", "netrc-empty-url"):
        path = tmp_path / "owned-netrc"
        path.write_text("machine 127.0.0.1 login owned-user password owned-password\n")
        path.chmod(0o600)
        monkeypatch.setenv("NETRC", str(path))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def answer(self, body: bytes, content_type: str = "application/json", code: int = 200) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            if mode == "gzip":
                body = gzip.compress(body)
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            calls.append(("GET", self.path, dict(self.headers)))
            if mode == "get-cookie" and self.path == "/api/":
                self.send_response(302)
                self.send_header("Location", "/ready")
                self.send_header("Set-Cookie", "owned=present; Path=/")
                self.end_headers()
            elif mode == "get-cookie" and self.headers.get("Cookie") != "owned=present":
                self.answer(b"{}", code=403)
            elif mode == "retry" and len(calls) == 1:
                self.answer(b"{}", code=503)
            else:
                self.answer(b"{}")

        def do_POST(self) -> None:
            calls.append(("POST", self.path, dict(self.headers)))
            self.rfile.read(int(self.headers["Content-Length"]))
            if self.path.endswith("/flow"):
                if mode == "invalid-first":
                    self.answer(b"invalid-private-response")
                elif mode == "text-first":
                    self.answer(b'{"flow_id":"must-not-submit"}', "text/plain")
                else:
                    self.answer(b'{"type":"form","flow_id":"owned"}')
            elif mode == "invalid-submit":
                self.answer(b"invalid-private-response")
            else:
                self.answer(b'{"type":"create_entry"}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        value = payload(tmp_path)
        value["action"] = "apply"
        value["api"]["url"] = f"http://127.0.0.1:{server.server_port}"
        if mode == "netrc-empty-url":
            value["api"]["url"] = value["api"]["url"].replace("http://", "http://@")
        value["api"]["retries"] = 1
        result = flow.run(value)
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
    assert result["success"] is (mode not in ("invalid-first", "text-first", "invalid-submit"))
    assert result["mutation_attempts"] == (1 if mode in ("invalid-first", "text-first") else 2)
    assert result["changed"]
    assert "invalid-private-response" not in json.dumps(result)
    expected_auth = "Bearer synthetic-private-bearer"
    if mode in ("netrc", "netrc-empty-url"):
        expected_auth = "Basic " + base64.b64encode(b"owned-user:owned-password").decode()
    assert all(headers["Authorization"] == expected_auth for _, _, headers in calls)
    assert all(headers.get("User-Agent") == "ansible-httpget" for _, _, headers in calls)
    # Each original URI task has its own cookie jar. A readiness redirect cookie
    # is not carried into the separate configuration POST tasks.
    assert all("Cookie" not in headers for method, _, headers in calls if method == "POST")
    if mode == "retry":
        assert sum(method == "GET" for method, _, _ in calls) == 2


@pytest.mark.parametrize("shell", ["bash", "fish"])
def test_actual_encoded_inspection_stdin_and_no_value_export(tmp_path: Path, shell: str) -> None:
    import shutil
    import subprocess

    from ops_deploy.services.homeassistant.integration_flows import flow_command
    from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(shell + " unavailable")
    value = payload(tmp_path)
    registry(tmp_path, [{"domain": "matter", "data": value["desired"]}])
    result = subprocess.run(
        [executable, "-c", flow_command(HomeAssistantRuntimeConfig())],
        input=json.dumps(value),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["success"]
    assert not report["needed"]
    assert report["http_requests"] == 0
    assert "owned-matter" not in result.stdout + result.stderr
    assert "synthetic-private-bearer" not in result.stdout + result.stderr


def test_original_selected_token_guard_precedes_any_host_work() -> None:
    from pydantic import SecretStr

    from ops_deploy.services.homeassistant.integration_flows import (
        ApiReadiness,
        HomeAssistantApiConfig,
        IntegrationSelection,
        integrate,
    )
    from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

    value = "owned-invalid-short"
    with pytest.raises(ValueError, match="long-lived token") as error:
        integrate(
            HomeAssistantRuntimeConfig(),
            HomeAssistantApiConfig(token=SecretStr(value)),
            IntegrationSelection(domain="matter", url=SecretStr("ws://owned")),
            ApiReadiness(),
        )
    assert value not in str(error.value)


def test_configured_system_python_is_actually_executed(tmp_path: Path) -> None:
    import sys

    from pydantic import SecretStr
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant.integration_flows import (
        ApiReadiness,
        HomeAssistantApiConfig,
        IntegrationSelection,
        integrate,
    )
    from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
    from ops_deploy.testing.harness import collect_ops

    marker = tmp_path / "interpreter-invoked"
    executable = tmp_path / "owned-python"
    executable.write_text(
        f"#!{sys.executable}\nimport os,sys\nfrom pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('invoked')\n"
        f"os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n"
    )
    executable.chmod(0o700)
    cfg = HomeAssistantRuntimeConfig(config_path=str(tmp_path), security={"system_python": str(executable)})
    selection = IntegrationSelection(domain="matter", url=SecretStr("ws://owned-current"))
    registry(tmp_path, [{"domain": "matter", "data": {"url": "ws://owned-current"}}])
    api = HomeAssistantApiConfig(token=SecretStr("owned-synthetic-long-lived-bearer-0123456789"))
    state = State(Inventory(([("@local", {})], {})), Config())
    try:
        connect_all(state)
        add_deploy(state, integrate, cfg, api, selection, ApiReadiness())
        assert marker.read_text() == "invoked"
        run_ops(state)
        assert not any(op.changed for op in collect_ops(state, "@local"))
    finally:
        disconnect_all(state)


def test_actual_helper_wall_deadline_retains_attempt_and_never_submits(tmp_path: Path) -> None:
    import subprocess
    import time

    from ops_deploy.services.homeassistant.integration_flows import flow_command
    from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

    requests: list[str] = []
    finished = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            requests.append(self.path)
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                self.wfile.write(b'{"flow_id":"owned-never-submit","private":"')
                self.wfile.flush()
                # Every recv has data well inside the configured socket timeout;
                # only the independent whole-helper deadline ends this request.
                for _ in range(200):
                    time.sleep(0.03)
                    self.wfile.write(b"x")
                    self.wfile.flush()
                self.wfile.write(b'"}')
            except OSError:
                pass
            finally:
                finished.set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        value = payload(tmp_path)
        value.update(action="apply", ready=True, deadline_seconds=0.2)
        value["api"]["timeout"] = 1
        value["api"]["url"] = f"http://127.0.0.1:{server.server_port}"
        started = time.monotonic()
        result = subprocess.run(
            ["bash", "-c", "exec " + flow_command(HomeAssistantRuntimeConfig())],
            input=json.dumps(value),
            capture_output=True,
            text=True,
            timeout=3,
        )
        elapsed = time.monotonic() - started
        assert result.returncode == 1
        report = json.loads(result.stdout)
        assert report["error"] == "DeadlineExceeded"
        assert report["phase"] == "start-flow"
        assert report["mutation_attempts"] == 1
        assert report["changed"]
        assert elapsed < 2
        assert "owned-never-submit" not in result.stdout + result.stderr
        assert finished.wait(2)
        assert requests == ["/api/config/config_entries/flow"]
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
        assert finished.wait(2)


@pytest.mark.parametrize("outcome", ["success", "failed-start"])
def test_late_deadline_during_actual_cleanup_keeps_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], outcome: str
) -> None:
    import io
    import signal
    from email.message import Message

    requests: list[str] = []

    class Response:
        status = 200

        def __init__(self, body: dict[str, Any]):
            self.headers = Message()
            self.headers["Content-Type"] = "application/json"
            self.body = body

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def read(self) -> bytes:
            return json.dumps(self.body).encode()

    class Opener:
        def open(self, request: Any, **kwargs: Any) -> Response:
            requests.append(request.full_url)
            if len(requests) == 1:
                if outcome == "failed-start":
                    return Response({"type": "abort", "reason": "owned-error"})
                return Response({"type": "form", "flow_id": "owned"})
            return Response({"type": "create_entry"})

    monkeypatch.setattr(flow, "request_transport", lambda url, *args: (url, Opener()))
    old_handler = signal.getsignal(signal.SIGALRM)
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    actual_setitimer = signal.setitimer
    injected = False

    def expire_during_disarm(which: int, seconds: float, interval: float = 0) -> tuple[float, float]:
        nonlocal injected
        if seconds == 0 and not injected:
            injected = True
            handler = signal.getsignal(signal.SIGALRM)
            assert callable(handler)
            handler(signal.SIGALRM, None)
        return actual_setitimer(which, seconds, interval)

    monkeypatch.setattr(flow.signal, "setitimer", expire_during_disarm)
    value = payload(tmp_path)
    value.update(action="apply", ready=True, deadline_seconds=60)
    value["api"]["url"] = "http://owned.invalid"
    monkeypatch.setattr(flow.sys, "stdin", io.StringIO(json.dumps(value)))
    try:
        result = flow.main()
        assert result == 1
        assert injected
        report = json.loads(capsys.readouterr().out)
        assert report["error"] == "DeadlineExceeded"
        assert report["phase"] == ("complete" if outcome == "success" else "start-flow")
        assert report["mutation_attempts"] == (2 if outcome == "success" else 1)
        assert len(requests) == report["mutation_attempts"]
        assert report["changed"]
        assert not report["success"]
    finally:
        actual_setitimer(signal.ITIMER_REAL, *old_timer)
        signal.signal(signal.SIGALRM, old_handler)


@pytest.mark.parametrize(
    ("cached", "failures", "expected_success", "requests"),
    [(True, 9, True, 0), (False, 0, True, 1), (False, 1, True, 2), (False, 3, False, 3)],
)
def test_standalone_readiness_has_no_registry_or_post_and_preserves_retries(
    tmp_path: Path, cached: bool, failures: int, expected_success: bool, requests: int
) -> None:
    calls: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            calls.append(self.path)
            self.send_response(503 if len(calls) <= failures else 200)
            self.end_headers()
            self.wfile.write(b"synthetic private status body is not exported")

        def do_POST(self) -> None:
            raise AssertionError("readiness must never POST")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        api = payload(tmp_path)["api"]
        api.update(url=f"http://127.0.0.1:{server.server_port}", retries=2)
        # Deliberately no config_path/domain/desired: readiness must not open a registry.
        result = flow.run({"action": "readiness", "api": api, "ready": cached})
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
    assert result["success"] is expected_success
    assert result["ready"] is expected_success
    assert calls == ["/api/"] * requests
    assert result["http_requests"] == requests
    assert result["mutation_attempts"] == 0
    assert result["changed"] is False
    assert result["needed"] is False
    assert "synthetic private" not in json.dumps(result)


@pytest.mark.parametrize("diff", [False, True])
@pytest.mark.parametrize("wrong_registration_time_reset", [False, True])
def test_actual_sdk_readiness_reset_occurs_at_handler_boundary(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, diff: bool, wrong_registration_time_reset: bool
) -> None:
    from pydantic import SecretStr
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant.integration_flows import (
        ApiReadiness,
        HomeAssistantApiConfig,
        ensure_api_readiness,
        reset_api_readiness,
    )
    from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
    from ops_deploy.testing.harness import collect_ops

    calls: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            calls.append(self.path)
            assert self.headers["Authorization"] == "Bearer owned-only-token-0123456789-0123456789"
            self.send_response(200)
            self.end_headers()

        def do_POST(self) -> None:
            raise AssertionError("no managed API call expected")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    readiness = ApiReadiness()
    api = HomeAssistantApiConfig(
        url=SecretStr(f"http://127.0.0.1:{server.server_port}"),
        token=SecretStr("owned-only-token-0123456789-0123456789"),
        retries=0,
        retry_delay=0,
        timeout=2,
    )
    runtime = HomeAssistantRuntimeConfig(config_path=str(tmp_path))
    state = State(Inventory(([("@local", {})], {})), Config(DIFF=diff))

    def deploy() -> None:
        ensure_api_readiness(runtime, api, readiness)
        ensure_api_readiness(runtime, api, readiness)
        # The negative reproduces the tempting but wrong plain Python reset:
        # registration finishes before the first readiness operation executes.
        if wrong_registration_time_reset:
            readiness.ready = False
        else:
            reset_api_readiness(readiness)
        ensure_api_readiness(runtime, api, readiness)

    try:
        connect_all(state)
        add_deploy(state, deploy)
        assert calls == []
        assert readiness.ready is False
        run_ops(state)
        operations = collect_ops(state, "@local")
        assert all(op.succeeded for op in operations)
        assert all(op.read_only for op in operations)
        assert sum(op.changed and not op.read_only for op in operations) == 0
        assert calls == ["/api/"] * (1 if wrong_registration_time_reset else 2)
        assert readiness.ready is True
        assert "owned-only-token" not in caplog.text
    finally:
        disconnect_all(state)
        server.shutdown()
        server.server_close()
        worker.join()


def test_readiness_retries_malformed_http_status_like_original_uri(tmp_path: Path) -> None:
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            requests.append(self.path)
            if len(requests) == 1:
                self.wfile.write(b"owned malformed status\r\n\r\n")
                self.close_connection = True
                return
            self.send_response(200)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        value = payload(tmp_path)
        value["action"] = "readiness"
        value["api"]["url"] = f"http://127.0.0.1:{server.server_port}"
        value["api"]["retries"] = 1
        result = flow.run(value)
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
    assert result["success"]
    assert result["ready"]
    assert requests == ["/api/", "/api/"]
    assert result["http_requests"] == 2
    assert result["mutation_attempts"] == 0
    assert not result["changed"]


def test_readiness_total_deadline_is_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def transport(*args: Any) -> Any:
        calls.append(True)
        raise flow.DeadlineExceeded()

    monkeypatch.setattr(flow, "request_transport", transport)
    value = payload(tmp_path)
    value["action"] = "readiness"
    value["api"]["url"] = "http://owned"
    value["api"]["retries"] = 3
    result = flow.run(value)
    assert not result["success"]
    assert result["error"] == "DeadlineExceeded"
    assert calls == [True]
    assert result["mutation_attempts"] == 0
