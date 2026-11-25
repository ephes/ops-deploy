import datetime as dt
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar
from urllib.request import Request, urlopen

import pytest

from ops_deploy.core.templates import render
from ops_deploy.services.voice_session_proxy import VoiceSessionProxyConfig, deploy_voice_session_proxy
from ops_deploy.services.voice_session_proxy.deploy import ROOT, TEMPLATE_PACKAGE
from ops_deploy.testing import run_deploy_fake

SCRIPT = ROOT / "files/voice_session_proxy.py"
HOST_DATA = {"ssh_hostname": "macmini.example.invalid", "ssh_user": "deploy"}
HA_SYSTEM = (
    "You answer questions from the family's shared voice satellite.\n"
    "Current time is 15:42:07. Today's date is 2026-11-25.\n"
)


def _load_proxy() -> Any:
    spec = importlib.util.spec_from_file_location("voice_session_proxy", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


proxy = _load_proxy()


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (dt.datetime(2026, 11, 25, 15, 0), "voice-wohnzimmer-2026-11-25"),
        (dt.datetime(2026, 11, 26, 3, 59), "voice-wohnzimmer-2026-11-25"),
        (dt.datetime(2026, 11, 26, 4, 0), "voice-wohnzimmer-2026-11-26"),
    ],
)
def test_session_day_rolls_over_at_rollover_hour(now: dt.datetime, expected: str) -> None:
    assert proxy.session_user("voice-wohnzimmer", now, 4) == expected


def test_rewrite_keeps_system_without_time_and_only_the_last_user_turn() -> None:
    payload = {
        "model": "openclaw",
        "user": "01HACONVERSATIONID",
        "stream": True,
        "messages": [
            {"role": "system", "content": HA_SYSTEM},
            {"role": "user", "content": "Wie hoch ist die Zugspitze?"},
            {"role": "assistant", "content": "2962 Meter."},
            {"role": "user", "content": "Und der Watzmann?"},
        ],
    }

    out = proxy.rewrite_chat_request(payload, "voice-wohnzimmer-2026-11-25")

    assert out["user"] == "voice-wohnzimmer-2026-11-25"
    assert out["stream"] is True
    assert out["messages"] == [
        {"role": "system", "content": "You answer questions from the family's shared voice satellite."},
        {"role": "user", "content": "Und der Watzmann?"},
    ]
    assert payload["user"] == "01HACONVERSATIONID"  # input not mutated


@pytest.mark.parametrize(
    "messages",
    [
        [],
        [{"role": "user", "content": "x"}, {"role": "tool", "content": "y", "tool_call_id": "1"}],
        "not a list",
    ],
)
def test_rewrite_leaves_unusual_requests_alone(messages: Any) -> None:
    payload = {"model": "openclaw", "user": "u", "messages": messages}
    assert proxy.rewrite_chat_request(payload, "voice-x") is payload


class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: ClassVar[list[dict[str, Any]]] = []

    def log_message(self, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        body = b'{"data": [{"id": "openclaw"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Upstream.seen.append({"auth": self.headers.get("Authorization"), "body": body})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for event in (b'data: {"choices":[{"delta":{"content":"Hallo"}}]}\n\n', b"data: [DONE]\n\n"):
            self.wfile.write(f"{len(event):x}\r\n".encode() + event + b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")


def _serve(server: ThreadingHTTPServer) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


def test_proxy_rewrites_chat_requests_and_streams_responses_through() -> None:
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    _serve(upstream)
    settings = proxy.Settings(
        {"VOICE_PROXY_UPSTREAM": f"http://127.0.0.1:{upstream.server_address[1]}", "VOICE_PROXY_LISTEN_PORT": "0"}
    )
    front = ThreadingHTTPServer(("127.0.0.1", 0), proxy.make_handler(settings))
    _serve(front)
    base = f"http://127.0.0.1:{front.server_address[1]}"
    try:
        with urlopen(Request(base + "/v1/models", headers={"Authorization": "Bearer t"}), timeout=5) as resp:
            assert json.load(resp)["data"][0]["id"] == "openclaw"

        request = {
            "model": "openclaw",
            "user": "01HA",
            "stream": True,
            "messages": [{"role": "system", "content": HA_SYSTEM}, {"role": "user", "content": "Hallo?"}],
        }
        req = Request(
            base + "/v1/chat/completions",
            data=json.dumps(request).encode(),
            headers={"Authorization": "Bearer t", "Content-Type": "application/json"},
        )
        with urlopen(req, timeout=5) as resp:
            assert resp.headers["Content-Type"] == "text/event-stream"
            streamed = resp.read()
    finally:
        front.shutdown()
        upstream.shutdown()

    assert streamed == b'data: {"choices":[{"delta":{"content":"Hallo"}}]}\n\ndata: [DONE]\n\n'
    forwarded = _Upstream.seen[-1]
    assert forwarded["auth"] == "Bearer t"
    assert forwarded["body"]["user"].startswith("voice-wohnzimmer-")
    assert "Current time" not in json.dumps(forwarded["body"])


def test_config_rejects_non_loopback_upstream() -> None:
    with pytest.raises(ValueError, match="loopback"):
        VoiceSessionProxyConfig(upstream_url="http://example.com:18789")


def test_first_deploy_installs_script_and_unit_and_starts_service() -> None:
    cfg = VoiceSessionProxyConfig()

    run = run_deploy_fake(deploy_voice_session_proxy, cfg, host_data=HOST_DATA)

    assert run.succeeded, run.error
    assert run.uploaded_paths == [str(cfg.script_path), str(cfg.unit_path)]
    assert run.upload(str(cfg.script_path)) == SCRIPT.read_bytes()
    unit = render(TEMPLATE_PACKAGE, "voice-session-proxy.service.j2", cfg=cfg)
    assert run.upload(str(cfg.unit_path)) == unit.encode()
    assert "Environment=VOICE_PROXY_UPSTREAM=http://127.0.0.1:18789" in unit
    assert "DynamicUser=yes" in unit
    commands = run.executed_commands
    assert "systemctl daemon-reload" in commands
    assert "systemctl enable voice-session-proxy.service" in commands
    assert Path(cfg.script_path).name == "voice_session_proxy.py"
