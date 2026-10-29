"""Owned native fixture transport controls, not HA application qualification."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tests.integration.homeassistant.model_server import MODEL, ModelServer


def test_actual_loopback_model_fixed_replies_streaming_and_faults(capsys: pytest.CaptureFixture[str]) -> None:
    with ModelServer(0) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}"

        def request(path: str, body: object | None = None) -> bytes:
            req = urllib.request.Request(
                url + path,
                data=None if body is None else json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return bytes(response.read())

        try:
            assert json.loads(request("/v1/models"))["data"][0]["id"] == MODEL
            payload = {"model": MODEL, "messages": [{"role": "user", "content": "never-log-this-synthetic-text"}]}
            result = json.loads(request("/v1/chat/completions", payload))
            assert result["choices"][0]["message"]["content"] == "OK"
            stream = request("/v1/chat/completions", {**payload, "stream": True})
            assert stream.endswith(b"data: [DONE]\n\n")
            chunks = [
                json.loads(line.removeprefix(b"data: ")) for line in stream.splitlines() if line.startswith(b"data: {")
            ]
            assert "".join(item["choices"][0]["delta"].get("content", "") for item in chunks) == "OK"
            assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
            assert json.loads(request("/owned/status")) == {"models": 1, "completions": 2, "streaming": 1}
            request("/owned/fault", {"mode": "empty"})
            assert json.loads(request("/chat/completions", payload))["choices"][0]["message"]["content"] == ""
            request("/owned/fault", {"mode": "unauthorized"})
            with pytest.raises(urllib.error.HTTPError) as caught:
                request("/v1/chat/completions", payload)
            assert caught.value.code == 401
            request("/owned/fault", {"mode": "normal"})
            assert json.loads(request("/v1/chat/completions", payload))["choices"][0]["message"]["content"] == "OK"
        finally:
            server.shutdown()
            thread.join(timeout=5)
        assert not thread.is_alive()
    output = capsys.readouterr()
    assert "never-log" not in output.out + output.err


def test_evidence_collector_rejects_links_and_reports_actual_file(tmp_path: Path) -> None:
    import hashlib

    from tests.integration.homeassistant.evidence import manifest

    regular = tmp_path / "phase.json"
    regular.write_bytes(b'{"success":true}\n')
    receipt = manifest(tmp_path)
    assert receipt["files"] == {
        "phase.json": {
            "size": regular.stat().st_size,
            "sha256": hashlib.sha256(regular.read_bytes()).hexdigest(),
        }
    }
    (tmp_path / "alias").symlink_to(regular)
    with pytest.raises(ValueError, match="unexpected path type"):
        manifest(tmp_path)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1",
        "http://localhost",
        "http://192.0.2.1",
        "http://x@127.0.0.1",
        "http://127.0.0.1/path",
        "http://127.0.0.1?x=1",
        "http://127.0.0.1#x",
    ],
)
def test_owned_api_refuses_non_loopback_or_ambiguous_url(url: str) -> None:
    from tests.integration.homeassistant.api import loopback_url

    with pytest.raises(ValueError, match="literal loopback"):
        loopback_url(url)


def test_actual_owned_onboarding_token_websocket_and_status_transport(capsys: pytest.CaptureFixture[str]) -> None:
    import asyncio

    from aiohttp import web

    from tests.integration.homeassistant.api import execute

    async def run() -> None:
        calls: list[str] = []
        selected = "synthetic-long-lived-token-" + "x" * 40

        async def users(request: web.Request) -> web.Response:
            value = await request.json()
            assert value["username"] == "owned-native"
            assert len(value["password"]) >= 32
            assert value["client_id"].endswith("/")
            calls.append("users")
            return web.json_response({"auth_code": "synthetic-authorization-code"})

        async def token(request: web.Request) -> web.Response:
            value = await request.post()
            assert value["code"] == "synthetic-authorization-code"
            assert value["grant_type"] == "authorization_code"
            calls.append("token")
            return web.json_response({"access_token": "synthetic-short-token"})

        async def websocket(request: web.Request) -> web.WebSocketResponse:
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            await ws.send_json({"type": "auth_required"})
            value = await ws.receive_json()
            assert value["access_token"] in {"synthetic-short-token", selected}
            await ws.send_json({"type": "auth_ok"})
            value = await ws.receive_json()
            calls.append(value["type"])
            if value["type"] == "auth/long_lived_access_token":
                assert value["lifespan"] == 1
                result: object = selected
            else:
                assert value["type"] == "config/area_registry/list"
                result = []
            await ws.send_json({"id": value["id"], "type": "result", "success": True, "result": result})
            await ws.close()
            return ws

        async def health(request: web.Request) -> web.Response:
            assert request.headers["Authorization"] == "Bearer " + selected
            calls.append("health")
            return web.Response(status=200, text="synthetic-body-not-exported")

        app = web.Application()
        app.router.add_post("/api/onboarding/users", users)
        app.router.add_post("/auth/token", token)
        app.router.add_get("/api/websocket", websocket)
        app.router.add_get("/api/", health)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        address = runner.addresses[0]
        url = f"http://127.0.0.1:{address[1]}"
        try:
            assert await execute({"action": "seed", "url": url}) == {"token": selected}
            assert await execute(
                {"action": "ws", "url": url, "token": selected, "command": {"type": "config/area_registry/list"}}
            ) == {"result": []}
            assert await execute({"action": "health", "url": url, "token": selected}) == {"status": 200}
            assert calls == ["users", "token", "auth/long_lived_access_token", "config/area_registry/list", "health"]
        finally:
            await runner.cleanup()

    asyncio.run(run())
    output = capsys.readouterr()
    assert "synthetic-" not in output.out + output.err


def test_actual_wyoming_describe_inline_and_length_frames_no_audio(capsys: pytest.CaptureFixture[str]) -> None:
    import socket

    from tests.integration.homeassistant.wyoming_server import WyomingServer

    with WyomingServer(0) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with (
                socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5) as client,
                client.makefile("rwb") as stream,
            ):
                stream.write(b'{"type":"describe"}\n')
                stream.flush()
                result = json.loads(stream.readline())
                assert result["type"] == "info"
                assert result["data"]["asr"][0]["models"][0]["languages"] == ["en"]
                assert result["data"]["tts"][0]["voices"][0]["name"] == "owned-native-voice"
                data = b'{"name":"owned-native-stt"}'
                stream.write(json.dumps({"type": "select-program", "data_length": len(data)}).encode() + b"\n" + data)
                stream.write(b'{"type":"describe"}\n')
                stream.flush()
                assert json.loads(stream.readline()) == result
            assert server.describe_count == 2
            assert server.unexpected_count == 0
            with (
                socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5) as client,
                client.makefile("rwb") as stream,
            ):
                stream.write(b'{"type":"audio-chunk","payload_length":4}\nDATA')
                stream.flush()
                assert stream.readline() == b""
            assert server.unexpected_count == 1
        finally:
            server.shutdown()
            thread.join(timeout=5)
    output = capsys.readouterr()
    assert not output.out + output.err


def test_streaming_redactor_never_persists_split_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.integration.homeassistant import fixture

    secret = "owned-synthetic-secret-with-a-long-prefix"
    monkeypatch.setattr(fixture, "VALUES", [secret])
    for split in range(len(secret) + 1):
        raw_path = tmp_path / "raw"
        durable_path = tmp_path / "durable"
        with raw_path.open("w") as raw, durable_path.open("w") as durable:
            stream = fixture.BoundedLog(raw, durable)
            stream.write("before " + secret[:split])
            stream.flush()
            assert secret not in durable_path.read_text()
            stream.write(secret[split:] + " after\n")
            stream.flush()
            assert secret not in durable_path.read_text()
        assert fixture.sanitize(raw_path.read_text()) == "before <synthetic-redacted> after\n"


def test_plan_recorder_does_not_execute_callback_or_condition(tmp_path: Path) -> None:
    from collections.abc import Generator

    from pyinfra.api import Config, FunctionCommand, Inventory, State, operation
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.operation import add_op

    from tests.integration.homeassistant.harness import planned_rows

    effect = tmp_path / "effect"

    def condition() -> bool:
        raise AssertionError("plan called condition")

    def callback(state: State, host: object) -> None:
        effect.write_text("unexpected mutation")

    @operation()
    def mutate() -> Generator[FunctionCommand, None, None]:
        yield FunctionCommand(callback, (), {})

    state = State(Inventory(([("@local", {})], {})), Config())
    try:
        connect_all(state)
        add_op(state, mutate, name="Owned planned change", _if=condition)
        rows = planned_rows(state)
        assert len(rows) == 1
        assert rows[0]["has_condition"] is True
        assert rows[0]["conditional_change"] or rows[0]["unresolved"]
        assert rows[0]["change"] is False
        assert rows[0]["read_only"] is False
        assert not effect.exists()
    finally:
        disconnect_all(state)


def test_owned_api_total_deadline_covers_silent_authenticated_websocket(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import time

    from aiohttp import web

    from tests.integration.homeassistant import api

    async def run() -> None:
        observed = asyncio.Event()

        async def silent(request: web.Request) -> web.WebSocketResponse:
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            await ws.send_json({"type": "auth_required"})
            assert (await ws.receive_json())["type"] == "auth"
            observed.set()
            await ws.receive()  # Client cancellation closes its owned connection.
            return ws

        app = web.Application()
        app.router.add_get("/api/websocket", silent)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        monkeypatch.setattr(api, "DEADLINE_SECONDS", 0.1)
        start = time.monotonic()
        try:
            with pytest.raises(TimeoutError):
                await api.execute(
                    {
                        "action": "ws",
                        "url": f"http://127.0.0.1:{runner.addresses[0][1]}",
                        "token": "synthetic",
                        "command": {"type": "config/area_registry/list"},
                    }
                )
            assert observed.is_set()
            assert time.monotonic() - start < 2
        finally:
            await runner.cleanup()

    asyncio.run(run())


def test_fixture_actual_api_rewrite_matches_listener_proxy_and_original_values(monkeypatch: pytest.MonkeyPatch) -> None:
    import yaml

    from ops_deploy.services.homeassistant.area_registry import area_payload
    from tests.integration.homeassistant import matrix, prerequisites
    from tests.integration.homeassistant.harness import API_URL

    guest = "192.0.2.10"
    monkeypatch.setattr(matrix, "default_ipv4", lambda: guest)
    cfg = matrix.config(token="owned-synthetic-token-" + "x" * 40)
    original = matrix.original_vars("2026.10.2")
    body = yaml.safe_load(prerequisites.configuration(guest))
    assert body["http"]["server_host"] == "0.0.0.0"
    assert body["http"]["trusted_proxies"] == ["127.0.0.1", guest]
    assert original["homeassistant_trusted_proxies"] == list(cfg.values.trusted_proxies)
    assert cfg.values.internal_url == original["homeassistant_internal_url"] == API_URL
    assert (
        json.loads(area_payload(cfg.api, [], "inspect", app_port=cfg.values.app_port).get_secret_value())["url"]
        == f"http://{guest}:10020"
    )
