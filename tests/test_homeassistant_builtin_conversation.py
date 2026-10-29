"""Exact original helper plus owned synthetic HTTP/WebSocket controls."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import io
import json
import types
import unittest
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web

from ops_deploy.services.homeassistant.builtin_conversation import (
    BuiltinConversationConfig,
    ConversationResult,
    builtin_command,
    builtin_payload,
)
from ops_deploy.services.homeassistant.integration_flows import HomeAssistantApiConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

PROGRAM = Path(str(files("ops_deploy.services.homeassistant").joinpath("files/llama_cpp_provision.py")))
SPEC = importlib.util.spec_from_file_location("owned_builtin_helper", PROGRAM)
assert SPEC is not None
assert SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
FIXTURE = Path(__file__).parent / "parity/homeassistant/builtin"


def test_exact_original_program_and_all_original_seventeen_controls() -> None:
    source = json.loads((FIXTURE / "source.json").read_text())
    assert hashlib.sha256(PROGRAM.read_bytes()).hexdigest() == source["program"]["sha256"]
    for name, value in source["sources"].items():
        assert hashlib.sha256((FIXTURE / name).read_bytes()).hexdigest() == value["sha256"]
    test_source = (FIXTURE / "original-tests.py.txt").read_text()
    original = 'ROOT / "roles/homeassistant_deploy/files/llama_cpp_provision.py"'
    assert test_source.count(original) == 1
    test_source = test_source.replace(original, f"Path({str(PROGRAM)!r})")
    module = types.ModuleType("original_builtin_controls")
    module.__file__ = str(FIXTURE / "original-tests.py.txt")
    exec(compile(test_source, module.__file__, "exec"), module.__dict__)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    assert suite.countTestCases() == 17
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream).run(suite)
    assert result.wasSuccessful(), stream.getvalue()


@pytest.mark.parametrize("fault", ["healthy", "http-auth", "ws-auth", "canary-auth"])
def test_real_owned_http_websocket_canary_keeps_bodies_local(tmp_path: Path, fault: str) -> None:
    async def scenario() -> None:
        calls: list[str] = []
        storage = tmp_path / "entries.json"
        storage.write_text(
            json.dumps(
                {
                    "data": {
                        "entries": [
                            {
                                "entry_id": "managed",
                                "data": {"base_url": "http://owned-model", "api_key": "synthetic-model-key"},
                                "subentries": [
                                    {
                                        "subentry_id": "sub",
                                        "data": {
                                            "chat_model": "owned-model",
                                            "prompt": "owned instructions",
                                            "llm_hass_api": [],
                                            "recommended": True,
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                }
            )
        )
        before = storage.read_bytes()

        async def entry(request: web.Request) -> web.Response:
            calls.append("entries")
            assert request.headers["Authorization"] == "Bearer synthetic-ha-token"
            if fault == "http-auth":
                return web.json_response({"private": "unexported"}, status=401)
            return web.json_response([{"entry_id": "managed", "title": "Managed voice bridge"}])

        async def canary(request: web.Request) -> web.Response:
            calls.append("canary")
            assert await request.json() == {
                "agent_id": "conversation.owned",
                "text": "Owned synthetic canary",
                "language": "en",
            }
            if fault == "canary-auth":
                return web.json_response({"private": "unexported"}, status=401)
            return web.json_response(
                {
                    "response": {
                        "response_type": "action_done",
                        "speech": {"plain": {"speech": "synthetic response never exported"}},
                    }
                }
            )

        async def websocket(request: web.Request) -> web.WebSocketResponse:
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            await ws.send_json({"type": "auth_required"})
            assert await ws.receive_json() == {"type": "auth", "access_token": "synthetic-ha-token"}
            await ws.send_json({"type": "auth_invalid" if fault == "ws-auth" else "auth_ok"})
            if fault == "ws-auth":
                await ws.close()
                return ws
            command = await ws.receive_json()
            calls.append(command["type"])
            if command["type"] == "config_entries/subentries/list":
                result: Any = [{"subentry_id": "sub", "subentry_type": "conversation"}]
            else:
                assert command["type"] == "config/entity_registry/list"
                result = [
                    {
                        "entity_id": "conversation.owned",
                        "platform": "llama_cpp",
                        "config_entry_id": "managed",
                        "config_subentry_id": "sub",
                        "disabled_by": None,
                    }
                ]
            await ws.send_json({"id": 1, "success": True, "result": result})
            await ws.close()
            return ws

        app = web.Application()
        app.router.add_get("/api/config/config_entries/entry", entry)
        app.router.add_post("/api/conversation/process", canary)
        app.router.add_get("/api/websocket", websocket)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        config = {
            "action": "ensure",
            "api_url": f"http://127.0.0.1:{runner.addresses[0][1]}",
            "api_token": "synthetic-ha-token",
            "forwarded_for": "127.0.0.1",
            "forwarded_proto": "http",
            "storage_path": str(storage),
            "base_url": "http://owned-model",
            "api_key": "synthetic-model-key",
            "model": "owned-model",
            "instructions": "owned instructions",
            "canary_text": "Owned synthetic canary",
        }
        try:
            if fault == "healthy":
                for _ in range(2):
                    assert await asyncio.wait_for(helper.Provisioner(config).run(), 5) == {
                        "changed": False,
                        "entity_id": "conversation.owned",
                    }
                assert calls.count("canary") == 2  # active, even on unchanged repeat
            else:
                with pytest.raises(helper.ProvisionError):
                    await asyncio.wait_for(helper.Provisioner(config).run(), 5)
                assert calls.count("canary") == (1 if fault == "canary-auth" else 0)
        finally:
            await runner.cleanup()
        assert storage.read_bytes() == before

    asyncio.run(scenario())


def test_controller_selected_paths_payload_and_masked_output() -> None:
    from pydantic import SecretStr

    runtime = HomeAssistantRuntimeConfig(user="owned", home="/srv/owned")
    config = BuiltinConversationConfig(
        base_url=SecretStr("http://owned-model"), instructions=SecretStr("private-prompt")
    )
    api = HomeAssistantApiConfig(token=SecretStr("synthetic-token-with-thirty-two-characters"))
    payload = builtin_payload(runtime, api, config, "ensure")
    assert "private-prompt" not in repr(payload)
    assert (
        json.loads(payload.get_secret_value())["storage_path"] == "/srv/owned/site/config/.storage/core.config_entries"
    )
    command = builtin_command(runtime, config)
    assert "/srv/owned/site/.venv/bin/python" in command
    assert "/srv/owned/site/bin/llama_cpp_provision.py" in command
    assert "private-prompt" not in command
    assert "synthetic-token" not in command
    assert not ConversationResult().completed


@pytest.mark.parametrize("diff", [False, True])
def test_real_pyinfra_plan_never_runs_canary_but_execution_is_managed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, diff: bool
) -> None:
    import shlex
    import sys

    from pydantic import SecretStr
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant import builtin_conversation as component
    from ops_deploy.testing.harness import collect_ops

    marker = tmp_path / "synthetic-canary-count"
    script = tmp_path / "owned-helper.py"
    script.write_text(
        "import json,pathlib,sys\njson.load(sys.stdin)\np=pathlib.Path(" + repr(str(marker)) + ")\n"
        "p.write_text(p.read_text()+'x' if p.exists() else 'x')\n"
        "print(json.dumps({'changed':False,'entity_id':'conversation.owned'}))\n"
    )
    monkeypatch.setattr(component, "builtin_command", lambda *_: shlex.join([sys.executable, str(script)]))
    api = HomeAssistantApiConfig(token=SecretStr("owned-synthetic-long-lived-token-0000"))
    result = ConversationResult()
    for run in (1, 2):
        state = State(Inventory(([("@local", {})], {})), Config(DIFF=diff))
        try:
            connect_all(state)
            add_deploy(
                state,
                lambda: component.run_builtin_conversation(
                    runtime=HomeAssistantRuntimeConfig(),
                    api=api,
                    config=BuiltinConversationConfig(),
                    action="ensure",
                    result=result,
                ),
            )
            assert (marker.read_text() if marker.exists() else "") == "x" * (run - 1)
            run_ops(state)
            operations = collect_ops(state, "@local")
            assert len(operations) == 1
            assert operations[0].changed
            assert operations[0].succeeded
            assert result.completed
            assert result.reported_changed is False
            assert marker.read_text() == "x" * run
        finally:
            disconnect_all(state)


@pytest.mark.parametrize(
    "raw",
    [
        '{"error":"private-model-response","unexpected":true}',
        "not-json-private",
        '{"changed":false,"entity_id":"conversation.owned","body":"private"}',
    ],
)
def test_failed_or_invalid_result_clears_previous_canary_and_reports_partial_effects(raw: str) -> None:
    from types import SimpleNamespace
    from typing import cast

    from pydantic import SecretStr
    from pyinfra.api import OperationError, State
    from pyinfra.api.host import Host

    from ops_deploy.services.homeassistant.builtin_conversation import _execute

    def execute(*args: Any, **kwargs: Any) -> Any:
        assert not kwargs["print_input"]
        assert not kwargs["print_output"]
        return False, SimpleNamespace(stdout=raw)

    result = ConversationResult(SecretStr("conversation.previous"), False, True)
    with pytest.raises(OperationError, match="partial effects may exist") as error:
        _execute(
            cast(State, None),
            cast(Host, SimpleNamespace(run_shell_command=execute)),
            "owned-command",
            SecretStr("{}"),
            1,
            "ensure",
            result,
        )
    assert "private" not in str(error.value)
    assert not result.completed
    assert result.entity_id.get_secret_value() == ""
    assert result.reported_changed is None


@pytest.mark.parametrize(
    "message",
    [
        "Unmarked llama_cpp entry uses the configured endpoint; "
        "verify ownership and rename it to Managed voice bridge, or remove it in HA before redeploying",
        "Multiple llama_cpp entries; refusing to choose",
        "Live llama_cpp entry is not yet persisted; retry deployment",
        "Legacy integration removal requires an HA restart",
        "llama_cpp entity did not answer the conversation canary within 180 seconds",
        "HA API request failed (HTTP 401)",
        "JSONDecodeError",
    ],
)
def test_original_sanitized_operator_recovery_diagnostic_is_retained(message: str) -> None:
    from types import SimpleNamespace
    from typing import cast

    from pydantic import SecretStr
    from pyinfra.api import OperationError, State
    from pyinfra.api.host import Host

    from ops_deploy.services.homeassistant.builtin_conversation import _execute

    target = cast(
        Host,
        SimpleNamespace(
            run_shell_command=lambda *a, **k: (False, SimpleNamespace(stdout=json.dumps({"error": message})))
        ),
    )
    with pytest.raises(OperationError) as error:
        _execute(cast(State, None), target, "owned-command", SecretStr("{}"), 1, "ensure", ConversationResult())
    assert message in str(error.value)
    assert "partial effects may exist" in str(error.value)


def test_actual_localconnector_timeout_clears_result_and_retains_uncertainty(tmp_path: Path) -> None:
    import shlex
    import sys

    from pydantic import SecretStr
    from pyinfra.api import Config, Inventory, OperationError, State
    from pyinfra.api.connect import connect_all, disconnect_all

    from ops_deploy.services.homeassistant.builtin_conversation import _execute

    state = State(Inventory(([("@local", {})], {})), Config())
    target = state.inventory.get_host("@local")
    result = ConversationResult(SecretStr("conversation.previous"), False, True)
    marker = tmp_path / "timeout-child-finished"
    # Finite owned child. LocalConnector timeout is real; wait for its known
    # completion marker separately rather than claiming timeout proves quiescence.
    command = shlex.join(
        [sys.executable, "-c", "import pathlib,time;time.sleep(2);pathlib.Path(" + repr(str(marker)) + ").touch()"]
    )
    try:
        connect_all(state)
        with pytest.raises(OperationError, match="timed out; partial effects and remote activity may exist"):
            _execute(state, target, command, SecretStr("{}"), 1, "ensure", result)
        assert not result.completed
        assert result.reported_changed is None
        import time

        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists()
    finally:
        disconnect_all(state)
