"""Owned synthetic protocol cases; no real HA, model or user content access."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import io
import json
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from aiohttp import web
from pydantic import SecretStr

from ops_deploy.services.homeassistant.custom_conversation import (
    CustomConversationConfig,
    custom_command,
    custom_payload,
)
from ops_deploy.services.homeassistant.integration_flows import HomeAssistantApiConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from tests.fakehost import command_host

PROGRAM = Path(str(files("ops_deploy.services.homeassistant").joinpath("files/custom_conversation.py")))
FIXTURE = Path(__file__).parent / "parity/homeassistant/custom-conversation"
DEFAULT = (
    "You are a voice assistant for Home Assistant.\n"
    "Answer questions about the world truthfully.\n"
    "Answer in plain text. Keep it simple and to the point.\n"
)


def payload(storage: Path, url: str = "http://127.0.0.1:1/prefix") -> dict[str, Any]:
    return {
        "secrets": {"HA_TOKEN": "synthetic-ha-secret", "HA_CC_API_KEY": "synthetic-model-secret"},
        "settings": {
            "HA_API_URL": url,
            "HA_STORAGE_PATH": str(storage),
            "HA_CC_ENABLED": "1",
            "HA_CC_PROVIDER": "openai",
            "HA_CC_BASE_URL": "http://synthetic-model/v1",
            "HA_CC_MODEL": "synthetic-model",
            "HA_CC_INSTRUCTIONS": "",
            "HA_CC_VERSION": "1.6.1",
            "HA_CANARY_TEXT": "Synthetic owned canary",
            "HA_TIMEOUT": "1",
            "HA_CANARY_TIMEOUT": "1",
            "HA_RESOLVE_RETRIES": "2",
            "HA_RESOLVE_DELAY": "0",
            "HA_FORWARDED_FOR": "127.0.0.1",
            "HA_FORWARDED_PROTO": "http",
        },
    }


def entry() -> dict[str, Any]:
    return {
        "domain": "custom_conversation",
        "entry_id": "synthetic-entry",
        "data": {
            "primary_provider": "openai",
            "primary_base_url": "http://synthetic-model/v1",
            "primary_api_key": "synthetic-model-secret",
            "primary_chat_model": "synthetic-model",
            "secondary_provider_enabled": False,
        },
        "options": {
            "llm_hass_api": "none",
            "custom_prompts": {"instructions_prompt": DEFAULT},
            "agents": {"enable_home_assistant_agent": False, "enable_llm_agent": True},
            "langfuse": {"enable_langfuse": True, "host": "synthetic-private-host"},
            "ignored_intents_section": {"ignored_intents": ["SyntheticIntent"]},
        },
    }


def load_helper(data: dict[str, Any]) -> dict[str, Any]:
    tree = ast.parse(PROGRAM.read_text())
    assert isinstance(tree.body[-1], ast.Try)
    tree.body.pop()  # Import definitions without executing the main API action.
    namespace: dict[str, Any] = {"__name__": "owned_custom"}
    with patch("sys.stdin", io.StringIO(json.dumps(data))):
        exec(compile(tree, str(PROGRAM), "exec"), namespace)
    return namespace


def test_original_protocol_function_and_source_bindings() -> None:
    source = json.loads((FIXTURE / "source.json").read_text())
    assert hashlib.sha256((FIXTURE / "integration.yml").read_bytes()).hexdigest() == source["integration_sha256"]
    assert (
        hashlib.sha256((FIXTURE / "original-program.py.txt").read_bytes()).hexdigest()
        == source["original_program_sha256"]
    )

    def functions(body: str) -> dict[str, str]:
        return {
            node.name: ast.dump(node, include_attributes=False)
            for node in ast.parse(body).body
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }

    original = functions((FIXTURE / "original-program.py.txt").read_text())
    actual = functions(PROGRAM.read_text())
    assert set(original) == set(actual)
    assert sorted(name for name in original if original[name] == actual[name]) == sorted(
        source["unchanged_function_asts"]
    )
    assert sorted(name for name in original if original[name] != actual[name]) == sorted(source["changed_functions"])


@pytest.mark.parametrize("field", ["primary_provider", "primary_base_url", "primary_api_key", "primary_chat_model"])
def test_actual_original_owned_data_drift(field: str, tmp_path: Path) -> None:
    helper = load_helper(payload(tmp_path / "entries"))
    current = entry()
    assert helper["data_drift"](current) is False
    current["data"][field] = "changed"
    assert helper["data_drift"](current) is True


def test_secondary_and_default_prompt_normalization(tmp_path: Path) -> None:
    helper = load_helper(payload(tmp_path / "entries"))
    current = entry()
    assert helper["options_drift"](current) is False
    current["data"]["secondary_provider_enabled"] = True
    assert helper["data_drift"](current) is True
    for value in ("", None, DEFAULT):
        current["options"]["custom_prompts"]["instructions_prompt"] = value
        assert helper["options_drift"](current) is False
    current["options"]["custom_prompts"]["instructions_prompt"] = "prior custom"
    assert helper["options_drift"](current) is True
    assert helper["ws_url"]("https://owned:8443/prefix/") == "wss://owned:8443/prefix/api/websocket"


@pytest.mark.parametrize(
    "case",
    [
        "unchanged",
        "create",
        "create-prompt",
        "update",
        "options",
        "disable",
        "disabled-absent",
        "duplicate",
        "duplicate-disabled",
        "credentials-error",
        "ws-auth",
        "canary-malformed",
        "canary-http",
        "unavailable",
        "delete-error",
        "unsupported-default",
        "malformed-storage",
    ],
)
def test_real_owned_http_websocket_protocol(tmp_path: Path, case: str) -> None:
    async def scenario() -> None:
        storage = tmp_path / "core.config_entries"
        current = entry()
        entries = [] if case in {"create", "create-prompt", "credentials-error", "disabled-absent"} else [current]
        if case.startswith("duplicate"):
            entries.append({**entry(), "entry_id": "second-private-id"})
        if case == "update":
            current["data"]["primary_base_url"] = "http://prior.invalid"
        if case == "options":
            current["options"]["custom_prompts"]["instructions_prompt"] = "old private prompt"
        storage.write_text(json.dumps({"data": {"entries": entries}}))
        if case == "malformed-storage":
            storage.write_text("{private-invalid-body")
        before = storage.read_bytes()
        calls: list[tuple[str, str, Any]] = []
        step = 0

        async def handler(request: web.Request) -> web.Response:
            nonlocal step
            assert request.headers["Authorization"] == "Bearer synthetic-ha-secret"
            assert request.headers["X-Forwarded-For"] == "127.0.0.1"
            assert request.headers["X-Forwarded-Proto"] == "http"
            body: Any = await request.json() if request.can_read_body else None
            path = request.path.removeprefix("/prefix")
            calls.append((request.method, path, body))
            if path == "/api/config/config_entries/flow":
                assert body["handler"] == "custom_conversation"
                reconfigure = "entry_id" in body
                assert reconfigure == (case == "update")
                assert "source" not in body
                return web.json_response(
                    {"type": "form", "step_id": "reconfigure_provider" if reconfigure else "user", "flow_id": "flow"}
                )
            if path == "/api/config/config_entries/flow/flow":
                step += 1
                if step == 1:
                    assert body == {"primary_provider": "openai"}
                    return web.json_response({"type": "form"})
                if step == 2:
                    assert body == {
                        "primary_api_key": "synthetic-model-secret",
                        "primary_base_url": "http://synthetic-model/v1",
                    }
                    return web.json_response(
                        {
                            "type": "form",
                            "errors": {"private": "never-export-body"} if case == "credentials-error" else {},
                        }
                    )
                assert body == {"primary_chat_model": "synthetic-model", "secondary_provider_enabled": False}
                if case == "update":
                    return web.json_response({"type": "abort", "reason": "reconfigure_successful"})
                return web.json_response({"type": "create_entry", "result": {"entry_id": "synthetic-entry"}})
            if path == "/api/config/config_entries/options/flow":
                assert body == {"handler": "synthetic-entry", "show_advanced_options": True}
                return web.json_response({"type": "form", "step_id": "init", "flow_id": "options"})
            if path == "/api/config/config_entries/options/flow/options":
                assert body["llm_hass_api"] == "none"
                if case == "options":
                    for key in ("agents", "langfuse", "ignored_intents_section"):
                        assert body[key] == current["options"][key]
                    assert body["custom_prompts"] == {"instructions_prompt": ""}
                else:
                    assert body["custom_prompts"] == {"instructions_prompt": "synthetic explicit prompt"}
                return web.json_response({"type": "create_entry"})
            if path == "/api/states/conversation.synthetic":
                return web.json_response(
                    {
                        "state": "unavailable" if case == "unavailable" else "idle",
                        "attributes": {"private": "never-export-body"},
                    }
                )
            if path == "/api/conversation/process":
                assert body == {
                    "text": "Synthetic owned canary",
                    "agent_id": "conversation.synthetic",
                    "language": "en",
                }
                response = (
                    {}
                    if case == "canary-malformed"
                    else {"response_type": "query_answer", "speech": "never-export-body"}
                )
                return web.json_response({"response": response}, status=401 if case == "canary-http" else 200)
            assert request.method == "DELETE"
            assert path == "/api/config/config_entries/entry/synthetic-entry"
            return web.json_response({"private": "never-export-body"}, status=403 if case == "delete-error" else 200)

        async def websocket(request: web.Request) -> web.WebSocketResponse:
            assert request.headers["X-Forwarded-For"] == "127.0.0.1"
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            await ws.send_json({"type": "auth_required"})
            assert await ws.receive_json() == {"type": "auth", "access_token": "synthetic-ha-secret"}
            await ws.send_json({"type": "auth_invalid" if case == "ws-auth" else "auth_ok"})
            if case != "ws-auth":
                assert await ws.receive_json() == {"id": 1, "type": "config/entity_registry/list"}
                await ws.send_json(
                    {
                        "id": 1,
                        "success": True,
                        "result": [
                            {
                                "entity_id": "conversation.foreign",
                                "platform": "foreign",
                                "config_entry_id": "synthetic-entry",
                            },
                            {
                                "entity_id": "conversation.synthetic",
                                "platform": "custom_conversation",
                                "config_entry_id": "synthetic-entry",
                            },
                        ],
                    }
                )
            await ws.close()
            return ws

        app = web.Application()
        app.router.add_get("/prefix/api/websocket", websocket)
        app.router.add_route("*", "/prefix/{tail:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        data = payload(storage, f"http://127.0.0.1:{runner.addresses[0][1]}/prefix")
        if case in {"disable", "disabled-absent", "duplicate-disabled", "delete-error"}:
            data["settings"]["HA_CC_ENABLED"] = "0"
        if case == "create-prompt":
            data["settings"]["HA_CC_INSTRUCTIONS"] = "synthetic explicit prompt"
        if case == "unsupported-default":
            data["settings"]["HA_CC_VERSION"] = "different"
        try:
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-B",
                str(PROGRAM),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(data).encode()), timeout=10)
        finally:
            await runner.cleanup()
        report = json.loads(stdout)
        success = case in {"unchanged", "create", "create-prompt", "update", "options", "disable", "disabled-absent"}
        assert process.returncode == (0 if success else 1), (report, stderr.decode())
        assert storage.read_bytes() == before
        assert all(
            secret not in stdout.decode() + stderr.decode()
            for secret in (
                "synthetic-ha-secret",
                "synthetic-model-secret",
                "never-export-body",
                "old private prompt",
                "second-private-id",
            )
        )
        writes = sum(method != "GET" for method, _, _ in calls)
        assert report["mutation_attempts"] == writes
        if success:
            assert report["status"] == "success"
            assert report["changed"] == (case not in {"unchanged", "disabled-absent"})
            assert report["entity_id"] == ("" if case in {"disable", "disabled-absent"} else "conversation.synthetic")
            if case == "unchanged":
                assert writes == 1  # The real canary is managed even with no config drift.
        else:
            assert report["status"] == "error"
            assert report["partial_possible"] == (writes > 0)
            if case in {"duplicate", "duplicate-disabled", "unsupported-default", "malformed-storage"}:
                assert calls == []
            if case == "credentials-error":
                assert writes == 3
                assert "credentials" in report["diagnostic"]
            if case == "delete-error":
                assert writes == 1

    asyncio.run(scenario())


def test_controller_payload_protects_all_settings_and_preserves_url() -> None:
    runtime = HomeAssistantRuntimeConfig()
    api = HomeAssistantApiConfig(
        url=SecretStr("https://owned:8443/prefix/"),
        token=SecretStr("owned-synthetic-long-lived-token-0000"),
        timeout=47,
    )
    config = CustomConversationConfig(
        enabled=True,
        base_url=SecretStr("http://owned-model"),
        api_key=SecretStr("model-secret"),
        model=SecretStr("model"),
    )
    protected = custom_payload(runtime, api, config)
    assert "owned-token" not in repr(protected)
    value = json.loads(protected.get_secret_value())
    assert value["settings"]["HA_API_URL"] == "https://owned:8443/prefix/"
    assert value["settings"]["HA_TIMEOUT"] == "47"
    command = custom_command(runtime)
    assert "owned-token" not in command
    assert "model-secret" not in command
    assert "HA_CC_API_KEY=" not in command
    assert "HA_TOKEN=" not in command
    assert "runuser" in command
    with pytest.raises(ValueError, match="requires"):
        custom_payload(runtime, api, CustomConversationConfig(enabled=True))
    custom_payload(runtime, api, CustomConversationConfig(enabled=False))


@pytest.mark.parametrize("diff", [False, True])
def test_real_pyinfra_plan_has_no_api_call_and_each_execution_remains_managed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, diff: bool
) -> None:
    import shlex

    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant import custom_conversation as component
    from ops_deploy.services.homeassistant.custom_conversation import CustomConversationResult
    from ops_deploy.testing.harness import collect_ops

    marker = tmp_path / "canary-count"
    script = tmp_path / "owned-helper.py"
    script.write_text(
        "import json,pathlib,sys\njson.load(sys.stdin)\np=pathlib.Path(" + repr(str(marker)) + ")\n"
        "p.write_text(p.read_text()+'x' if p.exists() else 'x')\n"
        "print(json.dumps({'status':'success','changed':False,'action':'unchanged',"
        "'entity_id':'conversation.owned','mutation_attempts':1}))\n"
    )
    monkeypatch.setattr(component, "custom_command", lambda *_: shlex.join([sys.executable, str(script)]))
    api = HomeAssistantApiConfig(token=SecretStr("owned-synthetic-long-lived-token-0000"), timeout=47)
    config = CustomConversationConfig(
        enabled=True, base_url=SecretStr("http://owned"), api_key=SecretStr("key"), model=SecretStr("model")
    )
    result = CustomConversationResult()
    for number in (1, 2):
        state = State(Inventory(([("@local", {})], {})), Config(DIFF=diff))
        try:
            connect_all(state)
            add_deploy(
                state,
                lambda: component.run_custom_conversation(
                    runtime=HomeAssistantRuntimeConfig(),
                    api=api,
                    config=config,
                    result=result,
                ),
            )
            assert (marker.read_text() if marker.exists() else "") == "x" * (number - 1)
            run_ops(state)
            operations = collect_ops(state, "@local")
            assert len(operations) == 1
            assert operations[0].changed
            assert operations[0].succeeded
            assert result.completed
            assert result.reported_changed is False
            assert result.mutation_attempts == 1
            assert result.phase == "complete"
            assert result.entity_id.get_secret_value() == "conversation.owned"
            assert marker.read_text() == "x" * number
        finally:
            disconnect_all(state)


@pytest.mark.parametrize(
    "raw",
    [
        "not-json-private-body",
        '{"status":"error","diagnostic":"private-body","unexpected":true}',
        '{"status":"success","changed":false,"action":"unchanged","entity_id":"conversation.owned","mutation_attempts":1,"body":"private-body"}',
    ],
)
def test_invalid_report_resets_prior_success_without_body_disclosure(raw: str) -> None:
    from types import SimpleNamespace
    from typing import cast

    from pyinfra.api import OperationError, State

    from ops_deploy.services.homeassistant.custom_conversation import CustomConversationResult, _execute

    def invoke(*args: Any, **kwargs: Any) -> Any:
        assert not kwargs["print_input"]
        assert not kwargs["print_output"]
        assert kwargs["_get_pty"] is False
        return False, SimpleNamespace(stdout=raw)

    result = CustomConversationResult(SecretStr("conversation.prior"), False, True)
    with pytest.raises(OperationError, match="partial effects may exist") as error:
        _execute(
            cast(State, None),
            command_host(invoke),
            "owned-command",
            SecretStr("{}"),
            1,
            True,
            result,
        )
    assert "private-body" not in str(error.value)
    assert not result.completed
    assert result.reported_changed is None
    assert result.entity_id.get_secret_value() == ""


def test_actual_localconnector_timeout_keeps_remote_activity_uncertainty(tmp_path: Path) -> None:
    import shlex
    import time

    from pyinfra.api import Config, Inventory, OperationError, State
    from pyinfra.api.connect import connect_all, disconnect_all

    from ops_deploy.services.homeassistant.custom_conversation import CustomConversationResult, _execute

    state = State(Inventory(([("@local", {})], {})), Config())
    marker = tmp_path / "known-late-child"
    command = shlex.join(
        [sys.executable, "-c", "import pathlib,time;time.sleep(2);pathlib.Path(" + repr(str(marker)) + ").touch()"]
    )
    result = CustomConversationResult(SecretStr("conversation.prior"), False, True)
    try:
        connect_all(state)
        with pytest.raises(OperationError, match="partial effects and remote activity may exist"):
            _execute(state, state.inventory.get_host("@local"), command, SecretStr("{}"), 1, True, result)
        assert not result.completed
        assert result.reported_changed is None
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists()
    finally:
        disconnect_all(state)


@pytest.mark.parametrize("count", [0, 3])
def test_valid_sanitized_failure_exposes_phase_and_attempts(count: int) -> None:
    from types import SimpleNamespace
    from typing import cast

    from pyinfra.api import OperationError, State

    from ops_deploy.services.homeassistant.custom_conversation import CustomConversationResult, _execute

    report = {
        "status": "error",
        "diagnostic": "source-owned diagnostic",
        "phase": "credentials",
        "mutation_attempts": count,
        "partial_possible": count > 0,
    }
    target = command_host(lambda *a, **k: (False, SimpleNamespace(stdout=json.dumps(report))))
    result = CustomConversationResult()
    with pytest.raises(OperationError) as error:
        _execute(cast(State, None), target, "owned-command", SecretStr("{}"), 1, True, result)
    assert f"mutation_attempts={count}" in str(error.value)
    assert "phase=credentials" in str(error.value)
    assert result.mutation_attempts == count
    assert result.partial_possible is (count > 0)
    assert not result.completed
    assert ("helper made no mutation attempt" in str(error.value)) is (count == 0)
