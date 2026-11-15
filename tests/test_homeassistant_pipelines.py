"""Owned real WebSocket pipeline protocol controls."""

from __future__ import annotations

import asyncio
import copy
import importlib.util
import json
import ssl
import sys
from collections.abc import Callable
from contextlib import asynccontextmanager
from importlib.resources import files
from typing import Any

import pytest
from aiohttp import web

SPEC = importlib.util.spec_from_file_location(
    "ha_owned_pipelines", str(files("ops_deploy.services.homeassistant").joinpath("files/pipelines.py"))
)
assert SPEC is not None
assert SPEC.loader is not None
pipelines = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipelines)
TOKEN = "owned-synthetic-pipeline-token-00000"


def definition(name: str = "Room", **kwargs: Any) -> dict[str, Any]:
    return {
        "name": name,
        "language": "en",
        "conversation_engine": "conversation.home_assistant",
        "conversation_language": "en",
        "stt_engine": "stt.owned",
        "stt_language": "en",
        "tts_engine": "tts.owned",
        "tts_language": "en",
        "tts_voice": "",
        **kwargs,
    }


def initial() -> dict[str, Any]:
    return {
        "pipelines": [
            {
                "id": "selected",
                **definition(),
                "wake_word_entity": "wake_word.owned",
                "wake_word_id": "owned-wake",
                "prefer_local_intents": True,
                "acknowledge_media_id": "owned-ack",
                "private": "never-export",
            },
            {"id": "other", **definition("Unlisted"), "private": "unlisted-private"},
        ],
        "preferred_pipeline": "other",
    }


@asynccontextmanager
async def endpoint(
    state: dict[str, Any],
    fault: str = "normal",
    persist: Callable[[], None] | None = None,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> Any:
    calls: list[dict[str, Any]] = []

    async def websocket(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_json({"type": "auth_required"})
        assert await ws.receive_json() == {"type": "auth", "access_token": TOKEN}
        await ws.send_json({"type": "auth_invalid" if fault == "auth" else "auth_ok"})
        if fault == "auth":
            await ws.close()
            return ws
        async for message in ws:
            body = json.loads(message.data)
            calls.append(body)
            kind = body["type"].rsplit("/", 1)[-1]
            if fault == "stall":
                await asyncio.sleep(1)
                break
            if fault == "closed":
                await ws.close()
                break
            result: Any = {}
            if body["type"] == "config/entity_registry/list":
                result = state.get(
                    "entities",
                    [
                        {
                            "entity_id": "stt.owned",
                            "platform": "wyoming",
                            "config_entry_id": "owned-entry",
                            "disabled_by": None,
                        }
                    ],
                )
            elif kind == "list":
                result = state
            elif kind == "get":
                result = next(item for item in state["pipelines"] if item["id"] == body["pipeline_id"])
            elif kind == "create":
                result = {key: val for key, val in body.items() if key not in {"id", "type"}}
                result["id"] = "created-" + str(len(state["pipelines"]))
                state["pipelines"].append(result)
            elif kind == "update":
                result = next(item for item in state["pipelines"] if item["id"] == body["pipeline_id"])
                result.update({key: val for key, val in body.items() if key not in {"id", "type", "pipeline_id"}})
            elif kind == "set_preferred":
                state["preferred_pipeline"] = body["pipeline_id"]
            else:
                raise AssertionError(kind)
            if persist is not None and kind in {"create", "update", "set_preferred"}:
                persist()
            await ws.send_json({"id": 999999, "success": True, "result": "unmatched-private"})
            await ws.send_json(
                {"id": body["id"], "success": fault != kind, "result": result, "error": "unexported-fault"}
            )
        return ws

    async def ready(request: web.Request) -> web.Response:
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        calls.append({"type": "readiness"})
        return web.Response(status=200)

    app = web.Application()
    app.router.add_get("/api/", ready)
    app.router.add_get("/api/websocket", websocket)
    runner = web.AppRunner(app, shutdown_timeout=0.1)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context)
    await site.start()
    try:
        yield f"{'https' if ssl_context else 'http'}://127.0.0.1:{runner.addresses[0][1]}", calls
    finally:
        await runner.cleanup()


def payload(url: str, desired: list[dict[str, Any]], action: str = "apply") -> dict[str, Any]:
    return {"url": url, "token": TOKEN, "desired": desired, "action": action, "timeout": 3}


@pytest.mark.parametrize(
    "desired",
    [[definition(language="de")], [definition("New", preferred=True)], [definition(preferred=True)], [definition()]],
)
def test_inspection_and_apply_then_strict_repeat(desired: list[dict[str, Any]]) -> None:
    async def scenario() -> None:
        state = initial()
        async with endpoint(state) as (url, calls):
            before = copy.deepcopy(state)
            plan = await pipelines.run(payload(url, desired, "inspect"), pipelines.new_report())
            assert plan["success"]
            assert plan["pending"] == (0 if desired == [definition()] else 1)
            assert not plan["changed"]
            assert calls == [{"type": "assist_pipeline/pipeline/list", "id": 1}]
            assert state == before
            first = await pipelines.run(payload(url, desired), pipelines.new_report())
            assert first["success"]
            assert first["applied"] == first["mutation_attempts"]
            after = copy.deepcopy(state)
            calls.clear()
            repeat = await pipelines.run(payload(url, desired), pipelines.new_report())
            assert repeat["success"]
            assert repeat["mutation_attempts"] == repeat["applied"] == repeat["pending"] == 0
            assert state == after
            assert calls == [{"type": "assist_pipeline/pipeline/list", "id": 1}]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("fault", "desired", "phase", "attempts"),
    [
        ("auth", [definition()], "authenticate", 0),
        ("list", [definition()], "list", 0),
        ("create", [definition("New")], "create", 1),
        ("update", [definition(language="de")], "update", 1),
        ("set_preferred", [definition(preferred=True)], "preferred", 1),
        ("stall", [definition()], "list", 0),
        ("closed", [definition()], "list", 0),
    ],
)
def test_real_fault_reports_known_attempts_not_zero_claim(
    fault: str, desired: list[dict[str, Any]], phase: str, attempts: int
) -> None:
    async def scenario() -> None:
        state = initial()
        async with endpoint(state, fault) as (url, _calls):
            value = payload(url, desired)
            if fault == "stall":
                value["timeout"] = 0.05
            report = await pipelines.run(value, pipelines.new_report())
        assert not report["success"]
        assert report["phase"] == phase
        assert report["mutation_attempts"] == attempts
        assert report["applied"] == 0
        assert (state != initial()) == bool(attempts)
        assert report["changed"] == bool(attempts)
        assert "unexported-fault" not in json.dumps(report)
        if fault == "stall":
            assert report["error"] == "TimeoutError"

    asyncio.run(scenario())


def test_actual_helper_main() -> None:
    async def scenario() -> None:
        async with endpoint(initial()) as (url, calls):
            source = files("ops_deploy.services.homeassistant").joinpath("files/pipelines.py").read_text()
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                "-B",
                "-c",
                source,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(json.dumps(payload(url, [definition()])).encode()), 10
            )
            assert process.returncode == 0
            assert stderr == b""
            report = json.loads(stdout)
            assert report["success"]
            assert set(report) == set(pipelines.new_report())
            assert report["mutation_attempts"] == 0
            assert len(calls) == 1
            assert TOKEN.encode() not in stdout

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("manage_stt", "manage_tts", "current"),
    [
        (True, False, False),
        (False, True, False),
        (True, True, False),
        (True, True, True),
        (False, False, False),
    ],
)
def test_standalone_voice_requests_state_and_repeat(manage_stt: bool, manage_tts: bool, current: bool) -> None:
    async def scenario() -> None:
        desired = {
            "stt_engine": "stt.owned" if current else "stt.new",
            "stt_language": "en" if current else "de",
            "tts_engine": "tts.owned" if current else "tts.new",
            "tts_language": "en" if current else "de",
            "tts_voice": "" if current else "owned-voice",
        }
        new = initial()
        changed = not current and (manage_stt or manage_tts)
        async with endpoint(new) as (url, new_calls):
            value = {
                **payload(url, []),
                "mode": "voice",
                "pipeline_id": "selected",
                "manage_stt": manage_stt,
                "manage_tts": manage_tts,
                "voice": desired,
            }
            before = copy.deepcopy(new)
            plan = await pipelines.run({**value, "action": "inspect"}, pipelines.new_report())
            assert plan["success"]
            assert plan["pending"] == int(changed)
            assert plan["mutation_attempts"] == 0
            assert new == before
            new_calls.clear()
            first = await pipelines.run(value, pipelines.new_report())
            assert first["success"]
            assert first["changed"] == changed
            assert (new != before) is changed
            after = copy.deepcopy(new)
            new_calls.clear()
            repeat = await pipelines.run(value, pipelines.new_report())
            assert repeat["success"]
            assert repeat["mutation_attempts"] == repeat["applied"] == 0
            assert new == after
            assert new_calls == [{"type": "assist_pipeline/pipeline/get", "pipeline_id": "selected", "id": 1}]
            assert new["preferred_pipeline"] == before["preferred_pipeline"]
            for key in (
                "wake_word_entity",
                "wake_word_id",
                "prefer_local_intents",
                "acknowledge_media_id",
                "conversation_engine",
            ):
                assert new["pipelines"][0][key] == before["pipelines"][0][key]

    asyncio.run(scenario())


def test_standalone_voice_partial_update_failure() -> None:

    async def scenario() -> None:
        state = initial()
        async with endpoint(state, "update") as (url, _calls):
            value = {
                **payload(url, []),
                "mode": "voice",
                "pipeline_id": "selected",
                "manage_stt": True,
                "manage_tts": False,
                "voice": {"stt_engine": "stt.new", "stt_language": "de"},
            }
            report = await pipelines.run(value, pipelines.new_report())
            assert not report["success"]
            assert report["phase"] == "update"
            assert report["mutation_attempts"] == 1
            assert report["applied"] == 0
            assert report["changed"]
            assert state["pipelines"][0]["stt_engine"] == "stt.new"
            assert "selected" not in json.dumps(report)

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["get", "stall", "closed"])
def test_voice_get_fault_has_exact_phase_and_no_attempt(fault: str) -> None:
    async def scenario() -> None:
        state = initial()
        async with endpoint(state, fault) as (url, calls):
            value = {
                **payload(url, []),
                "mode": "voice",
                "pipeline_id": "selected",
                "manage_stt": True,
                "manage_tts": False,
                "voice": {"stt_engine": "stt.new", "stt_language": "de"},
            }
            if fault == "stall":
                value["timeout"] = 0.05
            report = await pipelines.run(value, pipelines.new_report())
        assert not report["success"]
        assert report["phase"] == "get"
        assert report["mutation_attempts"] == 0
        assert state == initial()
        assert calls == [{"type": "assist_pipeline/pipeline/get", "pipeline_id": "selected", "id": 1}]

    asyncio.run(scenario())
