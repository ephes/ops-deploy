"""Real owned loopback WebSockets and original-script oracle; no HA inventory."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib.util
import json
import os
import sys
from contextlib import asynccontextmanager
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
import yaml
from aiohttp import web
from pydantic import SecretStr

from ops_deploy.services.homeassistant.area_registry import area_command, area_payload, validate_updates
from ops_deploy.services.homeassistant.integration_flows import HomeAssistantApiConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

SPEC = importlib.util.spec_from_file_location(
    "ha_areas_owned", str(files("ops_deploy.services.homeassistant").joinpath("files/area_registry.py"))
)
assert SPEC is not None
assert SPEC.loader is not None
areas = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(areas)
TOKEN = "synthetic-owned-area-token-00000000"
ORIGINAL = Path(__file__).parent / "parity/homeassistant/area-registry/original.yml"


def original_script() -> str:
    tasks = yaml.safe_load(ORIGINAL.read_text())
    task = next(item for item in tasks if item["name"] == "Update Home Assistant area registry via WebSocket API")
    return str(task["ansible.builtin.command"]["argv"][-1])


def initial() -> list[dict[str, Any]]:
    return [
        {
            "area_id": "owned",
            "name": "Room",
            "aliases": ["Before"],
            "floor_id": "private-floor",
            "temperature_entity_id": "sensor.old",
            "humidity_entity_id": None,
            "icon": "mdi:home",
        },
        {"area_id": "unlisted", "name": "Other", "aliases": ["Do not change"], "private": "no-export"},
    ]


@asynccontextmanager
async def endpoint(state: list[dict[str, Any]], outcome: str = "normal") -> Any:
    calls: list[dict[str, Any]] = []

    async def websocket(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_json({"type": "auth_required"})
        auth = await ws.receive_json()
        assert auth == {"type": "auth", "access_token": TOKEN}
        await ws.send_json({"type": "auth_invalid" if outcome == "auth-fail" else "auth_ok"})
        if outcome == "auth-fail":
            await ws.close()
            return ws
        async for message in ws:
            body = json.loads(message.data)
            calls.append(body)
            if outcome == "stall":
                await asyncio.sleep(1)
                break
            if outcome == "closed":
                await ws.close()
                break
            # Out-of-sequence event/ID must not be taken as our result.
            await ws.send_json({"id": 987654, "success": True, "result": "private-event"})
            if body["type"] == "config/area_registry/list":
                await ws.send_json({"id": body["id"], "success": outcome != "list-fail", "result": state})
            else:
                selected = next(item for item in state if item["area_id"] == body["area_id"])
                selected.update({key: value for key, value in body.items() if key not in {"type", "id", "area_id"}})
                # Fault AFTER applying models an unknown remote-effect response.
                await ws.send_json({"id": body["id"], "success": outcome != "update-fail", "error": "private-error"})
        return ws

    async def ready(request: web.Request) -> web.Response:
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        calls.append({"type": "readiness"})
        return web.Response(status=200)

    app = web.Application()
    app.router.add_get("/api/", ready)
    app.router.add_get("/api/websocket", websocket)
    app.router.add_get("/prefix/api/websocket", websocket)
    runner = web.AppRunner(app, shutdown_timeout=0.1)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        port = runner.addresses[0][1]
        yield f"http://127.0.0.1:{port}", calls
    finally:
        await runner.cleanup()


def value(url: str, updates: list[dict[str, Any]], action: str = "apply") -> dict[str, Any]:
    return {"url": url, "token": TOKEN, "timeout": 3, "updates": updates, "action": action}


@pytest.mark.parametrize(
    "desired",
    [
        [{"name": "Room", "aliases": ["  New ", "new", 4, "", "Second"], "humidity_entity_id": " sensor.humidity "}],
        [{"area_id": "owned", "temperature_entity_id": "", "name": "Not-the-name"}],
        [{"area_id": "owned", "aliases": ["Before"], "humidity_entity_id": None}],
        [{"area_id": "owned", "aliases": ["New"]}, {"area_id": "owned", "aliases": ["New"]}],
        [{"area_id": "owned", "aliases": ["New"]}, {"area_id": "missing", "aliases": []}],
        [{"area_id": "missing", "name": "Room", "aliases": []}],
    ],
)
def test_actual_original_script_and_typed_exchange_match_owned_state(
    tmp_path: Path, desired: list[dict[str, Any]]
) -> None:
    async def scenario() -> None:
        old_state, new_state = initial(), initial()
        result_file = tmp_path / "original-result.json"
        async with endpoint(old_state) as (url, old_calls):
            env = dict(
                os.environ,
                HA_API_URL=url,
                HA_TIMEOUT="3",
                HA_AREA_UPDATES=json.dumps(desired),
                HA_RESULT_PATH=str(result_file),
            )
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                "-B",
                "-c",
                original_script(),
                env=env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(json.dumps({"HA_TOKEN": TOKEN}).encode()), 10)
            old_result = json.loads(result_file.read_text())
        async with endpoint(new_state) as (url, new_calls):
            report = await areas.run(value(url, desired), areas.new_report())
        assert new_state == old_state
        assert new_calls == old_calls
        assert report["success"] == (old_result["status"] == "success")
        attempts = len([item for item in new_calls if item["type"].endswith("/update")])
        assert report["mutation_attempts"] == attempts
        assert report["changed"] == bool(attempts)
        assert new_state[1] == initial()[1]
        for key in ("floor_id", "icon"):
            assert new_state[0][key] == initial()[0][key]
        assert "private" not in json.dumps(report)
        assert TOKEN not in json.dumps(report)

    asyncio.run(scenario())


def test_inspect_first_repeat_and_whole_unrelated_state() -> None:
    async def scenario() -> None:
        state = initial()
        desired = [{"area_id": "owned", "aliases": ["New"]}]
        async with endpoint(state) as (url, calls):
            before = copy.deepcopy(state)
            plan = await areas.run(value(url, desired, "inspect"), areas.new_report())
            assert plan["success"]
            assert plan["pending"] == 1
            assert plan["mutation_attempts"] == 0
            assert state == before
            assert all(item["type"].endswith("/list") for item in calls)
            first = await areas.run(value(url, desired), areas.new_report())
            assert first["success"]
            assert first["applied"] == first["mutation_attempts"] == 1
            after = copy.deepcopy(state)
            calls.clear()
            repeat = await areas.run(value(url, desired), areas.new_report())
            assert repeat["success"]
            assert not repeat["changed"]
            assert repeat["pending"] == 0
            assert state == after
            assert len(calls) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("outcome", "phase", "attempts"),
    [
        ("auth-fail", "authenticate", 0),
        ("list-fail", "list", 0),
        ("update-fail", "update", 1),
        ("closed", "list", 0),
        ("stall", "list", 0),
    ],
)
def test_actual_protocol_faults_keep_effects_and_private_data(outcome: str, phase: str, attempts: int) -> None:
    async def scenario() -> None:
        state = initial()
        async with endpoint(state, outcome) as (url, _calls):
            payload = value(url, [{"area_id": "owned", "aliases": ["New"]}])
            if outcome == "stall":
                payload["timeout"] = 0.05
            report = await areas.run(payload, areas.new_report())
        assert not report["success"]
        assert report["phase"] == phase
        assert report["mutation_attempts"] == attempts
        assert report["changed"] == bool(attempts)
        assert report["applied"] == 0
        assert state[0]["aliases"] == (["New"] if attempts else ["Before"])
        assert "private-error" not in json.dumps(report)
        assert TOKEN not in json.dumps(report)
        if outcome == "stall":
            assert report["error"] == "TimeoutError"

    asyncio.run(scenario())


def test_actual_helper_main_fixed_report_and_prefix() -> None:
    async def scenario() -> None:
        async with endpoint(initial()) as (url, calls):
            script = files("ops_deploy.services.homeassistant").joinpath("files/area_registry.py").read_text()
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                "-B",
                "-c",
                script,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(
                    json.dumps(value(url + "/prefix", [{"name": "Room", "aliases": ["New"]}], "inspect")).encode()
                ),
                10,
            )
            assert proc.returncode == 0
            assert stderr == b""
            report = json.loads(stdout)
            assert report["success"]
            assert report["pending"] == 1
            assert len(calls) == 1
            assert set(report) == set(areas.new_report())
            assert TOKEN.encode() not in stdout
            assert b"Room" not in stdout

    asyncio.run(scenario())


def test_last_duplicate_id_name_and_normalization() -> None:
    state = [*initial(), {"area_id": "owned", "name": "Room", "aliases": ["Last"]}]
    assert list(areas.selected_updates(state, [{"name": "Room", "aliases": ["Last"]}])) == []
    assert areas.normalize_aliases([" a ", "A", 3, "ß", "SS", "", None]) == ["a", "ß"]
    assert areas.normalize_aliases("not-list") == []


@pytest.mark.parametrize(
    ("url", "expected"),
    [("http://host", "ws://host/api/websocket"), ("https://host/prefix/?old=1#x", "wss://host/prefix/api/websocket")],
)
def test_original_websocket_url(url: str, expected: str) -> None:
    assert areas.websocket_url(url) == expected


def test_actual_command_selected_interpreter_and_original_loopback_rewrite() -> None:
    cfg = HomeAssistantRuntimeConfig(virtualenv_path="/srv/owned/.venv", user="owned", home="/srv/owned")
    api = HomeAssistantApiConfig(
        url=SecretStr("https://localhost/prefix"), token=SecretStr(TOKEN), default_ipv4="192.0.2.7"
    )
    payload = json.loads(area_payload(api, [{"name": "Room"}], "inspect", app_port=10020).get_secret_value())
    assert payload["url"] == "http://192.0.2.7:10020"
    command = area_command(cfg)
    assert "/srv/owned/.venv/bin/python" in command
    assert "owned" in command
    assert TOKEN not in command
    assert "Room" not in command


def test_original_aggregate_selector_edge_and_alias_type() -> None:
    validate_updates([{"area_id": "owned", "name": "Room"}, {}])
    with pytest.raises(ValueError, match="selectors"):
        validate_updates([{}])
    with pytest.raises(ValueError, match="list"):
        validate_updates([{"name": "Room", "aliases": "bad"}])
    validate_updates([{"name": "Room", "aliases": [1, None, "ok"]}])


def test_captured_original_source_hash() -> None:
    receipt = json.loads(ORIGINAL.with_name("source.json").read_text())
    assert hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() == receipt["sha256"]
    assert receipt["path"] == "roles/homeassistant_deploy/tasks/area_registry.yml"


@pytest.mark.parametrize(
    "updates",
    [
        [{"area_id": "owned", "aliases": ["New"]}, {}],
        [{"area_id": "owned", "name": "Room"}, {}],
        [{"name": "Room", "aliases": "invalid"}],
        [{"name": "Room", "aliases": [1, None, "fine"]}],
    ],
)
def test_original_preceding_validation_matches_actual_payload(updates: list[dict[str, Any]]) -> None:
    from jinja2.nativetypes import NativeEnvironment

    tasks = yaml.safe_load(ORIGINAL.with_name("validate.yml").read_text())
    check = next(
        item["ansible.builtin.assert"]["that"]
        for item in tasks
        if item["name"] == "Validate Home Assistant area registry updates"
    )
    env = NativeEnvironment()
    env.filters["type_debug"] = lambda item: type(item).__name__
    context = {
        "homeassistant_api_url": "http://owned",
        "homeassistant_api_token": TOKEN,
        "homeassistant_virtualenv_path": "/srv/owned/.venv",
        "homeassistant_area_registry_updates": updates,
    }
    original_pass = all(env.from_string("{{ " + expression + " }}").render(**context) for expression in check)
    api = HomeAssistantApiConfig(token=SecretStr(TOKEN))
    if original_pass:
        area_payload(api, updates, "apply", app_port=10020)
    else:
        with pytest.raises(ValueError, match=r"selectors|list"):
            area_payload(api, updates, "apply", app_port=10020)


def test_validation_is_original_role_prelude_and_sources_bound() -> None:
    manifest = json.loads(ORIGINAL.with_name("source.json").read_text())
    for name, digest in manifest["additional_sources"].items():
        assert hashlib.sha256(ORIGINAL.with_name(name).read_bytes()).hexdigest() == digest
    original_main = ORIGINAL.with_name("main.yml").read_text()
    assert original_main.index("validate.yml") < original_main.index("area_registry.yml")


@pytest.mark.parametrize(
    "change",
    [
        {"applied": 2, "mutation_attempts": 1, "pending": 1, "changed": True},
        {"mutation_attempts": 2, "pending": 1, "changed": True},
        {"mutation_attempts": 1, "pending": 1, "changed": False},
        {"success": True, "phase": "update"},
        {"success": True, "phase": "complete", "error": "Unexpected"},
    ],
)
def test_actual_controller_rejects_inconsistent_effect_reports(change: dict[str, Any]) -> None:
    from types import SimpleNamespace
    from typing import cast

    from pyinfra.api import OperationError
    from pyinfra.api.host import Host

    from ops_deploy.services.homeassistant.area_registry import run_area_protocol

    result = {**areas.new_report(), **change}

    def answer(*args: Any, **kwargs: Any) -> Any:
        assert not kwargs["print_input"]
        assert not kwargs["print_output"]
        return result["success"], SimpleNamespace(stdout=json.dumps(result))

    target = cast(Host, SimpleNamespace(run_shell_command=answer))
    with pytest.raises(OperationError, match="invalid fixed report"):
        run_area_protocol(target, "owned-placeholder", SecretStr("{}"), timeout=3)


@pytest.mark.parametrize("fault", ["normal", "update-fail", "auth-fail"])
def test_actual_managed_sdk_area_plan_first_repeat_and_partial_failure(tmp_path: Path, fault: str) -> None:
    """Real child LocalConnector/protocol against a synthetic loopback server."""
    script = r"""
import base64,json,shlex,sys
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from pydantic import SecretStr
from pyinfra.api import Config,Inventory,State
from pyinfra.api.connect import connect_all,disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.api.exceptions import PyinfraError
from ops_deploy.services.homeassistant import area_registry as module
from ops_deploy.services.homeassistant.integration_flows import ApiReadiness,HomeAssistantApiConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing.harness import collect_ops
value=json.load(sys.stdin)
runtime=HomeAssistantRuntimeConfig()
runtime=runtime.model_copy(update={'security':runtime.security.model_copy(update={'system_python':sys.executable})})
api=HomeAssistantApiConfig(url=SecretStr(value['url']),token=SecretStr(value['token']),timeout=3,retries=0,retry_delay=0)
command=shlex.join([sys.executable,'-I','-B',value['program']])
results=[]
# Reuse the result object to prove stale success cannot survive the next failure.
result=module.AreaResult(completed=True,reported_changed=True,mutation_attempts=99,applied=99)
for iteration in range(value['runs']):
    state=State(Inventory(([('@local',{})],{})),Config())
    registered=[]
    try:
        connect_all(state)
        with patch.object(module,'area_command',lambda runtime:command):
            add_deploy(state,lambda:registered.extend(module.manage_area_registry(
                runtime,api,ApiReadiness(),value['updates'],result,app_port=10020)))
        # This marker lets the parent prove registration has made no HTTP/WS calls.
        print('PLANNED',flush=True)
        input()
        error=False
        try:run_ops(state)
        except PyinfraError:error=True
        ops=collect_ops(state,'@local')
        results.append({'error':error,'succeeded':all(x.succeeded for x in ops),
                        'managed':sum(x.changed and not x.read_only for x in ops),'result':asdict(result),
                        'did_error':registered[-1].did_error(),
                        'failed_hosts':sorted(h.name for h in state.failed_hosts)})
        print('DONE',flush=True)
    finally:disconnect_all(state)
print('RESULT '+json.dumps(results),flush=True)
"""

    async def scenario() -> None:
        current = initial()
        async with endpoint(current, fault) as (url, calls):
            # The endpoint's GET handler below returns status only; no body read.
            value = {
                "url": url,
                "token": TOKEN,
                "runs": 2 if fault == "normal" else 1,
                "updates": [{"area_id": "owned", "aliases": ["Changed"]}],
                "program": str(files("ops_deploy.services.homeassistant").joinpath("files/area_registry.py")),
            }
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                script,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "NETRC": str(tmp_path / "absent-owned-netrc")},
            )
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None
            try:
                process.stdin.write((json.dumps(value) + "\n").encode())
                await process.stdin.drain()
                for _ in range(value["runs"]):
                    before = len(calls)
                    line = await asyncio.wait_for(process.stdout.readline(), 20)
                    assert line == b"PLANNED\n", line
                    assert len(calls) == before
                    process.stdin.write(b"continue\n")
                    await process.stdin.drain()
                    assert await asyncio.wait_for(process.stdout.readline(), 20) == b"DONE\n"
                process.stdin.close()
                stdout, stderr = await asyncio.wait_for(process.communicate(), 30)
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.communicate()
            assert process.returncode == 0, stderr.decode()
            assert TOKEN.encode() not in stdout + stderr
            assert b"private-error" not in stdout + stderr
            result = json.loads(stdout.decode().strip().removeprefix("RESULT "))
            if fault == "normal":
                assert [item["managed"] for item in result] == [1, 0]
                assert all(item["succeeded"] and not item["error"] for item in result)
                assert all(not item["did_error"] and item["failed_hosts"] == [] for item in result)
                assert result[1]["result"] == {
                    "completed": True,
                    "reported_changed": False,
                    "mutation_attempts": 0,
                    "applied": 0,
                }
                assert current[0]["aliases"] == ["Changed"]
                assert [call["type"] for call in calls] == [
                    "readiness",
                    "config/area_registry/list",
                    "config/area_registry/list",
                    "config/area_registry/update",
                    "readiness",
                    "config/area_registry/list",
                ]
                assert current[1] == initial()[1]
            else:
                assert not result[0]["succeeded"]
                assert result[0]["did_error"] is True
                assert result[0]["failed_hosts"] == ["@local"]
                assert result[0]["result"]["completed"] is False
                assert result[0]["result"]["mutation_attempts"] == (1 if fault == "update-fail" else 0)
                if fault == "update-fail":
                    assert current[0]["aliases"] == ["Changed"]  # Failure retains actual partial write.

    # Use line-oriented payload so the child remains available for plan barriers.
    script = script.replace("value=json.load(sys.stdin)", "value=json.loads(sys.stdin.readline())")
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["timeout", "invalid"])
def test_apply_unknown_failure_clears_prior_inspection_success(failure: str) -> None:
    from types import SimpleNamespace
    from typing import cast

    from pyinfra.api import OperationError, State
    from pyinfra.api.host import Host

    from ops_deploy.services.homeassistant.area_registry import AreaResult, _apply_areas

    def answer(*args: Any, **kwargs: Any) -> Any:
        if failure == "timeout":
            raise TimeoutError("private response must not escape")
        return False, SimpleNamespace(stdout="private malformed body")

    target = cast(Host, SimpleNamespace(run_shell_command=answer))
    result = AreaResult(True, False, 0, 0)
    with pytest.raises(OperationError, match="partial effects or remote activity") as caught:
        _apply_areas(cast(State, None), target, "owned", SecretStr("{}"), 1, result)
    assert "private" not in str(caught.value)
    assert result == AreaResult()


def test_inspection_failure_completes_only_failed_host(monkeypatch: pytest.MonkeyPatch) -> None:
    from pyinfra import host
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.host import Host
    from pyinfra.api.operation import OperationMeta
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant import area_registry as module

    registered: dict[str, OperationMeta] = {}
    results: dict[str, module.AreaResult] = {}

    def observe(target: Host, *args: Any, **kwargs: Any) -> dict[str, Any]:
        failed = target.name.endswith("bad")
        return {
            **areas.new_report(),
            "success": not failed,
            "phase": "authenticate" if failed else "complete",
            "error": "RuntimeError" if failed else "",
        }

    monkeypatch.setattr(module, "run_area_protocol", observe)
    state = State(Inventory((["@fake/bad", "@fake/good"], {})), Config())

    def deploy() -> None:
        result = module.AreaResult()
        results[host.name] = result
        registered[host.name] = module._manage_areas(
            command="owned", inspect_payload=SecretStr("{}"), apply_payload=SecretStr("{}"), timeout=1, result=result
        )

    try:
        connect_all(state)
        add_deploy(state, deploy)
        run_ops(state)
        assert registered["@fake/bad"].did_error()
        assert not registered["@fake/bad"].did_succeed()
        assert registered["@fake/good"].did_succeed()
        assert not registered["@fake/good"].did_error()
        assert {item.name for item in state.failed_hosts} == {"@fake/bad"}
        assert {item.name for item in state.active_hosts} == {"@fake/good"}
        assert results["@fake/good"].completed
        assert not results["@fake/bad"].completed
    finally:
        disconnect_all(state)
