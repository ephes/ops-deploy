"""Real owned named-storage/HTTP/WS/LocalConnector wiring; no inventory."""

from __future__ import annotations

import asyncio
import copy
import importlib.util
import json
import os
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.homeassistant.integration_flows import ApiReadiness, HomeAssistantApiConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from tests.test_homeassistant_pipelines import TOKEN, endpoint, initial

CHILD = r"""
import json,shlex,sys
from unittest.mock import patch
from pydantic import SecretStr
from pyinfra.api import Config,Inventory,State
from pyinfra.api.connect import connect_all,disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.api.exceptions import PyinfraError
from ops_deploy.services.homeassistant import pipelines as module
from ops_deploy.services.homeassistant.builtin_conversation import ConversationResult
from ops_deploy.services.homeassistant.integration_flows import ApiReadiness,HomeAssistantApiConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing.harness import collect_ops
v=json.loads(sys.stdin.readline())
runtime=HomeAssistantRuntimeConfig(config_path=v['root'])
runtime=runtime.model_copy(update={'security':runtime.security.model_copy(update={'system_python':sys.executable})})
api=HomeAssistantApiConfig(url=SecretStr(v['url']),token=SecretStr(v['token']),timeout=3,retries=0,retry_delay=0)
def command(runtime):
    return shlex.join([sys.executable,'-I','-B',v['program']])
from ops_deploy.services.homeassistant import live_registry
registry_command=lambda runtime: shlex.join([sys.executable,'-I','-B',v['registry_program']])
module.registry_command=live_registry.registry_command=registry_command
module.pipeline_command=command  # Owned child interpreter/user transport for every execution phase.
result=module.PipelineResult()
reports=[]
for number in range(v['runs']):
    state=State(Inventory(([('@local',{})],{})),Config(DIFF=v['diff']))
    registered=[]
    try:
        connect_all(state)
        add_deploy(state,lambda:registered.extend(module.manage_pipelines(runtime,api,ApiReadiness(),
            v['mode'],SecretStr(json.dumps(v['options'])),result,app_port=10020)))
        print('PLANNED',flush=True);input()
        error=False
        try:run_ops(state)
        except PyinfraError:error=True
        ops=collect_ops(state,'@local')
        reports.append({'error':error,'succeeded':all(x.succeeded for x in ops),
                        'managed':sum(x.changed and not x.read_only for x in ops),
                        'failed_hosts':sorted(h.name for h in state.failed_hosts),
                        'result':{k:val for k,val in vars(result).items() if k!='selected'}})
        print('DONE',flush=True);input()
    finally:disconnect_all(state)
print('RESULT '+json.dumps(reports),flush=True)
"""


def storage(root: Path, name: str, value: Any) -> None:
    path = root / ".storage" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"data": value}))


def snapshot(root: Path) -> dict[str, Any]:
    return {
        p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ctime_ns, p.stat().st_ino)
        for p in (root / ".storage").iterdir()
    }


@pytest.mark.parametrize(
    "case",
    [
        "list",
        "voice",
        "auto-list",
        "auto-voice",
        "auto-list-saved",
        "auto-voice-saved",
        "auto-list-missing",
        "auto-voice-missing",
        "stt-voice",
        "current-voice",
        "create",
        "auth",
        "partial",
        "missing-stt",
        "canary",
    ],
)
@pytest.mark.parametrize("diff", [False, True])
def test_actual_sdk_pipeline_selection_readiness_and_repeat(tmp_path: Path, case: str, diff: bool) -> None:
    async def scenario() -> None:
        state = initial()
        original_other = copy.deepcopy(state["pipelines"][1])
        mode = (
            "voice"
            if case.startswith("auto-voice") or case in {"voice", "stt-voice", "current-voice", "missing-stt"}
            else "list"
        )
        options: dict[str, Any] = {"wyoming_host": "owned", "wyoming_port": 10300}
        storage(tmp_path, "core.entity_registry", {"entities": [{"entity_id": "stt.owned"}]})
        if mode == "list":
            options["pipelines"] = [
                {
                    "name": "New" if case == "create" else "Room",
                    "language": "de",
                    "stt_engine_id": "stt.owned",
                    "tts_engine_id": "tts.owned",
                }
            ]
            if case == "create":
                options["pipelines"][0]["preferred"] = True
            if case == "canary":
                options["llama_cpp_enabled"] = True
                options["pipelines"][0]["conversation_engine"] = "auto:llama_cpp"
        else:
            options.update(
                manage_stt=case in {"stt-voice", "missing-stt"},
                manage_tts=True,
                pipeline_id="selected",
                stt_engine_id="stt.missing" if case == "missing-stt" else "stt.owned",
                tts_engine_id="tts.owned",
                tts_language="en" if case == "current-voice" else "de",
            )

        if case.startswith("auto-"):
            if not case.endswith(("saved", "missing")):
                options["wyoming_entry_id"] = "owned-entry"
            storage(
                tmp_path,
                "core.config_entries",
                {
                    "entries": [
                        {"domain": "wyoming", "entry_id": "owned-entry", "data": {"host": "owned", "port": 10300}}
                    ]
                    if case.endswith("saved")
                    else []
                },
            )
            state["entities"] = [
                {
                    "entity_id": kind + ".disabled",
                    "platform": "wyoming",
                    "config_entry_id": "owned-entry",
                    "disabled_by": "user",
                }
                for kind in ("stt", "tts")
            ] + [
                {
                    "entity_id": kind + ".owned",
                    "platform": "wyoming",
                    "config_entry_id": "owned-entry",
                    "disabled_by": None,
                    "options": {"private": "unexported-fault"},
                }
                for kind in ("stt", "tts")
            ]
            storage(tmp_path, "core.entity_registry", {"entities": []})
            if mode == "list":
                options["pipelines"][0].pop("stt_engine_id")
                options["pipelines"][0].pop("tts_engine_id")
            else:
                options.update(manage_stt=True, stt_engine_id="", tts_engine_id="")

        def persist() -> None:
            storage(
                tmp_path,
                "assist_pipeline.pipelines",
                {"preferred_item": state["preferred_pipeline"], "items": state["pipelines"]},
            )

        persist()
        fault = {"auth": "auth", "partial": "update"}.get(case, "normal")
        async with endpoint(state, fault, persist) as (url, calls):
            value = {
                "url": url,
                "token": TOKEN,
                "mode": mode,
                "options": options,
                "root": str(tmp_path),
                "runs": 2
                if (case.startswith("auto-") and not case.endswith("missing"))
                or case in {"list", "voice", "stt-voice", "create"}
                else 1,
                "diff": diff,
                "program": str(files("ops_deploy.services.homeassistant").joinpath("files/pipelines.py")),
                "registry_program": str(files("ops_deploy.services.homeassistant").joinpath("files/live_registry.py")),
            }
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                CHILD,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "NETRC": str(tmp_path / "absent-owned-netrc")},
            )
            assert proc.stdin is not None
            assert proc.stdout is not None
            assert proc.stderr is not None
            try:
                proc.stdin.write((json.dumps(value) + "\n").encode())
                await proc.stdin.drain()
                for number in range(value["runs"]):
                    before_calls = len(calls)
                    before = snapshot(tmp_path)
                    assert await asyncio.wait_for(proc.stdout.readline(), 20) == b"PLANNED\n"
                    assert len(calls) == before_calls
                    assert snapshot(tmp_path) == before
                    proc.stdin.write(b"execute\n")
                    await proc.stdin.drain()
                    line = await asyncio.wait_for(proc.stdout.readline(), 20)
                    if line != b"DONE\n":
                        _, err = await proc.communicate()
                        raise AssertionError(err.decode())
                    if number or case in {"current-voice", "auth", "missing-stt", "canary"}:
                        assert snapshot(tmp_path) == before
                    if case == "current-voice":
                        assert calls == []
                    if case == "missing-stt":
                        assert [c["type"] for c in calls] == ["readiness", "config/entity_registry/list"]
                    if case == "stt-voice" and not number:
                        assert [c["type"] for c in calls] == [
                            "readiness",
                            "config/entity_registry/list",
                            "assist_pipeline/pipeline/get",
                            "assist_pipeline/pipeline/get",
                            "assist_pipeline/pipeline/update",
                        ]
                    if case == "canary":
                        assert calls == []
                    if number and case in {"voice", "stt-voice"}:
                        assert len(calls) == before_calls
                    proc.stdin.write(b"next\n")
                    await proc.stdin.drain()
                proc.stdin.close()
                out, err = await asyncio.wait_for(proc.communicate(), 20)
                assert proc.returncode == 0, err.decode()
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.communicate()
            assert TOKEN.encode() not in out + err
            assert b"unexported-fault" not in out + err
            report = json.loads(out.decode().strip().removeprefix("RESULT "))
            if case.endswith("missing") or case in {"auth", "partial", "missing-stt", "canary"}:
                assert not report[0]["succeeded"]
                assert report[0]["failed_hosts"] == ["@local"]
                assert report[0]["result"]["completed"] is False
                if case == "partial":
                    assert state["pipelines"][0]["language"] == "de"
                    assert report[0]["result"]["mutation_attempts"] == 1
            else:
                assert all(r["succeeded"] and not r["error"] for r in report), err.decode()
                assert [r["managed"] for r in report] == ([0] if case == "current-voice" else [1, 0])
                assert report[-1]["result"]["completed"]
            assert state["pipelines"][1] == original_other

    asyncio.run(scenario())


def test_stt_live_retry_and_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    source = files("ops_deploy.services.homeassistant").joinpath("files/live_registry.py")
    spec = importlib.util.spec_from_file_location("owned_stt_wait", str(source))
    assert spec is not None
    assert spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    calls: list[str] = []
    sleeps: list[int] = []

    async def registry(payload: dict[str, Any]) -> list[dict[str, str]]:
        calls.append("read")
        return [{"entity_id": "stt.synthetic"}] if sleeps else []

    async def sleep(delay: int) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(helper, "registry", registry)
    monkeypatch.setattr(helper.asyncio, "sleep", sleep)
    payload = {"entity_id": "stt.synthetic", "retries": 2, "delay": 5}
    assert asyncio.run(helper.query(payload)) == {"success": True, "ready": True, "attempts": 2}
    assert sleeps == [5]
    assert len(calls) == 2
    assert asyncio.run(helper.query(payload)) == {"success": True, "ready": True, "attempts": 1}
    payload["entity_id"] = "stt.absent"
    assert asyncio.run(helper.query(payload)) == {"success": True, "ready": False, "attempts": 3}


@pytest.mark.parametrize("shared", [False, True])
def test_two_host_registration_and_operation_barriers(monkeypatch: pytest.MonkeyPatch, shared: bool) -> None:
    from pydantic import SecretStr
    from pyinfra import host
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.host import Host
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant import pipelines as module

    events: list[tuple[str, str]] = []
    results: dict[str, module.PipelineResult] = {}
    shared_result = module.PipelineResult()

    def prepare(target: Host, *args: Any, **kwargs: Any) -> SecretStr:
        events.append(("prepare", target.name))
        return SecretStr(json.dumps([{"name": target.name}]))

    def protocol(target: Host, command: str, payload: SecretStr, timeout: int, result: Any) -> dict[str, Any]:
        events.append(("inspect", target.name))
        assert {name for phase, name in events if phase == "prepare"} == {"@fake/a", "@fake/b"}
        assert json.loads(payload.get_secret_value())["desired"] == [{"name": target.name}]
        return {"pending": 0}

    monkeypatch.setattr(module, "read_pipeline_preparation", prepare)
    monkeypatch.setattr(module, "_protocol", protocol)
    from ops_deploy.services.homeassistant import integration_flows

    monkeypatch.setattr(integration_flows, "_run", lambda *a, **k: {"success": True, "ready": True})
    state = State(Inventory((["@fake/a", "@fake/b"], {})), Config())

    def deploy() -> None:
        result = shared_result if shared else module.PipelineResult()
        results[host.name] = result
        module.manage_pipelines(
            HomeAssistantRuntimeConfig(),
            HomeAssistantApiConfig(token=SecretStr(TOKEN)),
            ApiReadiness(ready=True),
            "list",
            SecretStr("{}"),
            result,
            app_port=10020,
        )

    try:
        connect_all(state)
        if shared:
            with pytest.raises(ValueError, match="separately for each host"):
                add_deploy(state, deploy)
            assert events == []  # Refusal is before even named-storage/API inspection.
        else:
            add_deploy(state, deploy)
            assert events == []
            run_ops(state)
            assert all(result.completed for result in results.values())
            assert not state.failed_hosts
            assert len(events) == 4
    finally:
        disconnect_all(state)


@pytest.mark.parametrize("error_type", [OSError, __import__("paramiko").SSHException])
def test_transport_loss_is_accounted_per_host(monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]) -> None:
    from types import SimpleNamespace

    from pydantic import SecretStr
    from pyinfra import host
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.host import Host
    from pyinfra.api.operation import OperationMeta
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant import pipelines as module

    calls: list[str] = []
    registered: dict[str, OperationMeta] = {}
    results: dict[str, module.PipelineResult] = {}

    def transport(target: Host, *args: Any, **kwargs: Any) -> Any:
        calls.append(target.name)
        if target.name.endswith("bad"):
            raise error_type("private-transport-detail")
        return True, SimpleNamespace(
            stdout=json.dumps(
                {
                    "success": True,
                    "phase": "complete",
                    "pending": 0,
                    "mutation_attempts": 0,
                    "applied": 0,
                    "changed": False,
                    "error": "",
                }
            )
        )

    monkeypatch.setattr(Host, "run_shell_command", transport)
    state = State(Inventory((["@fake/bad", "@fake/good"], {})), Config())

    def deploy() -> None:
        result = module.PipelineResult(selected=SecretStr("[]"), prepared=True, needed=True)
        results[host.name] = result
        registered[host.name] = module._reconcile(
            runtime=HomeAssistantRuntimeConfig(),
            api=HomeAssistantApiConfig(token=SecretStr(TOKEN)),
            mode="list",
            result=result,
            app_port=10020,
        )

    try:
        connect_all(state)
        add_deploy(state, deploy)
        assert calls == []
        run_ops(state)
        assert set(calls) == {"@fake/bad", "@fake/good"}
        assert registered["@fake/bad"].did_error()
        assert registered["@fake/good"].did_succeed()
        assert {item.name for item in state.failed_hosts} == {"@fake/bad"}
        assert {item.name for item in state.active_hosts} == {"@fake/good"}
        assert results["@fake/good"].completed
        assert not results["@fake/bad"].completed
        assert results["@fake/bad"].mutation_attempts is None
    finally:
        disconnect_all(state)
