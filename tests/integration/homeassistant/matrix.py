"""Real HA current/upgrade, declared recovery and synthetic API peers only."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from ops_deploy.services.homeassistant import HomeAssistantDeployConfig
from ops_deploy.services.homeassistant.builtin_conversation import BuiltinConversationConfig
from ops_deploy.services.homeassistant.configuration_render import ConfigurationValues
from ops_deploy.services.homeassistant.deploy_config import AssistSelection
from ops_deploy.services.homeassistant.ingress import HomeAssistantIngressConfig
from ops_deploy.services.homeassistant.integration_flows import HomeAssistantApiConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

from .fixture import EVIDENCE, VALUES, command, default_ipv4, metadata, write
from .harness import API_URL, CONFIG, HOME, api, original, snapshot, typed, wait_http
from .matter_native import verify_native_dependencies
from .matter_ready import diagnostics, wait_ready
from .model_server import MODEL
from .prerequisites import seed

MODEL_URL = "http://127.0.0.1:18081"


def model(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    request = urllib.request.Request(
        MODEL_URL + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError("owned model control response invalid")
    return value


@contextmanager
def peers() -> Iterator[None]:
    processes: list[subprocess.Popen[bytes]] = []
    streams = []
    try:
        for name, port in (("model_server", 18081), ("wyoming_server", 10300), ("otbr_server", 18082)):
            stream = (EVIDENCE / (name + ".log")).open("wb")
            streams.append(stream)
            process = subprocess.Popen(
                [sys.executable, "-B", str(Path(__file__).with_name(name + ".py"))], stdout=stream, stderr=stream
            )
            processes.append(process)
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise RuntimeError("owned synthetic peer failed before ready")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("owned synthetic peer did not become ready") from None
                    time.sleep(0.1)
        yield
    finally:
        statuses = []
        for process in processes:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            statuses.append({"pid": process.pid, "exit": process.returncode, "reaped": process.poll() is not None})
        for stream in streams:
            stream.close()
        write("synthetic-peer-cleanup.json", {"processes": statuses})


def config(*, token: str = "", selected: bool = False) -> HomeAssistantDeployConfig:
    # Named synthetic endpoints and original pinned application versions only.
    # No inherited inventory/default route can select a real model or radio.
    runtime = HomeAssistantRuntimeConfig(
        package_spec="homeassistant==2026.10.2",
        manage_matter_server=True,
        matter_server_package_spec="python-matter-server[server]==8.1.2",
    )
    result = HomeAssistantDeployConfig(
        runtime=runtime,
        values=ConfigurationValues(internal_url=API_URL, trusted_proxies=("127.0.0.1", default_ipv4())),
        ingress=HomeAssistantIngressConfig(domain="owned.example.test", default_ipv4=default_ipv4()),
        api=HomeAssistantApiConfig(url=SecretStr(API_URL), token=SecretStr(token), default_ipv4=default_ipv4()),
    )
    if selected:
        key = "owned-synthetic-model-api-key"
        VALUES.append(key)
        result = result.model_copy(
            update={
                "builtin_enabled": True,
                "builtin": BuiltinConversationConfig(
                    base_url=SecretStr(MODEL_URL + "/v1"),
                    api_key=SecretStr(key),
                    model=SecretStr(MODEL),
                    instructions=SecretStr("Reply with the single word OK."),
                ),
                "manage_matter_integration": True,
                "manage_otbr_integration": True,
                "otbr_integration_url": SecretStr("http://127.0.0.1:18082"),
                "manage_wyoming_integration": True,
                "wyoming_host": "127.0.0.1",
                "wyoming_port": 10300,
                "assist": AssistSelection(
                    pipelines=SecretStr(
                        json.dumps(
                            [
                                {
                                    "name": "Owned native pipeline",
                                    "language": "en",
                                    "conversation_engine": "auto:llama_cpp",
                                    "preferred": True,
                                }
                            ]
                        )
                    )
                ),
            }
        )
    # model_copy is intentionally followed by full validation before real use.
    return HomeAssistantDeployConfig.model_validate(result.model_dump())


def original_vars(version: str, *, selected: HomeAssistantDeployConfig | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "homeassistant_package_spec": "homeassistant==" + version,
        "homeassistant_python_version": "3.14.8",
        "homeassistant_uv_version": "0.13.5",
        "homeassistant_manage_matter_server": True,
        "homeassistant_matter_server_package_spec": "python-matter-server[server]==8.1.2",
        "homeassistant_traefik_domain": "owned.example.test",
        "homeassistant_internal_url": API_URL,
        "homeassistant_trusted_proxies": ["127.0.0.1", default_ipv4()],
        "homeassistant_api_url": API_URL,
        "homeassistant_unifi_password_source": "variable",
    }
    if selected is not None:
        value.update(
            {
                "homeassistant_api_token": selected.api.token.get_secret_value(),
                "homeassistant_llama_cpp_enabled": True,
                "homeassistant_llama_cpp_base_url": selected.builtin.base_url.get_secret_value(),
                "homeassistant_llama_cpp_api_key": selected.builtin.api_key.get_secret_value(),
                "homeassistant_llama_cpp_model": MODEL,
                "homeassistant_llama_cpp_instructions": selected.builtin.instructions.get_secret_value(),
                "homeassistant_manage_matter_integration": True,
                "homeassistant_manage_otbr_integration": True,
                "homeassistant_otbr_integration_url": "http://127.0.0.1:18082",
                "homeassistant_manage_wyoming_integration": True,
                "homeassistant_wyoming_host": "127.0.0.1",
                "homeassistant_wyoming_port": 10300,
                "homeassistant_assist_pipelines": selected.assist.definitions(),
            }
        )
    return value


def app_identity() -> dict[str, Any]:
    current = snapshot().public["installed"]
    ha = current[".venv"]["distribution"]
    matter = current[".venv-matter-server"]["distribution"]
    assert ha["python"] == "3.14.8"
    assert dict(ha["packages"])["homeassistant"] == "2026.10.2"
    assert dict(matter["packages"])["python-matter-server"] == "8.1.2"
    version = command("/usr/local/bin/uv", "--version").stdout.strip()
    assert version.split()[:2] == ["uv", "0.13.5"]
    return {"applications": current, "uv_raw": version}


def registry(token: str) -> dict[str, Any]:
    # Actual WS returns are only in guest memory. Export named synthetic
    # selections and no config-entry data/options (which contain credentials).
    entries = api("ws", token=token, command_value={"type": "config_entries/get"})["result"]
    domains = [item["domain"] for item in entries]
    pipelines = api("ws", token=token, command_value={"type": "assist_pipeline/pipeline/list"})["result"]
    selected = [item for item in pipelines["pipelines"] if item["name"] == "Owned native pipeline"]
    assert len(selected) == 1
    assert domains.count("llama_cpp") == 1
    assert domains.count("otbr") == 1
    assert domains.count("matter") == 1
    assert domains.count("wyoming") == 1
    assert selected[0]["conversation_engine"] != "conversation.home_assistant"
    assert selected[0]["stt_engine"].startswith("stt.")
    assert selected[0]["tts_engine"].startswith("tts.")
    return {
        "domains": sorted(domains),
        "selected_pipeline": selected[0],
        "preferred_pipeline": pipelines["preferred_pipeline"],
    }


def run() -> None:
    case = os.environ["HOMEASSISTANT_FIXTURE_CASE"]
    assert case in {"current", "upgrade"}
    baseline = "2026.10.2" if case == "current" else "2026.10.1"
    seed(baseline)
    original("00-original-existing-host-bootstrap", original_vars(baseline))
    try:
        verify_native_dependencies()
    except BaseException:
        diagnostics()
        raise
    wait_ready()
    wait_http()
    token = api("seed")["token"]
    assert isinstance(token, str)
    VALUES.append(token)
    write(
        "api-onboarding.json",
        {
            "actual_user_created": True,
            "actual_token_exchange": True,
            "actual_long_lived_token": True,
            "frontend_core_onboarding_completed": False,
            "health": api("health", token=token),
        },
    )
    with peers():
        selected = config(token=token, selected=True)
        if case == "current":
            original("01-original-selected", original_vars("2026.10.2", selected=selected))
            original("02-original-selected-repeat", original_vars("2026.10.2", selected=selected))
        calls = model("/owned/status")
        typed("03-normal-plan", selected, plan=True)
        assert model("/owned/status") == calls
        typed("04-normal-first", selected)
        wait_http()
        write("04-actual-identity.json", app_identity())
        before = registry(token)
        calls = model("/owned/status")
        typed("05-normal-repeat", selected, stable=True)
        after = registry(token)
        assert before == after
        assert model("/owned/status")["completions"] > calls["completions"]
        write("05-selected-registry.json", {"before": before, "after": after, "active_canary_observed": True})
        typed("06-fish-repeat", selected, fish=True, stable=True)
        original("07-original-after-typed", original_vars("2026.10.2", selected=selected))
        typed("08-after-original", selected)
        typed("09-after-original-repeat", selected, stable=True)
        command("systemctl", "stop", "homeassistant.service")
        write(
            "10-stopped-fixture.json",
            {
                "classification": "declared owned fault",
                "state": command("systemctl", "is-active", "homeassistant.service", check=False).stdout.strip(),
            },
        )
        typed("10-stopped-recovery", selected)
        wait_http()
        typed("11-stopped-recovery-repeat", selected, stable=True)
        # Wrong-token canaries are real, but no generic authorization-failure
        # restart or synthesized success is allowed. Preserve all partial ops.
        wrong = secrets.token_urlsafe(48)
        VALUES.append(wrong)
        bad = selected.model_copy(
            update={"api": selected.api.model_copy(update={"token": SecretStr(wrong), "retries": 1})}
        )
        typed("12-invalid-token", bad, failure=True)
        typed("13-auth-corrected-repeat", selected, stable=True)
        model("/owned/fault", {"mode": "empty"})
        typed("14-empty-canary", selected, failure=True)
        model("/owned/fault", {"mode": "normal"})
        typed("15-canary-corrected-repeat", selected, stable=True)
        # Preserve deliberate operator content with the original false policy.
        path = CONFIG / "configuration.yaml"
        original_body = path.read_bytes()
        path.write_bytes(original_body + b"\n# owned preserved operator marker\n")
        preserved = path.read_bytes()
        typed("16-unmanaged-config-preservation", selected)
        assert path.read_bytes() == preserved
        typed("17-unmanaged-config-repeat", selected, stable=True)
        # Restore the explicit synthetic fixture edit before unrelated faults;
        # this is an observed fixture write, not silent application convergence.
        path.write_bytes(original_body)
        write(
            "17-fixture-config-restored.json",
            {"classification": "declared synthetic fixture reset", "metadata": metadata(path)},
        )
        version_file = HOME / ".venv/.ansible-python-version"
        version_file.unlink()
        typed("18-missing-version-record", selected)
        assert version_file.read_text() == "3.14.8\n"
        typed("19-version-record-repeat", selected, stable=True)
        # Missing entire environment is a genuine typed recovery, no preseed.
        command("systemctl", "stop", "homeassistant.service", "matter-server.service")
        shutil.rmtree(HOME / ".venv")
        typed("20-missing-entire-environment", selected)
        wait_http()
        assert api("health", token=token)["status"] == 200
        typed("21-environment-recovery-repeat", selected, stable=True)
        forced = selected.model_copy(update={"runtime": selected.runtime.model_copy(update={"force_reinstall": True})})
        typed("22-explicit-force-reinstall", forced)
        wait_http()
        typed("23-force-cleared-repeat", selected, stable=True)
        write("final-identity.json", app_identity())
        write("final-selected-registry.json", registry(token))
        from .component_matrix import run as components

        components(selected, token)
        typed("46-final-repeat", selected, stable=True)
        write("final-component-identity.json", app_identity())
        write("final-component-registry.json", registry(token))
