"""Native detector configuration, secret transport, retention and failure order."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
import plistlib
import shlex
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from ops_deploy.services.llama_server import LlamaServerConfig, deploy_llama_server
from ops_deploy.services.llama_server.deploy import host_command, payload
from ops_deploy.testing import run_deploy_fake

ROOT = Path(__file__).resolve().parents[1]
KEY_VALUE = "x" * 48


def host_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "llama_server_host_test", ROOT / "src/ops_deploy/services/llama_server/files/llama_server_host.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def cfg(tmp_path: Path) -> LlamaServerConfig:
    wrapper = tmp_path / "controller-wrapper.sh"
    pin = LlamaServerConfig(enabled=False).model_sha256
    wrapper.write_text(f'GGUF_SHA256="{pin}"\n# --api-key-file --no-slots --cache-ram 0\n')
    return LlamaServerConfig(user="owner", brew_user="owner", wrapper_source=wrapper)


def test_disabled_api_needs_no_controller_wrapper_or_secret() -> None:
    cfg = LlamaServerConfig(enabled=False)
    assert cfg.required_secret_keys == ()
    assert "contents" not in payload(cfg, {})


@pytest.mark.parametrize("value", ["", "#ignored" * 8, " padded" * 8, "line\n" * 10])
def test_invalid_api_key_rejected_before_host(cfg: LlamaServerConfig, value: str) -> None:
    with pytest.raises(ValueError, match="key"):
        payload(cfg, {"api_key": value})


@pytest.mark.parametrize(
    "changes",
    [
        {"bind_host": "0.0.0.0"},
        {"bind_host": "192.168.1.2"},
        {"bind_host": "::1"},
        {"model_file": "../model.gguf"},
        {"log_dir": "/"},
        {"port": 65536},
        {"model_url": "https://user:password@example.test/file.gguf"},
    ],
)
def test_unsafe_config_rejected(cfg: LlamaServerConfig, changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        LlamaServerConfig.model_validate({**cfg.model_dump(), **changes})


def test_key_only_reaches_secret_stdin(cfg: LlamaServerConfig) -> None:
    data = payload(cfg, {"api_key": KEY_VALUE})
    for action in ["status", "apply", "verify"]:
        command = host_command(data, action)
        public = json.loads(base64.b64decode(shlex.split(command)[-1]))
        assert KEY_VALUE not in command
        assert KEY_VALUE not in json.dumps(public)
        assert "contents" not in public
    assert data["contents"][str(cfg.api_key_path)] == KEY_VALUE + "\n"


def test_plist_preserves_native_owner_domain_and_pin(cfg: LlamaServerConfig) -> None:
    data = payload(cfg, {"api_key": KEY_VALUE})
    parsed = plistlib.loads(data["contents"][str(cfg.launchd_plist_path)].encode())
    assert parsed["UserName"] == "owner"
    assert parsed["GroupName"] == "staff"
    assert parsed["ProgramArguments"] == ["/bin/bash", "/opt/llama-server/detector-server.sh"]
    assert parsed["EnvironmentVariables"]["DELVE_DETECTOR_BUILD"] == cfg.build


def test_role_template_source_parity() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("OPS_LIBRARY_PATH unset; actual role source parity is an explicit paired check")
    assert (ROOT / "src/ops_deploy/services/llama_server/templates/llama-server.launchd.plist.j2").read_bytes() == (
        Path(source) / "roles/llama_server_deploy/templates/llama-server.launchd.plist.j2"
    ).read_bytes()


def test_current_deployment_has_no_upload_or_mutation(cfg: LlamaServerConfig) -> None:
    run = run_deploy_fake(deploy_llama_server, cfg, {"api_key": KEY_VALUE}, responses={" status ": ["current"]})
    assert run.succeeded
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert len(run.executed_commands) == 1
    assert " verify " in run.executed_commands[0]


def test_failure_stops_before_readiness(cfg: LlamaServerConfig) -> None:
    run = run_deploy_fake(
        deploy_llama_server,
        cfg,
        {"api_key": KEY_VALUE},
        responses={" status ": ["drift"], " apply ": {"success": False, "stderr": "owned fixture fault"}},
    )
    assert not run.succeeded
    assert not any(" verify " in command for command in run.executed_commands)


def test_existing_pinned_model_is_neither_opened_nor_downloaded(tmp_path: Path) -> None:
    module = host_script()
    model = tmp_path / "fixture.gguf"
    model.write_bytes(b"owned synthetic model, not read by status")
    wrapper = tmp_path / "wrapper.sh"
    wrapper.write_text('GGUF_SHA256="declared-pin"')
    with patch.object(module.urllib.request, "urlopen") as download:
        assert (
            module.stage_model({"model_path": str(model), "wrapper_path": str(wrapper), "model_sha256": "declared-pin"})
            is None
        )
    download.assert_not_called()


def test_bad_fresh_download_is_removed_without_replacing_existing_model(tmp_path: Path) -> None:
    module = host_script()
    model = tmp_path / "fixture.gguf"
    model.write_bytes(b"retained prior fixture model")
    before = model.stat()
    cfg = {
        "model_path": str(model),
        "model_dir": str(tmp_path),
        "wrapper_path": str(tmp_path / "missing-wrapper"),
        "model_sha256": "0" * 64,
        "model_url": "https://fixture.example/model.gguf",
        "wheel": os.getgid(),
    }
    with (
        patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(b"bad owned fixture download")),
        patch.object(module.os, "fchown"),
        pytest.raises(RuntimeError, match="checksum"),
    ):
        module.stage_model(cfg)
    assert model.read_bytes() == b"retained prior fixture model"
    assert model.stat().st_ino == before.st_ino
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fixture.gguf"]


def test_unload_waits_for_exact_job_to_leave() -> None:
    module = host_script()
    with (
        patch.object(module, "run") as run,
        patch.object(module, "job", side_effect=[(True, False), (False, False)]),
        patch.object(module.time, "sleep") as sleep,
    ):
        module.unload({"launchd_label": "org.example.owned-detector"})
    run.assert_called_once_with(["/bin/launchctl", "bootout", "system/org.example.owned-detector"], check=False)
    sleep.assert_called_once_with(0.1)
