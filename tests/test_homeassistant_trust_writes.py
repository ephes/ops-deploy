"""Source-bound trust writes/verify ordering on the fake SDK, no systemd calls."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath

import pytest
import yaml
from pyinfra.api import Config
from pyinfra.operations import server

from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig, ServiceState
from ops_deploy.services.homeassistant.trust import (
    dropin_text,
    trust_command,
    verify_running_trust,
    write_managed_dropin,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost


def test_original_dropin_source_contract() -> None:
    fixture = Path(__file__).parent / "parity/homeassistant/trust-write"
    manifest = json.loads((fixture / "source.json").read_text())
    for relative, row in manifest["files"].items():
        assert hashlib.sha256((fixture / row["fixture"]).read_bytes()).hexdigest() == row["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            actual = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles/homeassistant_deploy" / relative
            assert hashlib.sha256(actual.read_bytes()).hexdigest() == row["sha256"]
    original = yaml.safe_load((fixture / "dropin.yml").read_text())
    assert original[0]["ansible.builtin.file"] == {
        "path": "{{ homeassistant_uv_system_certs_dropin_path | dirname }}",
        "state": "directory",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    }
    assert original[1]["ansible.builtin.template"]["mode"] == "0644"
    assert original[1]["register"] == "_ha_uv_certs_dropin"
    assert dropin_text() == (fixture / "dropin.j2").read_text()


@pytest.mark.parametrize("current", [False, True])
def test_managed_dropin_file_result_and_root_modes(current: bool) -> None:
    cfg = HomeAssistantRuntimeConfig()
    directory = str(PurePosixPath(cfg.uv_system_certs_dropin_path).parent)
    responses = {**fakehost.LINUX, **fakehost.directory(directory)}
    if current:
        responses.update(fakehost.file(cfg.uv_system_certs_dropin_path, dropin_text()))
    result = []

    def component() -> None:
        result.append(write_managed_dropin(cfg))

    run = run_deploy_fake(component, responses=responses)
    assert run.succeeded
    assert result[0] is not None
    assert result[0].did_change() is (not current)
    assert len(run.uploads) == int(not current)
    if not current:
        assert run.uploads[0] == (cfg.uv_system_certs_dropin_path, dropin_text().encode())
    assert not any("systemctl" in command for command in run.executed_commands)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("desired", ["started", "stopped", "restarted", "reloaded"])
def test_verify_gate_and_actual_after_boundary_only(enabled: bool, desired: ServiceState) -> None:
    cfg = HomeAssistantRuntimeConfig(uv_system_certs=enabled, service_state=desired)
    report = {
        "load_state": "loaded",
        "active_state": "active",
        "managed_dropin": True,
        "running_managed_value": True,
        "problems": [],
    }
    command = trust_command(cfg, "verify")

    def component() -> None:
        server.shell(name="Owned final handler boundary", commands=["printf boundary"])
        verify_running_trust(cfg)

    run = run_deploy_fake(
        component, responses={**fakehost.LINUX, command: json.dumps(report)}, pyinfra_config=Config(DIFF=True)
    )
    assert run.succeeded
    probes = [event for event in run.events if event.value == command]
    assert len(probes) == int(enabled and desired == "started")
    assert all(event.phase == "execute" for event in probes)
    if probes:
        boundary = next(
            i for i, event in enumerate(run.events) if event.kind == "shell" and event.value == "printf boundary"
        )
        assert run.events.index(probes[0]) > boundary
    assert all(op.read_only for op in run.ops if "Verify running" in op.name)


def test_actual_failed_verify_stays_failed_no_repair() -> None:
    cfg = HomeAssistantRuntimeConfig()
    command = trust_command(cfg, "verify")
    report = {
        "load_state": "loaded",
        "active_state": "active",
        "managed_dropin": True,
        "running_managed_value": False,
        "problems": ["UV_SYSTEM_CERTS is not present in the running process"],
    }
    run = run_deploy_fake(verify_running_trust, cfg, responses={**fakehost.LINUX, command: json.dumps(report)})
    assert not run.succeeded
    assert str(run.error) == "No hosts remaining!"
    assert [op.succeeded for op in run.ops] == [False]
    assert not run.uploads
    assert not any("restart " in text for text in run.executed_commands)


def test_disabled_write_does_not_touch_existing_unmanaged_dropin() -> None:
    run = run_deploy_fake(write_managed_dropin, HomeAssistantRuntimeConfig(uv_system_certs=False))
    assert run.succeeded
    assert not run.events
    assert not run.ops


def test_directory_only_change_keeps_file_notification_false() -> None:
    cfg = HomeAssistantRuntimeConfig()
    directory = str(PurePosixPath(cfg.uv_system_certs_dropin_path).parent)
    result = []
    run = run_deploy_fake(
        lambda: result.append(write_managed_dropin(cfg)),
        responses={
            **fakehost.LINUX,
            **fakehost.directory(directory, mode="drwx------"),
            **fakehost.file(cfg.uv_system_certs_dropin_path, dropin_text()),
        },
    )
    assert run.succeeded
    assert len(run.mutating_changed_ops) == 1
    assert result[0] is not None
    assert not result[0].did_change()
    assert not run.uploads


@pytest.mark.parametrize("response", [{"success": False, "stderr": ["owned synthetic private detail"]}, "invalid"])
def test_verify_transport_or_schema_failure_stays_failed_without_gated_retry(
    response: object, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = HomeAssistantRuntimeConfig()
    command = trust_command(cfg, "verify")
    run = run_deploy_fake(verify_running_trust, cfg, responses={**fakehost.LINUX, command: response})
    assert not run.succeeded
    assert str(run.error) == "No hosts remaining!"
    assert [op.succeeded for op in run.ops] == [False]
    calls = [event for event in run.events if event.value == command]
    assert len(calls) == 1
    assert calls[0].phase == "execute"
    assert calls[0].kind == "shell"
    assert "running the step it gates" not in caplog.text
    assert "owned synthetic private detail" not in caplog.text
    assert not run.uploads
