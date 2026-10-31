"""Original maintenance ordering and real owned HTTP requests; no service actions."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import SecretStr
from pyinfra.api import Config, DeployError
from pyinfra.operations import server, systemd

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.services.homeassistant import trust_maintenance as maintenance
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake


def test_bound_original_maintenance_task_sequence() -> None:
    root = Path(__file__).parent / "parity/homeassistant/trust-maintenance"
    receipt = json.loads((root / "source.json").read_text())
    body = (root / "maintenance.yml").read_bytes()
    assert hashlib.sha256(body).hexdigest() == receipt["sha256"]
    if os.environ.get("OPS_LIBRARY_PATH"):
        assert body == (Path(os.environ["OPS_LIBRARY_PATH"]) / receipt["path"]).read_bytes()
    rows = yaml.safe_load(body)
    assert rows[1]["vars"] == {"_ha_uv_certs_mode": "preflight"}
    assert rows[4]["ansible.builtin.systemd"] == {
        "name": "{{ homeassistant_service_name }}",
        "state": "restarted",
        "daemon_reload": True,
    }
    assert rows[4]["when"] == "_ha_uv_certs_dropin is changed"
    assert rows[5]["ansible.builtin.uri"] == {
        "url": "{{ homeassistant_uv_system_certs_health_url }}",
        "status_code": 200,
        "validate_certs": False,
    }
    assert rows[6]["vars"] == {"_ha_uv_certs_mode": "verify"}
    defaults = yaml.safe_load((Path(__file__).parent / "parity/homeassistant/defaults.yml").read_text())
    cfg = maintenance.HomeAssistantTrustMaintenanceConfig()
    assert cfg.health_retries == defaults["homeassistant_uv_system_certs_health_retries"]
    assert cfg.health_delay == defaults["homeassistant_uv_system_certs_health_delay"]


@pytest.mark.parametrize("current", [False, True])
def test_changed_only_restart_original_order_and_unconditional_final_checks(
    current: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace: list[str] = []
    observed: list[dict[str, Any]] = []
    monkeypatch.setattr(maintenance, "require_linux", lambda label: trace.append("linux"))
    monkeypatch.setattr(maintenance, "inspect_trust", lambda cfg, mode: trace.append(mode))

    def store(cfg: HomeAssistantRuntimeConfig) -> None:
        assert not cfg.python_security_floor_enabled
        assert cfg.uv_system_certs
        trace.append("store")

    def write(cfg: HomeAssistantRuntimeConfig) -> Any:
        trace.append("write")
        return server.shell(commands=["owned-dropin"], _if=lambda: not current)

    def restart(**kwargs: Any) -> Any:
        observed.append(kwargs)
        return server.shell(commands=["owned-restart"], _if=kwargs["_if"])

    def verify(cfg: HomeAssistantRuntimeConfig) -> Any:
        assert cfg.service_state == "started"
        return mark_read_only(server.shell(commands=["owned-verify"]))

    monkeypatch.setattr(maintenance, "security_preflight", store)
    monkeypatch.setattr(maintenance, "write_managed_dropin", write)
    monkeypatch.setattr(systemd, "service", restart)
    monkeypatch.setattr(
        maintenance, "check_maintenance_health", lambda cfg: mark_read_only(server.shell(commands=["owned-health"]))
    )
    monkeypatch.setattr(maintenance, "verify_running_trust", verify)
    cfg = maintenance.HomeAssistantTrustMaintenanceConfig(runtime={"service_state": "stopped"})
    result = run_deploy_fake(maintenance.maintain_homeassistant_trust, cfg)
    assert result.succeeded
    assert trace == ["linux", "preflight", "store", "write"]
    assert result.executed_commands == ([] if current else ["owned-dropin", "owned-restart"]) + [
        "owned-health",
        "owned-verify",
    ]
    assert observed[0]["daemon_reload"] is True
    assert observed[0]["restarted"] is True
    assert "enabled" not in observed[0]


def test_disabled_feature_refuses_before_any_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maintenance, "require_linux", lambda label: pytest.fail("must assert first"))
    cfg = maintenance.HomeAssistantTrustMaintenanceConfig(runtime={"uv_system_certs": False})
    result = run_deploy_fake(maintenance.maintain_homeassistant_trust, cfg)
    assert not result.succeeded
    assert not result.events
    assert not result.ops


@pytest.mark.parametrize("failure", ["unit", "store"])
def test_failed_admission_has_no_write_or_restart(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maintenance, "require_linux", lambda label: None)

    def check(label: str) -> None:
        if label == failure:
            raise DeployError("owned admission failure")

    monkeypatch.setattr(maintenance, "inspect_trust", lambda cfg, mode: check("unit"))
    monkeypatch.setattr(maintenance, "security_preflight", lambda cfg: check("store"))
    monkeypatch.setattr(maintenance, "write_managed_dropin", lambda cfg: pytest.fail("admission must stop writes"))
    result = run_deploy_fake(
        maintenance.maintain_homeassistant_trust, maintenance.HomeAssistantTrustMaintenanceConfig()
    )
    assert not result.succeeded
    assert not result.ops


@pytest.mark.parametrize("shell", ["bash", "fish"])
@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([200], True),
        ([503, 200], True),
        ([503, 503], False),
        pytest.param(["malformed", 200], True, id="malformed-retry"),
    ],
)
def test_real_owned_health_helper_retries_without_exporting_bodies(
    shell: str, statuses: list[int | str], expected: bool, tmp_path: Path
) -> None:
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            response = statuses[min(len(requests) - 1, len(statuses) - 1)]
            if response == "malformed":
                self.wfile.write(b"owned malformed status\r\n\r\n")
                self.close_connection = True
                return
            assert isinstance(response, int)
            self.send_response(response)
            self.end_headers()
            self.wfile.write(b"owned-private-response-body")

        def log_message(self, *args: Any) -> None:
            pass

    http = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    runtime = HomeAssistantRuntimeConfig().model_copy(
        update={"security": HomeAssistantRuntimeConfig().security.model_copy(update={"system_python": sys.executable})}
    )
    payload = {
        "url": f"http://127.0.0.1:{http.server_port}/manifest.json",
        "retries": 1,
        "delay": 0,
        "deadline_seconds": 5,
    }
    try:
        result = subprocess.run(
            [shell, "-c", maintenance.health_command(runtime)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "NETRC": str(tmp_path / "missing-owned-netrc")},
        )
    finally:
        http.shutdown()
        thread.join(timeout=5)
        http.server_close()
    assert (result.returncode == 0) is expected
    assert json.loads(result.stdout) == {"success": expected, "attempts": len(requests)}
    assert requests == ["/manifest.json"] * (1 if statuses[0] == 200 else 2)
    assert "owned-private-response-body" not in result.stdout + result.stderr


def test_actual_sdk_health_callback_is_readonly_and_execution_only() -> None:
    cfg = maintenance.HomeAssistantTrustMaintenanceConfig(health_url=SecretStr("http://owned/manifest.json"))
    command = maintenance.health_command(cfg.runtime)
    result = run_deploy_fake(
        maintenance.check_maintenance_health,
        cfg,
        responses={command: json.dumps({"success": True, "attempts": 1})},
        pyinfra_config=Config(DIFF=True),
    )
    assert result.succeeded
    assert len(result.ops) == 1
    assert result.ops[0].read_only
    assert all(event.phase == "execute" for event in result.events if event.value == command)
    assert result.executed_commands == [command]


@pytest.mark.parametrize("response", ["not-json", "[]", '{"success":true,"attempts":true}'])
def test_malformed_health_result_fails_without_hiding_failure(response: str) -> None:
    cfg = maintenance.HomeAssistantTrustMaintenanceConfig()
    command = maintenance.health_command(cfg.runtime)
    result = run_deploy_fake(maintenance.check_maintenance_health, cfg, responses={command: response})
    assert not result.succeeded
    assert len(result.ops) == 1
    assert result.ops[0].succeeded is False


def test_failed_health_leaves_later_running_check_unexecuted() -> None:
    cfg = maintenance.HomeAssistantTrustMaintenanceConfig()
    command = maintenance.health_command(cfg.runtime)

    def deploy() -> None:
        maintenance.check_maintenance_health(cfg)
        server.shell(commands=["must-not-run"])

    result = run_deploy_fake(
        deploy, responses={command: {"success": False, "stdout": [json.dumps({"success": False, "attempts": 2})]}}
    )
    assert not result.succeeded
    assert result.executed_commands == [command]


def test_total_deadline_never_becomes_another_retry() -> None:
    scope = runpy.run_path(str(files("ops_deploy.services.homeassistant").joinpath("files/maintenance_health.py")))
    report = {"success": False, "attempts": 0}

    def transport(*args: Any) -> Any:
        raise scope["HealthDeadline"]()

    with pytest.raises(scope["HealthDeadline"]):
        scope["run"]({"url": "http://owned", "retries": 3, "delay": 0}, transport, report)
    assert report == {"success": False, "attempts": 1}
