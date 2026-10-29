"""Normal-role composition and actual SDK handler boundaries; no inventory."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.services.homeassistant.deploy_config import HomeAssistantDeployConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

module = importlib.import_module("ops_deploy.services.homeassistant.deploy")
TOKEN = "owned-deploy-token-with-at-least-32-characters"


def test_original_defaults_and_dependent_inputs() -> None:
    fixture = Path(__file__).parent / "parity/homeassistant/deployment/defaults.yml"
    original = yaml.safe_load(fixture.read_text())
    cfg = HomeAssistantDeployConfig()
    assert cfg.additional_packages == tuple(original["homeassistant_additional_packages"])
    assert cfg.include_files == tuple(original["homeassistant_include_files"])
    assert cfg.runtime.python_version == original["homeassistant_python_version"]
    assert cfg.runtime.package_spec == original["homeassistant_package_spec"]
    assert cfg.custom.enabled == original["homeassistant_custom_conversation_enabled"]
    assert cfg.assist.definitions() == original["homeassistant_assist_pipelines"]
    changed = HomeAssistantDeployConfig(values={"app_port": 12345}, runtime={"matter_server_port": 6789})
    assert changed.api.url.get_secret_value() == "http://localhost:12345"
    assert changed.ingress.app_port == 12345
    assert changed.matter_integration_url.get_secret_value() == "ws://localhost:6789/ws"
    explicit = HomeAssistantDeployConfig(values={"app_port": 12345}, api={"url": "https://owned/path"})
    assert explicit.api.url.get_secret_value() == "https://owned/path"


@pytest.mark.parametrize(
    "value",
    [
        {"assist": {"pipelines": "not-json"}},
        {"area_updates": "{}"},
        {"manage_wyoming_integration": True, "api": {"token": TOKEN}},
        {"builtin_enabled": True},
        {"assist": {"manage_stt": True}, "api": {"token": TOKEN}},
        {"assist": {"pipelines": '[{"name":"Room"}]'}, "api": {"token": TOKEN}},
        {"assist": {"pipelines": '[{"name":"Room","language":"en"}]'}, "api": {"token": TOKEN}},
    ],
)
def test_original_selected_input_failures(value: dict[str, Any]) -> None:
    with pytest.raises((ValueError, ValidationError)):
        HomeAssistantDeployConfig(**value)


def selected(
    *, custom: bool = False, builtin: bool = False, matter: bool = False, pipelines: bool = False
) -> HomeAssistantDeployConfig:
    return HomeAssistantDeployConfig(
        runtime={"manage_matter_server": matter, "package_spec": "homeassistant==2026.10.2"},
        api={"token": TOKEN},
        builtin_enabled=builtin,
        builtin={"base_url": "http://owned", "api_key": "owned", "model": "owned", "instructions": "owned"},
        custom={"enabled": custom, "base_url": "http://owned", "api_key": "owned", "model": "owned"},
        manage_matter_integration=True,
        manage_otbr_integration=True,
        manage_wyoming_integration=True,
        wyoming_host="owned",
        area_updates='[{"name":"Room"}]',
        assist={
            "pipelines": '[{"name":"Room","language":"en","conversation_engine":"auto:llama_cpp"}]'
            if pipelines
            else "[]"
        },
    )


def stub_composition(monkeypatch: pytest.MonkeyPatch, *, count: int = 0, uv: bool = True) -> list[str]:
    trace: list[str] = []
    meta = SimpleNamespace(did_change=lambda: True)
    changes = SimpleNamespace(
        homeassistant_changed=lambda: True, matter_changed=lambda: True, reload_required=lambda: True
    )

    def call(name: str, result: Any = None) -> Any:
        def run(*args: Any, **kwargs: Any) -> Any:
            trace.append(name)
            return result

        return run

    monkeypatch.setattr(module, "require_linux", call("linux"))
    monkeypatch.setattr(module, "_selection", lambda cfg, kind: {"exists": uv} if kind == "uv" else {"count": count})
    monkeypatch.setattr(
        module,
        "security_preflight",
        lambda cfg: trace.append("environment-floor" if cfg.python_security_floor_enabled else "store-floor"),
    )
    monkeypatch.setattr(module, "inspect_trust", call("unit-preflight"))
    monkeypatch.setattr(module.apt, "packages", call("packages"))
    monkeypatch.setattr(module, "configure_layout", call("layout", meta))
    monkeypatch.setattr(module, "install_uv", call("uv"))
    monkeypatch.setattr(module, "write_constraints", call("constraints"))
    monkeypatch.setattr(module, "install_builtin_helper", call("builtin-helper", meta))
    monkeypatch.setattr(
        module, "inspect_legacy_conversation", call("legacy-observe", SimpleNamespace(rebuild=True, retire=True))
    )
    monkeypatch.setattr(module, "run_builtin_conversation", lambda **kw: trace.append("builtin-" + kw["action"]))
    monkeypatch.setattr(module, "remove_legacy_component", call("legacy-remove"))
    monkeypatch.setattr(module, "configure_python_runtime", call("python", changes))
    monkeypatch.setattr(module, "verify_security", call("verify-floor"))
    monkeypatch.setattr(module, "configure_files", call("configuration", changes))
    monkeypatch.setattr(module, "application_check", lambda cfg, argv, label, **kw: trace.append(label))
    monkeypatch.setattr(module, "write_units", call("units", changes))
    monkeypatch.setattr(module, "write_managed_dropin", call("dropin", meta))
    monkeypatch.setattr(module, "write_ingress", call("ingress", meta))
    monkeypatch.setattr(module, "ensure_service_states", call("service-states"))
    monkeypatch.setattr(module, "manage_area_registry", call("areas"))
    monkeypatch.setattr(
        module, "integrate", lambda cfg, api, selection, ready: trace.append("flow-" + selection.domain)
    )
    monkeypatch.setattr(module, "install_custom_component", call("custom-installer", changes))
    monkeypatch.setattr(module, "run_custom_conversation", call("custom-flow"))
    monkeypatch.setattr(module, "flush_service_handlers", call("service-flush"))
    monkeypatch.setattr(module, "run_udev_handlers", call("udev-flush"))
    monkeypatch.setattr(module, "_traefik_notice", call("ingress-notice", meta))
    monkeypatch.setattr(module, "mark_read_only", lambda meta: meta)
    monkeypatch.setattr(module, "reset_api_readiness", call("reset-ready"))
    monkeypatch.setattr(module, "ensure_api_readiness", call("ready"))
    monkeypatch.setattr(module, "manage_pipelines", lambda *a, **kw: trace.append("pipelines-" + a[3]))
    monkeypatch.setattr(module, "verify_running_trust", call("verify-running"))
    return trace


def test_original_full_builtin_order_and_consumed_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    trace = stub_composition(monkeypatch)
    module.deploy_homeassistant.__wrapped__(cfg=selected(builtin=True, matter=True, pipelines=True))
    assert trace == [
        "linux",
        "environment-floor",
        "unit-preflight",
        "store-floor",
        "packages",
        "layout",
        "uv",
        "constraints",
        "builtin-helper",
        "legacy-observe",
        "ready",
        "builtin-retire",
        "legacy-remove",
        "python",
        "verify-floor",
        "configuration",
        "Validate upgraded Home Assistant configuration",
        "units",
        "dropin",
        "ingress",
        "service-states",
        "areas",
        "flow-matter",
        "flow-otbr",
        "flow-wyoming",
        "service-flush",
        "udev-flush",
        "ingress-notice",
        "reset-ready",
        "ready",
        "builtin-helper",
        "builtin-ensure",
        "Verify LiteLLM is absent",
        "pipelines-list",
        "Validate HA Matter import",
        "Validate Matter server imports",
        "verify-running",
    ]


def test_custom_then_disabled_builtin_nested_flush_does_not_replay_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    trace = stub_composition(monkeypatch)
    module.deploy_homeassistant.__wrapped__(cfg=selected(custom=True, pipelines=True, matter=True))
    assert trace[trace.index("custom-installer") :] == [
        "custom-installer",
        "service-flush",
        "udev-flush",
        "ingress-notice",
        "reset-ready",
        "ready",
        "Verify Custom Conversation aiohttp",
        "custom-flow",
        "reset-ready",
        "ready",
        "builtin-helper",
        "builtin-disable",
        "pipelines-list",
        "Validate HA Matter import",
        "Validate Matter server imports",
        "verify-running",
    ]


@pytest.mark.parametrize("count", [0, 1, 2])
def test_custom_disabled_original_existing_domain_branch(monkeypatch: pytest.MonkeyPatch, count: int) -> None:
    trace = stub_composition(monkeypatch, count=count)
    if count > 1:
        with pytest.raises(module.DeployError, match="at most one"):
            module.deploy_homeassistant.__wrapped__(cfg=selected())
        assert "custom-flow" not in trace
    else:
        module.deploy_homeassistant.__wrapped__(cfg=selected())
        assert ("custom-flow" in trace) == bool(count)
    assert "custom-installer" not in trace
    assert not any(t.startswith("builtin-") for t in trace)


def test_missing_uv_fails_before_registering_any_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    trace = stub_composition(monkeypatch, uv=False)
    with pytest.raises(module.DeployError, match="Install uv before"):
        module.deploy_homeassistant.__wrapped__(cfg=HomeAssistantDeployConfig())
    assert trace == ["linux"]


def test_actual_named_selection_never_exports_ids_or_other_body(tmp_path: Path) -> None:
    program = files("ops_deploy.services.homeassistant").joinpath("files/deployment_observe.py")
    target = tmp_path / "entries"
    payload = {"kind": "custom", "path": str(target)}
    for expected, body in [
        (0, None),
        (
            1,
            {
                "data": {
                    "entries": [
                        {"domain": "custom_conversation", "entry_id": "private-id"},
                        {"domain": "unrelated", "data": {"credential": "private-body"}},
                    ]
                }
            },
        ),
        (2, {"data": {"entries": [{"domain": "custom_conversation"}, {"domain": "custom_conversation"}]}}),
    ]:
        if body is not None:
            target.write_text(json.dumps(body))
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(program)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=True,
        )
        assert json.loads(result.stdout) == {"success": True, "count": expected}
        assert "private-" not in result.stdout + result.stderr
    before = target.read_bytes()
    metadata = target.stat()
    subprocess.run(
        [sys.executable, "-I", "-B", str(program)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    assert target.read_bytes() == before
    assert target.stat().st_mtime_ns == metadata.st_mtime_ns
    target.write_text("malformed")
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(program)], input=json.dumps(payload), text=True, capture_output=True
    )
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"success": False}


def test_real_sdk_multiple_flushes_consume_only_new_notifications(monkeypatch: pytest.MonkeyPatch) -> None:
    from collections.abc import Generator

    from pyinfra.api import Config, FunctionCommand, Inventory, State, operation
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    events: list[tuple[str, str]] = []

    def event(state: Any, host: Any, label: str) -> None:
        events.append((host.name, label))

    @operation()
    def op(label: str) -> Generator[FunctionCommand, None, None]:
        yield FunctionCommand(event, (label,), {})

    def flush(cfg: Any, **kw: Any) -> None:
        for label, key in [
            ("reload", "reload_required"),
            ("ha", "homeassistant_required"),
            ("matter", "matter_required"),
        ]:
            op(label=label, _if=kw[key])

    monkeypatch.setattr(module, "flush_service_handlers", flush)
    state = State(Inventory((["@fake/a", "@fake/b"], {})), Config())

    def deploy() -> None:
        pending = module._PendingHandlers()
        first = op(label="first")
        pending.homeassistant.append(first.did_change)
        pending.flush(HomeAssistantRuntimeConfig())
        op(label="between")
        pending.flush(HomeAssistantRuntimeConfig())
        second = op(label="second")
        pending.matter.append(second.did_change)
        pending.flush(HomeAssistantRuntimeConfig())
        pending.flush(HomeAssistantRuntimeConfig())

    try:
        connect_all(state)
        add_deploy(state, deploy)
        assert events == []
        run_ops(state)
        assert not state.failed_hosts
        for name in ["@fake/a", "@fake/b"]:
            assert [label for target, label in events if target == name] == [
                "first",
                "ha",
                "between",
                "second",
                "matter",
            ]
    finally:
        disconnect_all(state)


def test_original_composition_fixtures_are_hash_bound() -> None:
    fixture = Path(__file__).parent / "parity/homeassistant/deployment"
    manifest = json.loads((fixture / "source.json").read_text())
    for name, entry in manifest["files"].items():
        body = (fixture / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
    original = yaml.safe_load((fixture / "main.yml").read_text())
    imports = [task.get("ansible.builtin.import_tasks") for task in original]
    assert imports.index("llama_cpp_prepare.yml") < imports.index("python.yml")
    assert imports.index("custom_conversation_component.yml") < imports.index("llama_cpp_integration.yml")
    nested = yaml.safe_load((fixture / "builtin.yml").read_text())
    assert nested[0]["ansible.builtin.meta"] == "flush_handlers"
    assert nested[1]["ansible.builtin.set_fact"]["_ha_api_ready_once"] is False


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="paired original collection not configured")
def test_original_composition_fixtures_match_actual_paired_source() -> None:
    root = Path(os.environ["OPS_LIBRARY_PATH"])
    fixture = Path(__file__).parent / "parity/homeassistant/deployment"
    for name, entry in json.loads((fixture / "source.json").read_text())["files"].items():
        assert (fixture / name).read_bytes() == (root / entry["source"]).read_bytes()


@pytest.mark.parametrize("side", ["api", "ingress"])
@pytest.mark.parametrize("object_input", [False, True])
def test_default_route_fact_derives_both_components(side: str, object_input: bool) -> None:
    from ops_deploy.services.homeassistant.ingress import HomeAssistantIngressConfig
    from ops_deploy.services.homeassistant.integration_flows import HomeAssistantApiConfig

    cls = HomeAssistantApiConfig if side == "api" else HomeAssistantIngressConfig
    supplied = cls(default_ipv4="192.0.2.19") if object_input else {"default_ipv4": "192.0.2.19"}
    cfg = HomeAssistantDeployConfig(**{side: supplied})
    assert cfg.api.default_ipv4 == cfg.ingress.default_ipv4 == "192.0.2.19"
    explicit = HomeAssistantDeployConfig(api={"default_ipv4": "192.0.2.20"}, ingress={"default_ipv4": None})
    assert explicit.api.default_ipv4 == "192.0.2.20"
    assert explicit.ingress.default_ipv4 is None


@pytest.mark.parametrize("error_type", [TimeoutError, OSError, __import__("paramiko").SSHException])
def test_selection_transport_error_is_sanitized(monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise error_type("unexported-transport-detail")

    monkeypatch.setattr(module, "host", SimpleNamespace(run_shell_command=fail))
    with pytest.raises(module.DeployError, match="prerequisite/selection inspection failed") as caught:
        module._selection(HomeAssistantRuntimeConfig(), "uv")
    assert "unexported" not in str(caught.value)


def test_root_exports_exact_reviewed_composition() -> None:
    from ops_deploy.services.homeassistant import HomeAssistantDeployConfig as ExportedConfig
    from ops_deploy.services.homeassistant import deploy_homeassistant

    assert ExportedConfig is HomeAssistantDeployConfig
    assert deploy_homeassistant is module.deploy_homeassistant


@pytest.mark.parametrize("names", [(), ("scenes.yaml",), ("scripts.yaml", "automations.yaml")])
def test_original_include_selection_reaches_full_deployment(
    names: tuple[str, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    stub_composition(monkeypatch)
    observed: list[tuple[str, ...]] = []

    def configure(*args: Any, **kwargs: Any) -> SimpleNamespace:
        observed.append(kwargs["include_files"])
        return SimpleNamespace(homeassistant_changed=lambda: False)

    monkeypatch.setattr(module, "configure_files", configure)
    cfg = HomeAssistantDeployConfig(include_files=names)
    module.deploy_homeassistant._inner(cfg=cfg)
    assert observed == [names]


@pytest.mark.parametrize(
    ("selector", "changed", "enabled"),
    [
        ("restart matter server", True, True),
        ("owned missing handler", True, True),
        ("owned missing handler", False, True),
        ("owned missing handler", True, False),
    ],
)
def test_full_deploy_selected_notification_wiring_and_failure_boundary(
    monkeypatch: pytest.MonkeyPatch, selector: str, changed: bool, enabled: bool
) -> None:
    from pyinfra.operations import server

    from ops_deploy.services.homeassistant.services import flush_service_handlers
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    stub_composition(monkeypatch)
    quiet = SimpleNamespace(
        homeassistant_changed=lambda: False, matter_changed=lambda: False, reload_required=lambda: False
    )
    for name in ("configure_python_runtime", "configure_files", "write_units"):
        monkeypatch.setattr(module, name, lambda *args, **kw: quiet)
    for name in ("configure_layout", "write_managed_dropin"):
        monkeypatch.setattr(module, name, lambda *args, **kw: None)
    monkeypatch.setattr(module, "flush_service_handlers", flush_service_handlers)
    monkeypatch.setattr(
        module,
        "write_ingress",
        lambda cfg, **kw: (
            server.shell(name="Owned route result", commands=["printf route"], _if=lambda: changed)
            if cfg.enabled
            else None
        ),
    )
    monkeypatch.setattr(
        module,
        "ensure_service_states",
        lambda cfg: server.shell(name="Owned service-state task", commands=["printf service-state"]),
    )
    cfg = HomeAssistantDeployConfig(
        runtime={"manage_matter_server": False}, ingress={"reload_handler": selector, "enabled": enabled}
    )
    run = run_deploy_fake(
        lambda: module.deploy_homeassistant(cfg=cfg),
        responses={**fakehost.LINUX, **fakehost.service("matter-server.service")},
    )
    missing = selector == "owned missing handler" and changed and enabled
    assert run.succeeded is not missing, run.error
    commands = "\n".join(run.executed_commands)
    assert ("printf service-state" in commands) is not missing
    if selector == "restart matter server":
        assert commands.count("restart matter-server.service") == 1
        assert commands.index("printf service-state") < commands.index("restart matter-server.service")
