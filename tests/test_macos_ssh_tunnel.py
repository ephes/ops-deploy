"""Owner-local role resources, explicit port extension and unchanged mutation oracle."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import plistlib
import shlex
import sys
from pathlib import Path
from typing import Any

import jinja2
import pytest
from pydantic import ValidationError

from ops_deploy.services.macos_ssh_tunnel import MacosSshTunnelConfig, deploy_macos_ssh_tunnel
from ops_deploy.services.macos_ssh_tunnel.deploy import host_command, payload
from ops_deploy.testing import run_deploy_fake

ROOT = Path(__file__).resolve().parents[1]


def config(**overrides: Any) -> MacosSshTunnelConfig:
    return MacosSshTunnelConfig(
        owner="operator",
        home=Path("/Users/operator"),
        host="relay.example.test",
        user="operator",
        target="backend.example.test",
        **overrides,
    )


@pytest.mark.parametrize("port", [22, 21222])
def test_default_role_ssh_config_and_explicit_port_are_one_host_block(port: int) -> None:
    cfg = config(ssh_port=port)
    data = payload(cfg)
    template = ROOT / "src/ops_deploy/services/macos_ssh_tunnel/templates/ssh_config.j2"
    context = {"macos_ssh_tunnel_" + name: value for name, value in cfg.model_dump(mode="json").items()}
    role = (
        jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
        .from_string(template.read_text())
        .render(context)
    )
    expected = role if port == 22 else role + f"    Port {port}\n"
    assert cfg.directory is not None
    text = data["contents"][str(cfg.directory / "ssh_config")]
    assert text == expected
    assert text.count("Host ") == 1
    assert "ControlMaster no" in text


def test_plist_and_health_configuration_keep_owner_gui_stopped_model() -> None:
    cfg = config()
    data = payload(cfg)
    parsed = plistlib.loads(data["contents"][str(cfg.plist)].encode())
    assert parsed["Disabled"] is True
    assert parsed["RunAtLoad"] is True
    assert parsed["LimitLoadToSessionType"] == "Aqua"
    assert "UserName" not in parsed
    assert parsed["ProgramArguments"][:2] == ["/usr/bin/ssh", "-F"]
    assert cfg.directory is not None
    health = json.loads(data["contents"][str(cfg.directory / "config.json")])
    assert health["ignore_ssl_errors"] is False
    assert health["local_port"] == 18443
    assert health["ca_file"] == ""


@pytest.mark.parametrize(
    "changes",
    [
        {"ssh_port": 0},
        {"ssh_port": 65536},
        {"local_port": 443},
        {"directory": "/outside/home"},
        {"directory": "/Users/operator/../other"},
        {"label": "invalid/label"},
        {"ignore_ssl_errors": "false"},
        {"relay_home": "/Users/operator"},
    ],
)
def test_invalid_tunnel_configuration_fails_before_connection(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**changes)


def test_exact_unchanged_mutation_and_controller_resource_hashes() -> None:
    base = ROOT / "src/ops_deploy/services/macos_ssh_tunnel/files"
    assert hashlib.sha256((base / "forwarding_identity_host.py").read_bytes()).hexdigest() == (
        "6b41198477b0015984af506625694b2c7ebb2dd3180995497a909c7860a4fb3a"
    )
    assert hashlib.sha256((base / "tunnel_control.py").read_bytes()).hexdigest() == (
        "9a5783aff94d9d99cd1676da6083dcd65daa3f5feb25a8a2fcfad0a22b7d3d43"
    )


def test_actual_role_resource_pair_parity() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("OPS_LIBRARY_PATH unset; paired role oracle parity is run explicitly")
    base = ROOT / "src/ops_deploy/services/macos_ssh_tunnel"
    library = Path(source)
    pairs = {
        "files/forwarding_identity_host.py": "roles/ssh_forwarding_identity/files/manage_forwarding_identity.py",
        "files/tunnel_control.py": "roles/macos_ssh_tunnel/files/tunnel_control.py",
        "templates/ssh_config.j2": "roles/macos_ssh_tunnel/templates/ssh_config.j2",
        "templates/launchagent.plist.j2": "roles/macos_ssh_tunnel/templates/launchagent.plist.j2",
    }
    for target, role in pairs.items():
        assert (base / target).read_bytes() == (library / role).read_bytes()


def test_bundled_original_module_can_load_dataclasses_without_execution() -> None:
    command = shlex.split(host_command(config(), "status"))
    assert command[:3] == ["/usr/bin/python3", "-B", "-c"]
    assert len(command[3].encode()) < 120000
    namespace: dict[str, Any] = {"__name__": "unit_probe_not_main"}
    try:
        exec(compile(command[3], "<owned-unit-loader>", "exec"), namespace)
        assert namespace["ns"]["RegularBinding"].__module__ == "ops_forwarding_identity"
        assert callable(namespace["ns"]["manage"])
        assert callable(namespace["probe_ns"]["probe_identity"])
    finally:
        sys.modules.pop("ops_forwarding_identity", None)
        sys.modules.pop("ops_identity_probe", None)
    data = json.loads(base64.b64decode(command[-1]))
    assert data["manage_identity"] is False
    assert "private_key" not in data


def test_converged_install_stopped_does_not_mutate_or_stage() -> None:
    run = run_deploy_fake(deploy_macos_ssh_tunnel, config(), responses={" status ": ["current"]})
    assert run.succeeded
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert len(run.executed_commands) == 1
    assert " verify " in run.executed_commands[0]


def test_failed_relay_or_apply_stops_before_success_verification() -> None:
    run = run_deploy_fake(
        deploy_macos_ssh_tunnel,
        config(),
        responses={" status ": ["drift"], " apply ": {"success": False, "stderr": "owned relay fault"}},
    )
    assert not run.succeeded
    assert not any(" verify " in command for command in run.executed_commands)
