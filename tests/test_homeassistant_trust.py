"""Unchanged original trust program on owned systemctl/proc fixtures only."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.services.homeassistant import trust
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig


def fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **updates: str
) -> tuple[HomeAssistantRuntimeConfig, list[dict[str, Any]]]:
    dropin = tmp_path / "unit.d/50-uv-system-certs.conf"
    dropin.parent.mkdir()
    dropin.write_text(trust.dropin_text())
    proc = tmp_path / "proc/123"
    proc.mkdir(parents=True)
    proc.joinpath("environ").write_bytes(b"UV_SYSTEM_CERTS=1\0OTHER=synthetic-private-value\0")
    state = dict(
        LoadState="loaded",
        ActiveState="active",
        NeedDaemonReload="no",
        DropInPaths=str(dropin),
        EnvironmentFiles="",
        Environment="UV_SYSTEM_CERTS=1 OTHER=synthetic-private-value",
        PassEnvironment="",
        MainPID="123",
    )
    state.update(updates)
    manager = state.pop("manager", "")
    commands = tmp_path / "commands"
    commands.mkdir()
    script = commands / "systemctl"
    script.write_text(
        f"#!{sys.executable}\nimport sys\n"
        f"state={state!r}\nmanager={manager!r}\n"
        "if sys.argv[1]=='show-environment':print(manager)\n"
        "elif sys.argv[1]=='show':print('\\n'.join(k+'='+v for k,v in state.items()))\n"
        "else:raise SystemExit(87)\n"
    )
    script.chmod(0o700)
    env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"])
    results = []

    def actual_probe(command: str, *, name: str) -> str:
        result = subprocess.run(
            ["bash", "-c", command + " --proc " + shlex.quote(str(proc.parent))],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "synthetic-private-value" not in result.stdout + result.stderr
        parsed = json.loads(result.stdout)
        results.append(parsed)
        return result.stdout

    monkeypatch.setattr(trust, "probe", actual_probe)
    return HomeAssistantRuntimeConfig(uv_system_certs_dropin_path=str(dropin)), results


def test_actual_encoded_current_and_running_trust(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, results = fixture(tmp_path, monkeypatch)
    for value in (trust.inspect_trust(cfg, "preflight"), trust.inspect_trust(cfg, "verify")):
        assert value["managed_dropin"] is True
        assert value["running_managed_value"] is True
        assert value["problems"] == []
    assert len(results) == 2


@pytest.mark.parametrize(
    ("field", "value", "problem"),
    [
        ("NeedDaemonReload", "yes", "reload first"),
        ("EnvironmentFiles", "/owned/environment", "EnvironmentFile"),
        ("DropInPaths", "/owned/unknown.conf", "other drop-ins"),
        ("Environment", "SSL_CERT_FILE=synthetic-private-value", "SSL_CERT_FILE"),
        ("manager", "UV_NATIVE_TLS=synthetic-private-value", "service manager"),
        ("ActiveState", "inactive", "not running"),
    ],
)
def test_original_refusals_export_no_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: str, problem: str
) -> None:
    cfg, _ = fixture(tmp_path, monkeypatch, **{field: value})
    with pytest.raises(DeployError, match=problem) as error:
        trust.inspect_trust(cfg, "verify")
    assert "synthetic-private-value" not in str(error.value)


def test_missing_unit_only_allowed_in_explicit_preflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, _ = fixture(tmp_path, monkeypatch, LoadState="not-found", MainPID="0")
    assert trust.inspect_trust(cfg, "preflight", allow_missing_unit=True)["problems"] == []
    with pytest.raises(DeployError, match="not-found"):
        trust.inspect_trust(cfg, "preflight")
    with pytest.raises(DeployError, match="not-found"):
        trust.inspect_trust(cfg, "verify", allow_missing_unit=True)


@pytest.mark.parametrize(
    ("mutation", "problem"),
    [
        ("running-trust-key", "the running service has SSL_CERT_FILE"),
        ("missing-dropin", "without the managed drop-in"),
        ("unreadable-environ", "could not be read"),
        ("changed-dropin", "differs from the managed drop-in"),
    ],
)
def test_running_process_and_dropin_refusals_export_no_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, problem: str
) -> None:
    cfg, results = fixture(tmp_path, monkeypatch)
    environ = tmp_path / "proc/123/environ"
    dropin = Path(cfg.uv_system_certs_dropin_path)
    if mutation == "running-trust-key":
        environ.write_bytes(b"UV_SYSTEM_CERTS=1\0SSL_CERT_FILE=synthetic-private-value\0")
    elif mutation == "missing-dropin":
        dropin.unlink()
    elif mutation == "unreadable-environ":
        environ.unlink()
    else:
        dropin.write_text("synthetic-private-value")
    with pytest.raises(DeployError, match=problem) as error:
        trust.inspect_trust(cfg, "verify")
    assert "synthetic-private-value" not in str(error.value)
    assert len(results) == 1


@pytest.mark.parametrize("loaded", [True, False])
def test_running_status_field_matches_actual_original_shape(monkeypatch: pytest.MonkeyPatch, loaded: bool) -> None:
    value: dict[str, Any] = dict(
        load_state="loaded" if loaded else "not-found", active_state="active", managed_dropin=False, problems=[]
    )
    if not loaded:
        value["running_managed_value"] = False
    monkeypatch.setattr(trust, "probe", lambda *args, **kwargs: json.dumps(value))
    with pytest.raises(DeployError, match="invalid status"):
        trust.inspect_trust(HomeAssistantRuntimeConfig(), "preflight")


def test_template_and_host_program_are_exact_original_sources() -> None:
    root = Path(__file__).parents[1] / "src/ops_deploy/services/homeassistant"
    manifest = json.loads((Path(__file__).parent / "parity/homeassistant_trust_sources.json").read_text())
    for source, digest in manifest["files"].items():
        assert hashlib.sha256((root / source).read_bytes()).hexdigest() == digest
        if os.environ.get("OPS_LIBRARY_PATH"):
            original = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles/homeassistant_deploy" / source
            assert hashlib.sha256(original.read_bytes()).hexdigest() == digest


@pytest.mark.parametrize(
    "value", [{}, [], {"load_state": "loaded", "active_state": "active", "managed_dropin": "true", "problems": []}]
)
def test_malformed_status_refused(monkeypatch: pytest.MonkeyPatch, value: Any) -> None:
    monkeypatch.setattr(trust, "probe", lambda *args, **kwargs: json.dumps(value))
    with pytest.raises(DeployError, match="invalid status"):
        trust.inspect_trust(HomeAssistantRuntimeConfig(), "preflight")
