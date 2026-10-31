"""Real encoded helper execution against owned synthetic executables, not HA."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.services.homeassistant import python_observation as observation
from ops_deploy.services.homeassistant.python_state import EnvironmentState, homeassistant_decision, matter_decision
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig


def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, matter: bool = False) -> tuple[Path, Path]:
    bin_path = tmp_path / "venv/bin"
    bin_path.mkdir(parents=True)
    log = tmp_path / "calls.jsonl"
    script = f"""#!{sys.executable}
import json,sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with Path({str(log)!r}).open('a') as stream:stream.write(json.dumps([name,*args])+'\\n')
if name=='hass':print('2026.10.2');sys.exit(0)
if args==['--version']:print('Python 3.14.8');sys.exit(0)
if args==['-m','pip','--version']:print('pip synthetic');sys.exit(0)
if args==['-m','pip','show','python-matter-server']:
 print('Version: 8.1.2');sys.exit({0 if matter else 1})
if args==['-c','import chip.exceptions']:sys.exit(0)
sys.exit(3)
"""
    for name in ("python", "hass", "matter-server"):
        path = bin_path / name
        path.write_text(script)
        path.chmod(0o755)
    stub = tmp_path / "controller-bin"
    stub.mkdir()
    runuser = stub / "runuser"
    runuser.write_text(
        f"#!{sys.executable}\nimport os,sys\n"
        "assert sys.argv[1:4]==['-u','homeassistant','--']\nos.execvp(sys.argv[4],sys.argv[4:])\n"
    )
    runuser.chmod(0o755)
    env = dict(os.environ, PATH=str(stub) + ":" + os.environ["PATH"])

    def actual_probe(command: str, *, stdin: str, name: str) -> str:
        result = subprocess.run(
            ["/bin/bash", "-c", command], input=stdin, text=True, capture_output=True, timeout=30, env=env
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    monkeypatch.setattr(observation, "probe", actual_probe)
    return bin_path.parent, log


def calls(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def test_actual_encoded_current_homeassistant_observation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, log = fixture(tmp_path, monkeypatch)
    cfg = HomeAssistantRuntimeConfig(virtualenv_path=str(venv), package_spec="homeassistant==2026.10.2")
    result = observation.inspect_environment(cfg, "homeassistant")
    assert result.python_stdout == "Python 3.14.8"
    assert result.installed_version == "2026.10.2"
    assert not homeassistant_decision(cfg, result).replace
    assert not homeassistant_decision(cfg, result).install_application
    assert calls(log) == [
        ["python", "--version"],
        ["python", "-m", "pip", "--version"],
        ["python", "-m", "pip", "show", "python-matter-server"],
        ["hass", "--version"],
    ]


@pytest.mark.parametrize("cause", ["force", "missing-python", "llama-rebuild"])
def test_replacement_never_imports_old_application(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cause: str) -> None:
    venv, log = fixture(tmp_path, monkeypatch)
    if cause == "missing-python":
        (venv / "bin/python").unlink()
    cfg = HomeAssistantRuntimeConfig(virtualenv_path=str(venv), force_reinstall=cause == "force")
    result = observation.inspect_environment(cfg, "homeassistant", llama_cpp_rebuild=cause == "llama-rebuild")
    assert homeassistant_decision(cfg, result, llama_cpp_rebuild=cause == "llama-rebuild").replace
    assert all(entry[0] != "hass" for entry in calls(log))
    if cause == "missing-python":
        assert calls(log) == []


def test_existing_python_missing_application(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, _ = fixture(tmp_path, monkeypatch)
    (venv / "bin/hass").unlink()
    cfg = HomeAssistantRuntimeConfig(virtualenv_path=str(venv))
    result = observation.inspect_environment(cfg, "homeassistant")
    decision = homeassistant_decision(cfg, result)
    assert not decision.replace
    assert decision.install_application


@pytest.mark.parametrize("kind", ["homeassistant", "matter"])
def test_dangling_python_refuses_before_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: observation.Kind
) -> None:
    venv, log = fixture(tmp_path, monkeypatch, matter=kind == "matter")
    interpreter = venv / "bin/python"
    interpreter.unlink()
    interpreter.symlink_to(venv / "missing-owned-interpreter")
    before = interpreter.lstat()
    cfg = HomeAssistantRuntimeConfig(virtualenv_path=str(venv), matter_server_virtualenv_path=str(venv))
    with pytest.raises(AssertionError, match="no recognised Python version"):
        observation.inspect_environment(cfg, kind)
    after = interpreter.lstat()
    assert (
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) == (
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    assert calls(log) == []


@pytest.mark.parametrize("pinned", [False, True])
def test_dangling_hass_preserves_original_stat_and_failed_command_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pinned: bool
) -> None:
    venv, _ = fixture(tmp_path, monkeypatch)
    app = venv / "bin/hass"
    app.unlink()
    app.symlink_to(venv / "missing-owned-application")
    cfg = HomeAssistantRuntimeConfig(
        virtualenv_path=str(venv), package_spec="homeassistant==2026.10.2" if pinned else "homeassistant"
    )
    result = observation.inspect_environment(cfg, "homeassistant")
    assert result.application_exists
    assert result.installed_version == ""
    assert homeassistant_decision(cfg, result).install_application is pinned


def test_actual_separate_matter_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, log = fixture(tmp_path, monkeypatch, matter=True)
    cfg = HomeAssistantRuntimeConfig(
        matter_server_virtualenv_path=str(venv), matter_server_package_spec="python-matter-server[server]==8.1.2"
    )
    result = observation.inspect_environment(cfg, "matter")
    assert result.installed_version == "8.1.2"
    assert not matter_decision(cfg, result).install_application
    assert calls(log) == [
        ["python", "--version"],
        ["python", "-m", "pip", "--version"],
        ["python", "-c", "import chip.exceptions"],
        ["python", "-m", "pip", "show", "python-matter-server"],
    ]


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"extra": "field"},
        [],
        {**asdict(EnvironmentState(False)), "python_exists": "true"},
        {**asdict(EnvironmentState(False)), "pip_status": True},
        {**asdict(EnvironmentState(False)), "installed_version": None},
    ],
)
def test_unknown_status_schema_refused(monkeypatch: pytest.MonkeyPatch, bad: Any) -> None:
    monkeypatch.setattr(observation, "probe", lambda *a, **k: json.dumps(bad))
    with pytest.raises(DeployError, match="state inspection failed"):
        observation.inspect_environment(HomeAssistantRuntimeConfig(), "homeassistant")


def test_observation_command_declares_service_user_and_no_bytecode() -> None:
    args = shlex.split(observation.observation_command(HomeAssistantRuntimeConfig()))
    assert args[:6] == ["runuser", "-u", "homeassistant", "--", "env", "HOME=/home/homeassistant"]
    assert "PYTHONDONTWRITEBYTECODE=1" in args
    assert args[-5:-1] == ["python3", "-I", "-B", "-c"]
