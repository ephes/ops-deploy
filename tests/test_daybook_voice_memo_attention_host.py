"""Owned attention helper transitions and genuine application-import failure."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

PACKAGE = "ops_deploy.services.daybook_voice_memo_attention"


@pytest.fixture
def module(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    filesystem = types.ModuleType("ops_attention_filesystem")
    body = files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py").read_text()
    exec(compile(body, "<owned-resource-context>", "exec"), filesystem.__dict__)
    monkeypatch.setitem(sys.modules, "ops_attention_filesystem", filesystem)
    spec = importlib.util.spec_from_file_location(
        "owned_attention_host", str(files(PACKAGE).joinpath("files/attention_host.py"))
    )
    assert spec is not None
    assert spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.fixture
def installation(module: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    home = tmp_path / "home"
    monkeypatch.setattr(
        module.pwd, "getpwnam", lambda _: types.SimpleNamespace(pw_name="fixture", pw_uid=501, pw_dir=str(home))
    )
    data = {
        "service_user": "fixture",
        "service_home": str(home),
        "install_root": str(tmp_path / "install"),
        "venv": str(tmp_path / "install/venv"),
        "python_install_dir": str(tmp_path / "python"),
        "wheel_name": "daybook-0.0.0-py3-none-any.whl",
        "wheel_sha1": "a" * 40,
        "python_version": "3.14.7",
        "runtime_dir": str(home / "runtime"),
        "config_path": str(home / "runtime/config.json"),
        "launchd_label": "example.owned.attention",
        "plist_path": str(home / "Library/LaunchAgents/owned.plist"),
    }
    return module.Installation(data)


class Launchd:
    def __init__(self, *, faults: tuple[str, ...] = ()) -> None:
        self.loaded = True
        self.disabled = False
        self.faults = faults
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> types.SimpleNamespace:
        self.calls.append(argv)
        rc, out, err = 0, b"", b""
        command = argv[1]
        if command in self.faults:
            return types.SimpleNamespace(returncode=127, stdout=b"", stderr=b"owned tool fault")
        if command == "print" and argv[2].count("/") == 2 and not self.loaded:
            rc, err = 113, b'Could not find service "example.owned.attention" in domain for user gui: 501'
        elif command == "print-disabled":
            out = b'"example.owned.attention" => true' if self.disabled else b'"example.owned.attention" => false'
        elif command == "disable":
            self.disabled = True
        elif command == "bootout":
            self.loaded = False
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def test_only_original_label_disabled_unloaded_and_verified(module: Any, installation: Any, monkeypatch: Any) -> None:
    launchd = Launchd()
    monkeypatch.setattr(module, "run", launchd)
    installation.quiesce()
    assert launchd.disabled
    assert not launchd.loaded
    assert [argv[1] for argv in launchd.calls if argv[1] in {"disable", "bootout"}] == ["disable", "bootout"]
    assert all(
        argv[-1] == "gui/501/example.owned.attention" for argv in launchd.calls if argv[1] in {"disable", "bootout"}
    )


@pytest.mark.parametrize("fault", ["disable", "bootout", "print-disabled"])
def test_actual_label_fault_cannot_report_success(module: Any, installation: Any, monkeypatch: Any, fault: str) -> None:
    launchd = Launchd(faults=(fault,))
    monkeypatch.setattr(module, "run", launchd)
    with pytest.raises(module.AttentionError, match="not_disabled_unloaded"):
        installation.quiesce()
    assert any(argv[1] == "bootout" for argv in launchd.calls)


def test_wrong_interpreter_rebuild_does_not_execute_old_code(module: Any, installation: Any, monkeypatch: Any) -> None:
    installation.venv.mkdir(parents=True)
    (installation.venv / "untrusted.py").write_text("raise AssertionError('must never run')")
    events: list[str] = []
    monkeypatch.setattr(installation, "require_quiescent", lambda: events.append("quiescent"))
    monkeypatch.setattr(installation, "code_tree", lambda **kw: events.append("code-skip" if kw else "code-all"))
    monkeypatch.setattr(installation, "wheel_current", lambda: True)
    monkeypatch.setattr(installation, "interpreter", lambda: Path("/owned/python/bin/python3.14"))
    monkeypatch.setattr(installation, "venv_current", lambda _: (installation.venv / "bin/python").exists())

    def uv(*argv: str, **kwargs: Any) -> str:
        events.append(" ".join(argv[:2]))
        if argv[0] == "venv":
            assert not (installation.venv / "untrusted.py").exists()
            (installation.venv / "bin").mkdir(parents=True)
            (installation.venv / "bin/python").write_text("owned new inert interpreter")
        return ""

    monkeypatch.setattr(installation, "uv", uv)
    installation.install_environment()
    assert events == ["quiescent", "code-skip", "python install", "code-all", "venv --python", "pip install"]


def test_import_failure_keeps_receipt_and_uses_real_original_gui_transition(
    module: Any, installation: Any, monkeypatch: Any
) -> None:
    installation.root.mkdir()
    installation.receipt.write_text("OLD receipt\n")
    monkeypatch.setattr(installation, "require_quiescent", lambda: None)
    monkeypatch.setattr(installation, "code_tree", lambda: None)
    monkeypatch.setattr(installation, "wheel_current", lambda: True)
    monkeypatch.setattr(installation, "interpreter", lambda: Path("/owned/python/bin/python3.14"))
    monkeypatch.setattr(installation, "venv_current", lambda _: True)
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def failed(argv: list[str], **kwargs: Any) -> types.SimpleNamespace:
        calls.append((argv, kwargs))
        return types.SimpleNamespace(returncode=1, stdout=b"PRIVATE owned app output", stderr=b"PRIVATE owned failure")

    monkeypatch.setattr(module, "run", failed)
    with pytest.raises(module.AttentionError, match="application_import_failed"):
        installation.verify_import()
    assert installation.receipt.read_text() == "OLD receipt\n"
    assert calls[0][0] == [
        "/usr/bin/sudo",
        "-n",
        "-H",
        "-u",
        "fixture",
        "--",
        str(installation.venv / "bin/python"),
        "-I",
        "-c",
        "import daybook.attention",
    ]
    assert calls[0][1]["cwd"] == installation.data["service_home"]


def test_pure_observation_never_calls_import_or_managed_methods(
    module: Any, installation: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr(installation, "validate_paths", lambda: None)
    monkeypatch.setattr(installation, "controls", lambda: True)
    monkeypatch.setattr(installation, "directories", lambda: [])
    monkeypatch.setattr(installation, "resources", lambda: [])
    monkeypatch.setattr(installation, "wheel_current", lambda: True)
    monkeypatch.setattr(installation, "environment_current", lambda: True)
    monkeypatch.setattr(module, "run", lambda *a, **kw: pytest.fail("pure observation entered a command"))
    for name in ("quiesce", "install_environment", "verify_import"):
        monkeypatch.setattr(installation, name, lambda: pytest.fail("pure observation entered managed work"))
    assert json.loads(json.dumps(installation.status())) == dict.fromkeys(
        ("quiescent", "directories", "wheel", "environment", "resources"), True
    )
