"""Owned attention helper transitions and genuine application-import failure."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
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


def owned_configuration(installation: Any, module: Any, monkeypatch: Any) -> Path:
    installation.account = types.SimpleNamespace(pw_uid=os.getuid(), pw_name="fixture")
    path = Path(installation.data["config_path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    Path(installation.data["plist_path"]).parent.mkdir(parents=True, exist_ok=True)
    installation.data["config"] = {
        "version": 1,
        "enabled": False,
        "profile": "synthetic",
        "state_path": installation.data["runtime_dir"] + "/state.sqlite3",
        "source": {"kind": "synthetic"},
    }
    installation.data["plist"] = "owned plist"
    monkeypatch.setitem(module.put_bytes.__globals__, "ids", lambda spec: (os.getuid(), os.getgid()))
    monkeypatch.setattr(module, "run", lambda *args, **kw: types.SimpleNamespace(returncode=0))
    return path


def production(installation: Any, reader: Path) -> dict[str, Any]:
    return {
        **installation.data["config"],
        "profile": "production",
        "source": {"kind": "s3", "endpoint_url": "https://owned.invalid/", "credentials_file": str(reader)},
    }


def exact_file(path: Path) -> tuple[Any, ...]:
    info = path.lstat()
    return (
        path.read_bytes(),
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@pytest.mark.parametrize("mode", [0o400, 0o600])
@pytest.mark.parametrize("profile", ["synthetic", "production"])
def test_existing_disabled_configuration_bytes_metadata_and_auth_untouched(
    module: Any,
    installation: Any,
    monkeypatch: Any,
    mode: int,
    profile: str,
) -> None:
    path = owned_configuration(installation, module, monkeypatch)
    reader = path.parent / "not-an-allowlisted-reader.json"
    reader.write_text("OWNED authentication sentinel")
    reader.chmod(0o600)
    config = production(installation, reader) if profile == "production" else installation.data["config"]
    path.write_text("\n  " + json.dumps(config, indent=3) + "  \n")
    path.chmod(mode)
    before = exact_file(path), exact_file(reader)
    opened: list[str] = []
    original_open = os.open

    def opened_path(name: Any, *args: Any, **kwargs: Any) -> int:
        opened.append(str(name))
        assert str(name) not in {str(reader), reader.name}
        return original_open(name, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", opened_path)
    assert installation.configuration_current()
    assert [row["path"] for row in installation.resources()] == [installation.data["plist_path"]]
    installation.publish_resources()
    installation.publish_resources()
    assert (exact_file(path), exact_file(reader)) == before
    assert path.name in opened


def test_missing_configuration_seeds_original_default_once(module: Any, installation: Any, monkeypatch: Any) -> None:
    path = owned_configuration(installation, module, monkeypatch)
    assert not installation.configuration_current()
    assert len(installation.resources()) == 2
    installation.publish_resources()
    assert json.loads(path.read_bytes()) == installation.data["config"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    before = exact_file(path)
    installation.publish_resources()
    assert exact_file(path) == before


@pytest.mark.parametrize("enabled", [False, True])
def test_actual_no_replace_publication_keeps_concurrent_creator(
    module: Any,
    installation: Any,
    monkeypatch: Any,
    enabled: bool,
) -> None:
    path = owned_configuration(installation, module, monkeypatch)
    winner = {**production(installation, path.parent / "never-opened-reader"), "enabled": enabled}
    original_link = module.os.link
    winners: list[tuple[Any, ...]] = []

    def create_before_link(src: Any, dst: Any, **kwargs: Any) -> Any:
        assert str(dst) == path.name
        path.write_text(json.dumps(winner, indent=7) + "\n")
        path.chmod(0o400)
        winners.append(exact_file(path))
        return original_link(src, dst, **kwargs)

    monkeypatch.setattr(module.os, "link", create_before_link)
    if enabled:
        with pytest.raises(module.AttentionError, match="configuration_invalid"):
            installation.publish_resources()
        assert not Path(installation.data["plist_path"]).exists()
    else:
        installation.publish_resources()
    assert len(winners) == 1
    assert exact_file(path) == winners[0]
    assert not list(path.parent.glob(".daybook-sessions-*"))


@pytest.mark.parametrize(
    "fault",
    [
        "enabled",
        "invalid-json",
        "oversize",
        "writable",
        "readable",
        "hardlink",
        "symlink",
        "directory",
        "fifo",
        "owner",
        "source",
    ],
)
def test_unsafe_or_enabled_existing_configuration_refuses_before_publication(
    module: Any,
    installation: Any,
    monkeypatch: Any,
    fault: str,
) -> None:
    path = owned_configuration(installation, module, monkeypatch)
    value = {**installation.data["config"], "enabled": fault == "enabled"}
    if fault == "source":
        value["source"] = {"kind": "s3", "credentials_file": "PRIVATE sentinel"}
    path.write_text("PRIVATE malformed" if fault == "invalid-json" else json.dumps(value))
    path.chmod(0o600)
    if fault == "oversize":
        path.write_bytes(b" " * 65537)
    elif fault in {"writable", "readable"}:
        path.chmod(0o620 if fault == "writable" else 0o640)
    elif fault == "hardlink":
        os.link(path, path.parent / "second-link")
    elif fault in {"symlink", "directory", "fifo"}:
        path.unlink()
        if fault == "symlink":
            path.symlink_to(path.parent / "absent")
        elif fault == "directory":
            path.mkdir()
        else:
            os.mkfifo(path)
    elif fault == "owner":
        installation.account.pw_uid = os.getuid() + 1
    monkeypatch.setattr(module, "put_bytes", lambda *a, **kw: pytest.fail("unsafe config seeded"))
    monkeypatch.setattr(module, "put_resource", lambda *a, **kw: pytest.fail("unsafe config published"))
    with pytest.raises((module.AttentionError, OSError)):
        installation.publish_resources()


@pytest.mark.parametrize("replace_path", [False, True])
def test_configuration_change_during_read_is_rejected(
    module: Any,
    installation: Any,
    monkeypatch: Any,
    replace_path: bool,
) -> None:
    path = owned_configuration(installation, module, monkeypatch)
    path.write_text(json.dumps(installation.data["config"]))
    path.chmod(0o600)
    original_read = os.read

    def changing_read(fd: int, size: int) -> bytes:
        body = original_read(fd, size)
        if replace_path:
            path.unlink()
        path.write_bytes(body + b" ")
        path.chmod(0o600)
        return body

    monkeypatch.setattr(module.os, "read", changing_read)
    with pytest.raises(module.AttentionError, match="configuration_changed"):
        installation.configuration_current()


def test_main_invalid_config_returns_fixed_error_without_private_body(
    module: Any,
    installation: Any,
    monkeypatch: Any,
    capsys: Any,
) -> None:
    path = owned_configuration(installation, module, monkeypatch)
    path.write_text("PRIVATE owned configuration sentinel")
    path.chmod(0o600)
    monkeypatch.setattr(module, "Installation", lambda data: installation)
    monkeypatch.setattr(module.sys, "argv", ["attention_host.py", "resources"])
    monkeypatch.setattr(module.sys, "stdin", io.StringIO("{}"))
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(installation, "require_quiescent", lambda: pytest.fail("invalid config reached managed work"))
    assert module.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "attention_component_failed\n"


@pytest.mark.parametrize("existing", [False, True])
def test_existing_config_is_authority_while_fresh_invalid_seed_refuses(
    module: Any,
    installation: Any,
    monkeypatch: Any,
    existing: bool,
) -> None:
    path = owned_configuration(installation, module, monkeypatch)
    if existing:
        path.write_text(json.dumps(production(installation, path.parent / "reader-never-opened"), indent=3))
        path.chmod(0o400)
        before = exact_file(path)
    # The unchanged controller model accepts this mismatched profile/source.
    # It has no authority over an installed valid disabled document.
    installation.data["config"] = {**installation.data["config"], "profile": "production"}
    if existing:
        assert [row["path"] for row in installation.resources()] == [installation.data["plist_path"]]
        installation.publish_resources()
        assert exact_file(path) == before
    else:
        with pytest.raises(module.AttentionError, match="configuration_invalid"):
            installation.resources()
        with pytest.raises(module.AttentionError, match="configuration_invalid"):
            installation.publish_resources()
        assert not path.exists()
        assert not Path(installation.data["plist_path"]).exists()
