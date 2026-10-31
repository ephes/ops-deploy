"""Owned filesystem controls: original additive keys, private preservation and no sends."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import types
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

PACKAGE = "ops_deploy.services.daybook_voice_memo_attention_notifier"


def load(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.fixture
def module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    fs = load(
        "owned_notifier_fs",
        Path(str(files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py"))),
    )
    monkeypatch.setitem(sys.modules, "ops_notifier_filesystem", fs)
    helper = load("owned_notifier", Path(str(files(PACKAGE).joinpath("files/notifier_host.py"))))
    local, etc, root = (tmp_path / name for name in ("local", "etc", "root"))
    for path in (local, etc, root):
        path.mkdir(mode=0o755)
    monkeypatch.setattr(helper, "ROOT_UID", os.getuid())
    monkeypatch.setattr(helper, "ROOT_GID", os.getgid())
    monkeypatch.setattr(helper, "LOCAL", str(local))
    monkeypatch.setattr(helper, "SCRIPT", str(local / "libexec" / "notify.py"))
    monkeypatch.setattr(helper, "CONFIG", str(etc / "notify.json"))
    monkeypatch.setattr(helper, "KEYS", str(root / ".ssh" / "authorized_keys"))
    monkeypatch.setattr(
        helper, "DIRECTORIES", {str(local): None, str(local / "libexec"): 0o755, str(root / ".ssh"): 0o700}
    )
    monkeypatch.setattr(fs, "ids", lambda spec: (os.getuid(), os.getgid()))
    return helper


@pytest.fixture
def pins() -> dict[str, str]:
    return {
        "public_key": "ssh-ed25519 " + "A" * 68 + " owned",
        "native_host": "owned-host",
        "recipient": "123456789",
        "container": "openclaw-gateway",
        "script_base64": base64.b64encode(b"raise RuntimeError('must never execute')\n").decode(),
    }


def captured(module: Any) -> dict[str, tuple[bytes, os.stat_result]]:
    return {p: (Path(p).read_bytes(), Path(p).stat()) for p in (module.SCRIPT, module.CONFIG, module.KEYS)}


def test_fresh_then_repeat_compile_without_execution(module: Any, pins: dict[str, str]) -> None:
    assert module.snapshot(pins)[0] == dict.fromkeys(("directories", "script", "config", "authorization"), False)
    assert module.apply(pins) == {"changed": True, "category": "shared_notifier_installed"}
    before = captured(module)
    assert module.apply(pins) == {"changed": False, "category": "shared_notifier_installed"}
    assert captured(module) == before
    assert [Path(p).stat().st_mode & 0o777 for p in (module.SCRIPT, module.CONFIG, module.KEYS)] == [
        0o755,
        0o600,
        0o600,
    ]


def test_script_update_preserves_formatted_config_and_whole_admin_authorization(
    module: Any, pins: dict[str, str]
) -> None:
    module.apply(pins)
    config = Path(module.CONFIG)
    config.write_text(json.dumps(json.loads(config.read_text()), indent=4) + "\n\n")
    keys = Path(module.KEYS)
    keys.write_bytes(b"# retained administrator\nssh-ed25519 " + b"B" * 68 + b" admin\n\n" + keys.read_bytes())
    before = captured(module)
    changed = {**pins, "script_base64": base64.b64encode(b"raise AssertionError('new source not executed')\n").decode()}
    assert module.apply(changed)["changed"] is True
    after = captured(module)
    assert after[module.CONFIG] == before[module.CONFIG]
    assert after[module.KEYS] == before[module.KEYS]
    assert after[module.SCRIPT][0] != before[module.SCRIPT][0]


@pytest.mark.parametrize("fault", ["same-key-options", "foreign-marker"])
def test_conflicting_authorization_refused_before_any_write(module: Any, pins: dict[str, str], fault: str) -> None:
    module.apply(pins)
    keys = Path(module.KEYS)
    if fault == "same-key-options":
        keys.write_text(pins["public_key"] + "\n")
    elif fault == "foreign-marker":
        keys.write_text("ssh-ed25519 " + "B" * 68 + " daybook-attention-notifier\n")
    before = captured(module)
    with pytest.raises(module.Refused):
        module.apply(pins)
    assert captured(module) == before


def test_existing_same_key_same_options_duplicates_are_preserved(module: Any, pins: dict[str, str]) -> None:
    module.apply(pins)
    keys = Path(module.KEYS)
    keys.write_bytes(keys.read_bytes() * 2)
    before = captured(module)
    assert module.apply(pins)["changed"] is False
    assert captured(module) == before


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "unsafe-mode", "oversize"])
def test_unsafe_private_resource_refuses_without_mutation(module: Any, pins: dict[str, str], fault: str) -> None:
    module.apply(pins)
    path = Path(module.CONFIG)
    other = path.with_name("owned-other")
    if fault == "symlink":
        path.rename(other)
        path.symlink_to(other)
    elif fault == "hardlink":
        os.link(path, other)
    elif fault == "unsafe-mode":
        path.chmod(0o666)
    else:
        path.write_bytes(b" " * 8193)
    original_script = Path(module.SCRIPT).read_bytes(), Path(module.SCRIPT).stat()
    with pytest.raises((OSError, module.Refused)):
        module.apply(pins)
    assert (Path(module.SCRIPT).read_bytes(), Path(module.SCRIPT).stat()) == original_script


def test_status_does_not_create_missing_private_directories(module: Any, pins: dict[str, str]) -> None:
    before = tuple(Path(module.LOCAL).iterdir())
    module.snapshot(pins)
    assert tuple(Path(module.LOCAL).iterdir()) == before
    assert not Path(module.KEYS).parent.exists()


def test_invalid_source_refuses_before_directories_or_config(module: Any, pins: dict[str, str]) -> None:
    pins["script_base64"] = base64.b64encode(b"if invalid syntax").decode()
    with pytest.raises(SyntaxError):
        module.apply(pins)
    assert not Path(module.SCRIPT).parent.exists()
    assert not Path(module.CONFIG).exists()


def test_changed_private_descriptor_during_read_refuses(
    module: Any, pins: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    module.apply(pins)
    original_read = os.read
    altered = False

    def read(fd: int, size: int) -> bytes:
        nonlocal altered
        result = original_read(fd, size)
        if not altered:
            altered = True
            Path(module.CONFIG).write_bytes(b"{}")
        return result

    monkeypatch.setattr(os, "read", read)
    with pytest.raises(module.Refused):
        module.read(module.CONFIG, 8192)


def test_atomic_publication_interruption_preserves_existing_file(
    module: Any, pins: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    module.apply(pins)
    before = captured(module)
    pins["script_base64"] = base64.b64encode(b"pass\n").decode()

    def interrupted(*args: Any, **kwargs: Any) -> None:
        raise OSError("owned interrupted publication")

    monkeypatch.setattr(os, "replace", interrupted)
    with pytest.raises(OSError, match="owned interrupted publication"):
        module.apply(pins)
    assert captured(module) == before
    assert list(Path(module.SCRIPT).parent.iterdir()) == [Path(module.SCRIPT)]
