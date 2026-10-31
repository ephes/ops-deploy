"""Owned temporary filesystem proof only; no fixed HA path or inventory call."""

from __future__ import annotations

import errno
import grp
import importlib.util
import json
import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SOURCE = Path(__file__).parents[1] / "src/ops_deploy/services/homeassistant/files/configuration_file.py"
SPEC = importlib.util.spec_from_file_location("owned_ha_configuration_file", SOURCE)
assert SPEC is not None
assert SPEC.loader is not None
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


def payload(path: Path, kind: str = "template", action: str = "apply") -> dict[str, Any]:
    return {
        "path": str(path),
        "kind": kind,
        "action": action,
        "content": "new synthetic private body\n",
        "pattern": "old",
        "user": pwd.getpwuid(os.getuid()).pw_name,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "mode": "0600",
    }


def invoke(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(SOURCE)], input=json.dumps(data), capture_output=True, text=True, timeout=10
    )
    assert result.stderr == ""
    assert "synthetic private" not in result.stdout
    return result.returncode, json.loads(result.stdout)


def metadata(path: Path) -> tuple[int, ...]:
    s = path.lstat()
    return s.st_mode, s.st_uid, s.st_gid, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def test_new_template_check_apply_and_whole_noop(tmp_path: Path) -> None:
    path = tmp_path / "configuration.yaml"
    code, checked = invoke(payload(path, action="check"))
    assert code == 0
    assert checked["changed"]
    assert not checked["body_written"]
    assert list(tmp_path.iterdir()) == []
    code, first = invoke(payload(path))
    assert code == 0
    assert first["body_written"]
    assert not first["backup_created"]
    assert path.read_text() == "new synthetic private body\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    before = metadata(path)
    assert invoke(payload(path))[1] == {
        "success": True,
        "changed": False,
        "effects_started": False,
        "backup_created": False,
        "body_written": False,
        "metadata_written": False,
    }
    assert metadata(path) == before


@pytest.mark.parametrize("link", [False, True])
@pytest.mark.parametrize("same", [False, True])
def test_template_original_backup_and_leaf_link_replacement(tmp_path: Path, link: bool, same: bool) -> None:
    target, path = tmp_path / "target", tmp_path / "configuration.yaml"
    body = "new synthetic private body\n" if same else "old synthetic private body\n"
    if link:
        target.write_text(body)
        target.chmod(0o640)
        path.symlink_to(target.name)
        target_before = metadata(target)
    else:
        path.write_text(body)
        path.chmod(0o640)
    code, result = invoke(payload(path))
    assert code == 0
    assert result["changed"]
    expected_body_write = link or not same
    assert result["backup_created"] is expected_body_write
    assert result["body_written"] is expected_body_write
    assert not path.is_symlink()
    backups = list(tmp_path.glob("configuration.yaml.*~"))
    assert len(backups) == int(expected_body_write)
    if backups:
        assert backups[0].read_text() == body
        assert stat.S_IMODE(backups[0].stat().st_mode) == 0o640
    if link:
        assert target.read_text() == body
        assert metadata(target) == target_before
    before = metadata(path)
    assert invoke(payload(path))[1]["changed"] is False
    assert metadata(path) == before


@pytest.mark.parametrize("changed", [False, True])
def test_replace_follows_leaf_and_backup_stays_next_to_link(tmp_path: Path, changed: bool) -> None:
    sub = tmp_path / "other"
    sub.mkdir()
    target, path = sub / "target", tmp_path / "configuration.yaml"
    target.write_text("old synthetic private body\n" if changed else "matching synthetic private body\n")
    target.chmod(0o640)
    path.symlink_to("other/target")
    before_link, before_target = metadata(path), metadata(target)
    original = target.read_bytes()
    code, result = invoke(payload(path, "replace"))
    assert code == 0
    assert result["changed"] is changed
    assert path.is_symlink()
    assert metadata(path) == before_link
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert not list(sub.glob("*~"))
    if changed:
        assert next(tmp_path.glob("configuration.yaml.*~")).read_bytes() == original
        assert target.read_bytes() == original.replace(b"old", b"")
    else:
        assert not list(tmp_path.glob("*~"))
        assert metadata(target) == before_target


def test_missing_replace_and_parent_refuse_without_creation(tmp_path: Path) -> None:
    assert invoke(payload(tmp_path / "missing", "replace"))[0] == 1
    assert invoke(payload(tmp_path / "parent/file"))[0] == 1
    assert list(tmp_path.iterdir()) == []


def test_failed_rename_retains_actual_backup_and_original_then_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "configuration.yaml"
    path.write_text("old synthetic private body\n")
    path.chmod(0o600)
    before = metadata(path)
    effects = {
        "changed": False,
        "effects_started": False,
        "backup_created": False,
        "body_written": False,
        "metadata_written": False,
    }

    def fail(*args: object) -> None:
        raise PermissionError("synthetic private must not be exported")

    with monkeypatch.context() as patch:
        patch.setattr(HELPER.os, "replace", fail)
        with pytest.raises(PermissionError):
            HELPER.process(payload(path), effects)
    assert effects == {
        "changed": True,
        "effects_started": True,
        "backup_created": True,
        "body_written": False,
        "metadata_written": False,
    }
    assert metadata(path) == before
    assert len(list(tmp_path.glob("*~"))) == 1
    assert not list(tmp_path.glob(".ops-ha-config-*"))
    assert invoke(payload(path))[0] == 0
    assert invoke(payload(path))[1]["changed"] is False


def test_partial_backup_failure_is_not_reported_as_zero_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "configuration.yaml"
    path.write_text("old synthetic private body\n")
    original = path.read_bytes()
    effects = {
        "changed": False,
        "effects_started": False,
        "backup_created": False,
        "body_written": False,
        "metadata_written": False,
    }

    def partial(source: object, destination: str) -> None:
        Path(destination).write_bytes(b"partial owned backup")
        raise OSError("owned partial backup fault")

    monkeypatch.setattr(HELPER.shutil, "copy2", partial)
    with pytest.raises(OSError, match="owned partial backup fault"):
        HELPER.process(payload(path), effects)
    assert effects["effects_started"] is True
    assert effects["backup_created"] is False
    assert effects["body_written"] is False
    assert next(tmp_path.glob("*~")).read_bytes() == b"partial owned backup"
    assert path.read_bytes() == original


def test_metadata_failure_after_body_write_and_ordinary_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "configuration.yaml"
    request = {**payload(path), "mode": "0644"}
    effects = {
        "changed": False,
        "effects_started": False,
        "backup_created": False,
        "body_written": False,
        "metadata_written": False,
    }

    def fail(*args: object) -> None:
        raise PermissionError("owned chmod fault")

    with monkeypatch.context() as patch:
        patch.setattr(HELPER.os, "chmod", fail)
        with pytest.raises(PermissionError):
            HELPER.process(request, effects)
    assert effects["body_written"] is True
    assert effects["effects_started"] is True
    assert effects["metadata_written"] is False
    assert path.read_text() == request["content"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    code, repaired = invoke(request)
    assert code == 0
    assert repaired["metadata_written"] is True
    assert repaired["backup_created"] is False
    assert repaired["body_written"] is False
    assert invoke(request)[1]["changed"] is False


@pytest.mark.parametrize(
    ("kind", "number"), [("replace", errno.EPERM), ("template", errno.EPERM), ("replace", errno.EACCES)]
)
def test_original_atomic_metadata_eperm_only_is_tolerated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, number: int
) -> None:
    path = tmp_path / "configuration.yaml"
    path.write_text("old synthetic private body\n")
    path.chmod(0o640)
    effects = {
        "changed": False,
        "effects_started": False,
        "backup_created": False,
        "body_written": False,
        "metadata_written": False,
    }
    chown = HELPER.os.chown

    def fault(destination: object, uid: int, gid: int) -> None:
        if Path(str(destination)).name.startswith(".ops-ha-config-"):
            raise OSError(number, "owned atomic metadata fault")
        chown(destination, uid, gid)

    monkeypatch.setattr(HELPER.os, "chown", fault)
    if number == errno.EPERM:
        HELPER.process(payload(path, kind), effects)
        assert effects["body_written"] is True
        # Both original atomic_move and this helper skip remaining copystat
        # after EPERM. Replace has no declared metadata repair after the move.
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert "old" not in path.read_text()
    else:
        with pytest.raises(OSError, match="owned atomic metadata fault"):
            HELPER.process(payload(path, kind), effects)
        assert effects["body_written"] is False
        assert effects["backup_created"] is True
        assert path.read_text() == "old synthetic private body\n"
    assert not list(tmp_path.glob(".ops-ha-config-*"))
