"""Original exact OCR replacement and metadata-only ownership convergence."""

import importlib.util
import inspect
import os
import shlex
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ops_deploy.services.paperless import assets
from ops_deploy.services.paperless.config import PaperlessConfig

SPEC = importlib.util.spec_from_file_location(
    "paperless_python_assets", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/python_assets.py"
)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_actual_ocr_bytes_first_and_physical_repeat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / ".venv"
    target = root / "lib/python3.14/site-packages/ocrmypdf/helpers.py"
    target.parent.mkdir(parents=True)
    target.write_text("# before\n" + MODULE.OLD + "# after\n")
    target.chmod(0o640)
    assert MODULE.patch_ocr(root, False)
    assert MODULE.patch_ocr(root, True)
    assert target.read_text() == "# before\n" + MODULE.NEW + "# after\n"
    before = target.stat()
    assert not MODULE.patch_ocr(root, True)
    after = target.stat()
    assert before.st_ino == after.st_ino
    assert before.st_mtime_ns == after.st_mtime_ns
    assert before.st_ctime_ns == after.st_ctime_ns
    assert after.st_mode & 0o777 == 0o640
    assert list(target.parent.iterdir()) == [target]


def test_ocr_absent_old_pattern_preserves_source_like_original(tmp_path: Path) -> None:
    target = tmp_path / "lib/python3.14/site-packages/ocrmypdf/helpers.py"
    target.parent.mkdir(parents=True)
    target.write_text("# different upstream implementation\n")
    before = target.stat()
    assert not MODULE.patch_ocr(tmp_path, True)
    assert target.stat().st_ctime_ns == before.st_ctime_ns


def test_ocr_parent_symlink_escape_is_refused(tmp_path: Path) -> None:
    root = tmp_path / ".venv"
    root.mkdir()
    foreign = tmp_path / "foreign"
    target = foreign / "python3.14/site-packages/ocrmypdf/helpers.py"
    target.parent.mkdir(parents=True)
    target.write_text(MODULE.OLD)
    (root / "lib").symlink_to(foreign, target_is_directory=True)
    with pytest.raises(ValueError, match="escapes"):
        MODULE.patch_ocr(root, True)
    assert target.read_text() == MODULE.OLD


def test_healthy_ownership_skips_all_chown_and_does_not_traverse_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / ".venv"
    root.mkdir()
    (root / "program").write_text("program")
    foreign = tmp_path / "outside"
    foreign.mkdir()
    (foreign / "not-a-program").write_text("untouched")
    (root / "external").symlink_to(foreign, target_is_directory=True)
    monkeypatch.setattr(MODULE.os, "chown", lambda *a, **k: pytest.fail("healthy chown"))
    monkeypatch.setattr(MODULE.os, "fchown", lambda *a, **k: pytest.fail("healthy fchown"))
    assert not MODULE.ownership(root.resolve(), os.getuid(), os.getgid(), True)


def test_ownership_changes_only_mismatches_without_following_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / ".venv"
    root.mkdir()
    (root / "program").write_text("program")
    calls = []
    directory_calls = []
    monkeypatch.setattr(MODULE.os, "chown", lambda path, uid, gid, **kw: calls.append((path, uid, gid, kw)))
    monkeypatch.setattr(MODULE.os, "fchown", lambda fd, uid, gid: directory_calls.append((fd, uid, gid)))
    assert MODULE.ownership(root.resolve(), os.getuid() + 1, os.getgid(), False)
    assert calls == []
    assert directory_calls == []
    assert MODULE.ownership(root.resolve(), os.getuid() + 1, os.getgid(), True)
    assert [call[0] for call in calls] == ["program"]
    assert len(directory_calls) == 1
    assert all(call[3]["follow_symlinks"] is False and isinstance(call[3]["dir_fd"], int) for call in calls)


def test_parent_swap_cannot_redirect_actual_ownership_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = (tmp_path / ".venv").resolve()
    child = root / "nested"
    child.mkdir(parents=True)
    owned = child / "program"
    owned.write_text("owned program")
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    protected = foreign / "program"
    protected.write_text("unrelated program")
    before = protected.stat()
    owned_ino = owned.stat().st_ino
    actual_stat, actual_lstat, actual_chown = os.stat, os.lstat, os.chown
    injected: list[bool] = []

    def misowned(meta: os.stat_result) -> os.stat_result:
        if meta.st_ino != owned_ino:
            return meta
        fields = list(meta)
        fields[4] = os.getuid() + 1
        return os.stat_result(fields)

    def checked_stat(*args: Any, **kwargs: Any) -> os.stat_result:
        return misowned(actual_stat(*args, **kwargs))

    def checked_lstat(*args: Any, **kwargs: Any) -> os.stat_result:
        return misowned(actual_lstat(*args, **kwargs))

    def swap_then_chown(path: Any, uid: int, gid: int, **kwargs: Any) -> None:
        assert not injected
        child.rename(root / "moved")
        child.symlink_to(foreign, target_is_directory=True)
        injected.append(True)
        actual_chown(path, uid, gid, **kwargs)

    monkeypatch.setattr(MODULE.os, "stat", checked_stat)
    monkeypatch.setattr(MODULE.os, "lstat", checked_lstat)
    monkeypatch.setattr(MODULE.os, "chown", swap_then_chown)
    assert MODULE.ownership(root, os.getuid(), os.getgid(), True)
    assert injected == [True]
    after = actual_stat(protected)
    assert before.st_ctime_ns == after.st_ctime_ns
    assert before.st_ino == after.st_ino
    assert protected.read_text() == "unrelated program"


def test_actual_ocr_operation_drops_to_service_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assets, "state", SimpleNamespace(is_executing=True))
    monkeypatch.setattr(assets, "probe", lambda *a, **k: "pending")
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    command = next(inspect.unwrap(assets.python_assets)(cfg, "ocr"))
    argv = shlex.split(str(command.get_raw_value()))
    assert argv[:6] == ["runuser", "-u", "paperless", "--", "env", "HOME=/home/paperless"]
    assert command.connector_arguments["_get_pty"] is False
