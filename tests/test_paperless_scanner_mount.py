"""Synthetic fstab bytes and mount identity; never mount on the local host."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "paperless_scanner_mount", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/scanner_mount.py"
)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_original_semantics_leave_whitespace_and_peer_lines_intact(tmp_path: Path) -> None:
    table = tmp_path / "fstab"
    body = "# synthetic peer\n/srv/consume\t/srv/inbox none bind 0 0 # retained\n"
    table.write_text(body)
    before = table.stat()
    assert MODULE.fstab_change(table, Path("/srv/consume"), Path("/srv/inbox"), True) is False
    assert table.read_text() == body
    assert table.stat().st_ino == before.st_ino
    assert table.stat().st_mtime_ns == before.st_mtime_ns


def test_missing_entry_one_atomic_change_then_repeat(tmp_path: Path) -> None:
    table = tmp_path / "fstab"
    table.write_text("# unrelated fixture line\n")
    table.chmod(0o640)
    assert MODULE.fstab_change(table, Path("/srv/consume"), Path("/srv/inbox"), False) is True
    assert table.read_text() == "# unrelated fixture line\n"
    assert MODULE.fstab_change(table, Path("/srv/consume"), Path("/srv/inbox"), True) is True
    assert table.read_text() == "# unrelated fixture line\n/srv/consume /srv/inbox none bind 0 0\n"
    assert table.stat().st_mode & 0o777 == 0o640
    assert MODULE.fstab_change(table, Path("/srv/consume"), Path("/srv/inbox"), True) is False
    assert not list(tmp_path.glob(".paperless-fstab-*"))


@pytest.mark.parametrize("body", ["/foreign /srv/inbox none bind 0 0\n", "/srv/consume /srv/inbox none bind 0 0\n" * 2])
def test_foreign_or_duplicate_entry_refuses_without_write(body: str, tmp_path: Path) -> None:
    table = tmp_path / "fstab"
    table.write_text(body)
    with pytest.raises(MODULE.Refusal, match=r"another source|duplicate"):
        MODULE.fstab_change(table, Path("/srv/consume"), Path("/srv/inbox"), True)
    assert table.read_text() == body


def test_healthy_existing_bind_never_invokes_mount(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, target = tmp_path / "consume", tmp_path / "inbox"
    source.mkdir()
    target.mkdir()
    monkeypatch.setattr(MODULE, "mounted", lambda *args: True)
    monkeypatch.setattr(MODULE, "fstab_change", lambda *args: False)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("healthy bind must never remount")

    monkeypatch.setattr(MODULE.subprocess, "run", forbidden)
    assert MODULE.reconcile({"source": str(source), "target": str(target), "apply": True}) == {
        "fstab_changed": False,
        "mount_changed": False,
    }


def test_failed_mount_remains_a_failure_after_fstab_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, target = tmp_path / "consume", tmp_path / "inbox"
    source.mkdir()
    target.mkdir()
    written: list[bool] = []
    monkeypatch.setattr(MODULE, "mounted", lambda *args: False)

    def fstab(path: Path, source: Path, target: Path, apply: bool) -> bool:
        written.append(apply)
        return True

    monkeypatch.setattr(MODULE, "fstab_change", fstab)
    monkeypatch.setattr(MODULE.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1))
    with pytest.raises(MODULE.Refusal, match="after fstab convergence"):
        MODULE.reconcile({"source": str(source), "target": str(target), "apply": True})
    assert written == [True]
