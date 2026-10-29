"""Owned release faults with synthetic archives; production checksum stays fixed."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import tarfile
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "paperless_release", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/release.py"
)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def archive(root: Path, monkeypatch: pytest.MonkeyPatch, *, incomplete: bool = False) -> Path:
    path = root / "paperless-ngx-v3.2.1.tar.xz"
    entries = {
        "paperless-ngx/pyproject.toml": '[project]\nname="paperless-ngx"\nversion="3.2.1"\n',
        "paperless-ngx/src/paperless/__init__.py": "# synthetic owned source\n",
    }
    if not incomplete:
        entries["paperless-ngx/src/manage.py"] = "# synthetic owned entry point\n"
    with tarfile.open(path, "w:xz") as stream:
        for name, text in entries.items():
            body = text.encode()
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(body), 0o644
            stream.addfile(item, io.BytesIO(body))
    monkeypatch.setattr(MODULE, "ARCHIVE_SHA256", hashlib.sha256(path.read_bytes()).hexdigest())
    return path


def test_first_release_and_repeat_leave_existing_tree_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive(tmp_path, monkeypatch)
    payload = {"site_root": str(tmp_path), "apply": True}
    assert MODULE.reconcile(payload) == {"release_changed": True, "current_changed": True}
    paths = [tmp_path / "paperless-ngx", *sorted((tmp_path / "paperless-ngx-v3.2.1").rglob("*"))]
    before = {str(p): (p.lstat().st_ino, p.lstat().st_mtime_ns, p.lstat().st_ctime_ns) for p in paths}
    assert MODULE.reconcile(payload) == {"release_changed": False, "current_changed": False}
    assert {str(p): (p.lstat().st_ino, p.lstat().st_mtime_ns, p.lstat().st_ctime_ns) for p in paths} == before
    assert not (tmp_path / ".paperless-ngx-v3.2.1-extract").exists()


def test_valid_staging_precedes_broken_release_and_legacy_current_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive(tmp_path, monkeypatch)
    for name in ("paperless-ngx-v3.2.1", "paperless-ngx", ".paperless-ngx-v3.2.1-extract"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "synthetic-interrupted-file").write_text("old")
    assert MODULE.reconcile({"site_root": str(tmp_path), "apply": True}) == {
        "release_changed": True,
        "current_changed": True,
    }
    assert (tmp_path / "paperless-ngx").is_symlink()
    assert MODULE.complete(tmp_path / "paperless-ngx-v3.2.1")


@pytest.mark.parametrize("fault", ["checksum", "incomplete"])
def test_failed_archive_preserves_existing_legacy_path(
    fault: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = archive(tmp_path, monkeypatch, incomplete=fault == "incomplete")
    if fault == "checksum":
        source.write_bytes(source.read_bytes() + b"corrupt")
    current = tmp_path / "paperless-ngx"
    current.mkdir()
    (current / "synthetic-old").write_text("preserved")
    with pytest.raises(MODULE.Refusal, match=r"checksum|incomplete"):
        MODULE.reconcile({"site_root": str(tmp_path), "apply": True})
    assert (current / "synthetic-old").read_text() == "preserved"
    assert not (tmp_path / ".paperless-ngx-v3.2.1-extract").exists()


def test_special_metadata_refuses_without_blocking(tmp_path: Path) -> None:
    release = tmp_path / "paperless-ngx-v3.2.1"
    release.mkdir()
    os.mkfifo(release / "pyproject.toml")
    with pytest.raises(MODULE.Refusal, match="regular"):
        MODULE.complete(release)


def test_foreign_version_symlink_is_not_overwritten(tmp_path: Path) -> None:
    (tmp_path / "paperless-ngx-v3.2.1").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(MODULE.Refusal, match="symlink"):
        MODULE.reconcile({"site_root": str(tmp_path), "apply": True})
