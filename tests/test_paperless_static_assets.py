"""Exact original recursive frontend-copy semantics on owned synthetic files."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "paperless_static_assets", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/static_assets.py"
)
assert SPEC is not None
assert SPEC.loader is not None
assets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assets)


def metadata(path: Path) -> tuple[int, int, int, int]:
    value = path.stat()
    return value.st_mode, value.st_ino, value.st_mtime_ns, value.st_ctime_ns


@pytest.mark.parametrize("mode", [0o600, 0o644, 0o664, 0o755])
def test_matching_frontend_mode_is_not_a_collection_trigger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"same compiled program")
    target = tmp_path / "static"
    target.mkdir()
    output = target / "frontend.js"
    output.write_bytes(source.read_bytes())
    output.chmod(mode)
    before = metadata(output)
    monkeypatch.setattr(assets, "expected_files", lambda _: (target, {Path(output.name): (source, True)}))
    assert assets.inspect_static({}) == {"pending": False}
    assert metadata(output) == before
    output.write_bytes(b"corrupt program")
    assert assets.inspect_static({}) == {"pending": True}
    output.unlink()
    assert assets.inspect_static({}) == {"pending": True}


def test_overlay_preserves_same_and_copies_changed_missing_source_metadata(tmp_path: Path) -> None:
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    output.mkdir(mode=0o700)
    for name, body in (("same", b"same"), ("changed", b"new longer"), ("missing", b"missing")):
        (source / name).write_bytes(body)
        (source / name).chmod(0o644)
    (output / "same").write_bytes(b"same")
    (output / "same").chmod(0o664)
    (output / "changed").write_bytes(b"old")
    (output / "changed").chmod(0o600)
    same = metadata(output / "same")
    nested = source / "new-directory"
    nested.mkdir(mode=0o750)
    (nested / "child").write_bytes(b"new child")
    (nested / "child").chmod(0o640)
    os.utime(nested / "child", ns=(123456789, 123456789))
    assets.overlay_frontend(source, output)
    assert metadata(output / "same") == same
    assert output.stat().st_mode & 0o7777 == 0o755
    for name in ("changed", "missing"):
        assert (output / name).read_bytes() == (source / name).read_bytes()
        assert (output / name).stat().st_mode & 0o7777 == 0o644
    assert (output / "new-directory").stat().st_mode & 0o7777 == 0o750
    child = output / "new-directory/child"
    assert child.stat().st_mode & 0o7777 == 0o640
    assert child.stat().st_mtime_ns == (nested / "child").stat().st_mtime_ns
    before = {str(p.relative_to(output)): metadata(p) for p in output.rglob("*")}
    assets.overlay_frontend(source, output)
    assert {str(p.relative_to(output)): metadata(p) for p in output.rglob("*")} == before


def test_static_destination_symlink_still_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"same")
    target = tmp_path / "target"
    target.mkdir()
    (target / "link").symlink_to(source)
    monkeypatch.setattr(assets, "expected_files", lambda _: (target, {Path("link"): (source, True)}))
    with pytest.raises(OSError, match="Too many levels"):
        assets.inspect_static({})
