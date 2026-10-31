"""Owned Linux filesystem primitive; no Home Assistant/device/host qualification."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture
def program() -> ModuleType:
    source = Path(__file__).parents[1] / "src/ops_deploy/services/homeassistant/files/venv_ownership.py"
    spec = importlib.util.spec_from_file_location("owned_ha_venv_permissions", source)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def metadata(root: Path) -> dict[str, tuple[int, ...]]:
    return {
        str(p.relative_to(root)): (s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        for p in [root, *root.rglob("*")]
        for s in [p.lstat()]
    }


def test_current_tree_preserves_all_metadata(tmp_path: Path, program: ModuleType) -> None:
    root = tmp_path / "venv"
    root.mkdir()
    (root / "module.py").write_text("synthetic owned package\n")
    (root / "module.py").chmod(0o640)
    (root / "link").symlink_to("module.py")
    before = metadata(root)
    assert program.converge(str(root), os.getuid(), os.getgid(), False) == "current"
    assert program.converge(str(root), os.getuid(), os.getgid(), True) == "current"
    assert metadata(root) == before


@pytest.mark.parametrize("kind", ["file", "cycle", "filesystem-root"])
def test_invalid_root_or_cycle_fails_before_changes(tmp_path: Path, program: ModuleType, kind: str) -> None:
    root = tmp_path / "venv"
    if kind == "file":
        root.write_text("owned")
    elif kind == "filesystem-root":
        root.symlink_to("/")
    else:
        root.mkdir()
        (root / "cycle").symlink_to(root)
    before = root.lstat()
    with pytest.raises(ValueError, match="environment ownership"):
        program.converge(str(root), os.getuid(), os.getgid(), True)
    after = root.lstat()
    assert (after.st_mode, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_mode,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )


@pytest.mark.skipif(sys.platform != "linux" or os.geteuid() != 0, reason="owned Linux container root fixture only")
def test_descendant_drift_links_targets_and_strict_repeat(tmp_path: Path, program: ModuleType) -> None:
    root = tmp_path / "venv"
    root.mkdir()
    os.chown(root, 1234, 1235)
    child = root / "package"
    child.mkdir()
    (child / "code.py").write_text("owned package\n")
    (child / "code.py").chmod(0o640)
    os.link(child / "code.py", child / "hardlink.py")
    external = tmp_path / "owned-python-base"
    external.mkdir()
    (external / "python").write_text("owned interpreter marker\n")
    (root / "bin").symlink_to(external)
    (root / "dangling").symlink_to("missing")
    before = metadata(tmp_path)
    assert program.converge(str(root), 1234, 1235, False) == "pending"
    assert metadata(tmp_path) == before
    assert program.converge(str(root), 1234, 1235, True) == "changed"
    for path in [
        root,
        child,
        child / "code.py",
        child / "hardlink.py",
        root / "bin",
        root / "dangling",
        external,
        external / "python",
    ]:
        assert (path.lstat().st_uid, path.lstat().st_gid) == (1234, 1235)
        relative = str(path.relative_to(tmp_path))
        assert (path.lstat().st_mode, path.lstat().st_mtime_ns) == (before[relative][0], before[relative][4])
    after = metadata(tmp_path)
    assert program.converge(str(root), 1234, 1235, False) == "current"
    assert program.converge(str(root), 1234, 1235, True) == "current"
    assert metadata(tmp_path) == after


@pytest.mark.skipif(sys.platform != "linux" or os.geteuid() != 0, reason="owned Linux container root fixture only")
def test_original_missing_ancestors_and_root_link_follow(tmp_path: Path, program: ModuleType) -> None:
    root = tmp_path / "new-parent/venv"
    link = tmp_path / "configured-link"
    link.symlink_to(root)
    assert program.converge(str(link), 1234, 1235, False) == "pending"
    assert not root.exists()
    assert program.converge(str(link), 1234, 1235, True) == "changed"
    for path in (root.parent, root):
        assert (path.stat().st_uid, path.stat().st_gid) == (1234, 1235)
    # Original root follow=true changes the target, not the root link owner.
    assert link.lstat().st_uid == 0


@pytest.mark.skipif(sys.platform != "linux" or os.geteuid() != 0, reason="owned Linux container root fixture only")
def test_original_link_chain_keeps_recursive_target_link_identity(tmp_path: Path, program: ModuleType) -> None:
    root = tmp_path / "venv"
    root.mkdir()
    outside = tmp_path / "base"
    outside.mkdir()
    (outside / "code").write_text("owned")
    middle = tmp_path / "middle"
    middle.symlink_to(outside)
    (root / "linked").symlink_to(middle)
    assert program.converge(str(root), 1234, 1235, True) == "changed"
    assert middle.lstat().st_uid == 1234
    assert (outside / "code").stat().st_uid == 1234
    # Original recursive function lchowns the intermediate link, while os.walk
    # follows that root to its contents; it does not lchown the final base root.
    assert outside.stat().st_uid == 0
    after = metadata(tmp_path)
    assert program.converge(str(root), 1234, 1235, True) == "current"
    assert metadata(tmp_path) == after


def test_original_missing_root_below_dangling_ancestor_is_not_repaired(tmp_path: Path, program: ModuleType) -> None:
    ancestor = tmp_path / "home"
    destination = tmp_path / "uncreated-target"
    ancestor.symlink_to(destination)
    root = ancestor / "venv"
    assert program.converge(str(root), os.getuid(), os.getgid(), False) == "pending"
    with pytest.raises(FileExistsError):
        program.converge(str(root), os.getuid(), os.getgid(), True)
    assert not destination.exists()
    assert ancestor.is_symlink()
