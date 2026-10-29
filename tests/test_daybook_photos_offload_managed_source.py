"""Real owned Git source first/repeat/update, with simulated root/ACL metadata.

These tests never claim a real root/user transition; the disposable native
fixture supplies that proof. Git and every protected/outside byte are real.
"""

from __future__ import annotations

import grp
import hashlib
import os
import runpy
import stat
import subprocess
import sys
import types
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest


@pytest.fixture
def source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    package = "ops_deploy.services.daybook_photos_offload"
    module = runpy.run_path(str(files(package).joinpath("files/photos_source.py")))
    managed = tmp_path / "Daybook/photos-offload"
    root = managed / "daybook"
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}

    def git(path: Path, *args: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(path), *args], env=env, capture_output=True, text=True, check=True
        ).stdout.strip()

    git(upstream, "init", "--quiet", "--template=", "-b", "main")
    (upstream / "source.py").write_text("# OWNED code never imported\n")
    (upstream / ".gitignore").write_text(".venv/\n")
    git(upstream, "add", ".")
    git(upstream, "-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "first")
    data = {
        "checkout": str(root),
        "bundle": str(managed / "source.bundle"),
        "attestation": str(managed / "managed-v1"),
        "revision": git(upstream, "rev-parse", "HEAD"),
        "system_group": grp.getgrgid(os.getgid()).gr_name,
    }
    fs = types.ModuleType("ops_photos_filesystem")

    def ensure(row: dict[str, Any]) -> None:
        path = Path(row["path"])
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(row["mode"])

    def put(row: dict[str, Any]) -> None:
        path = Path(row["path"])
        path.write_text(row["content"])
        path.chmod(row["mode"])

    fs.ensure_directory = ensure  # type: ignore[attr-defined]
    fs.put_resource = put  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, fs.__name__, fs)
    module["prepare_ancestors"].__globals__["FIXED_ANCESTORS"] = (str(tmp_path),)
    base: Any = module["PhotosProbes"]

    class Probes(base):  # type: ignore[misc]
        def __init__(self) -> None:
            self.data = data
            self.commands: list[list[str]] = []

        def root_info(self, info: Any) -> Any:
            if info is None:
                return None
            return SimpleNamespace(
                **{
                    name: (0 if name == "st_uid" else getattr(info, name))
                    for name in (
                        "st_dev",
                        "st_ino",
                        "st_size",
                        "st_mtime_ns",
                        "st_ctime_ns",
                        "st_mode",
                        "st_uid",
                        "st_gid",
                        "st_nlink",
                    )
                }
            )

        def info(self, path: Any) -> Any:
            result = self.root_info(module["metadata"](path))
            if Path(path).is_relative_to(root) and not Path(path).is_relative_to(root / ".venv") and root.exists():
                assert result is not None, ("missing enumerated Git entry", str(path))
                assert module["protected"](result, directory=stat.S_ISDIR(result.st_mode)), (
                    "unsafe enumerated Git entry",
                    str(path),
                    vars(result),
                )
            return result

        def fstat(self, descriptor: int) -> Any:
            return self.root_info(os.fstat(descriptor))

        def acl_free(self, path: Any) -> bool:
            return True

        def run(self, argv: list[str], *, user: bool = False, managed: bool = False) -> Any:
            self.commands.append(argv)
            return subprocess.run(argv, env=env, capture_output=True)

    class Controls:
        def __init__(self) -> None:
            self.quiet = True

        def require_quiescent(self) -> None:
            if not self.quiet:
                raise RuntimeError("OWNED Photos still active")

    def bundle() -> None:
        ensure({"path": str(managed), "mode": 0o755})
        path = Path(data["bundle"])
        path.unlink(missing_ok=True)
        git(upstream, "bundle", "create", str(path), "refs/heads/main")
        path.chmod(0o600)
        data.update(
            revision=git(upstream, "rev-parse", "HEAD"), bundle_sha256=hashlib.sha256(path.read_bytes()).hexdigest()
        )

    bundle()
    return SimpleNamespace(
        module=module,
        data=data,
        root=root,
        upstream=upstream,
        git=git,
        bundle=bundle,
        probes=Probes(),
        controls=Controls(),
    )


def converge(c: Any) -> Any:
    with patch("os.geteuid", return_value=0):
        return c.module["converge_source"](c.data, c.probes, c.controls)


def test_original_clone_fetch_detach_preserves_git_and_gui_venv(source: Any) -> None:
    c = source
    assert converge(c) == {"source_changed": True}
    assert c.module["check_checkout"](c.data, c.probes)
    git_inode = (c.root / ".git").stat().st_ino
    venv = c.root / ".venv"
    venv.mkdir()
    marker = venv / "user-owned-code-never-walked"
    marker.write_text("OWNED state-free environment continuity")
    marker.chmod(0o666)
    venv_inode = venv.stat().st_ino
    (c.upstream / "source.py").write_text("# OWNED next Main code never imported\n")
    c.git(c.upstream, "add", ".")
    c.git(c.upstream, "-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "second")
    c.bundle()
    assert converge(c) == {"source_changed": True}
    assert (c.root / ".git").stat().st_ino == git_inode
    assert venv.stat().st_ino == venv_inode
    assert marker.read_text() == "OWNED state-free environment continuity"
    assert converge(c) == {"source_changed": False}
    assert c.git(c.root, "rev-parse", "HEAD") == c.data["revision"]
    assert any("clone" in args and "--no-checkout" in args and "--branch" in args for args in c.probes.commands)
    mutations = [args for args in c.probes.commands if any(verb in args for verb in ("clone", "fetch", "checkout"))]
    assert mutations
    assert all("maintenance.auto=false" in args and "gc.auto=0" in args for args in mutations)
    assert any(
        args[-5:] == ["fetch", "--no-tags", "--force", "origin", "refs/heads/main"] for args in c.probes.commands
    )


def test_existing_missing_attestation_refuses_before_fetch(source: Any) -> None:
    c = source
    converge(c)
    Path(c.data["attestation"]).unlink()
    before = (c.root / "source.py").read_bytes(), (c.root / ".git").stat().st_ino
    c.probes.commands.clear()
    with pytest.raises(c.module["PhotosSourceError"], match="attestation_missing"):
        converge(c)
    assert before == ((c.root / "source.py").read_bytes(), (c.root / ".git").stat().st_ino)
    assert not any("fetch" in args or "checkout" in args for args in c.probes.commands)


def test_own_active_label_refuses_before_any_prep_or_git(source: Any) -> None:
    c = source
    c.controls.quiet = False
    with pytest.raises(RuntimeError, match="Photos still active"):
        converge(c)
    assert not c.root.exists()
    assert not c.probes.commands


def test_bundle_wrong_main_or_link_refuses_before_clone(source: Any) -> None:
    c = source
    c.data["revision"] = "f" * 40
    with pytest.raises(c.module["PhotosSourceError"], match="bundle_wrong_main"):
        converge(c)
    assert not c.root.exists()
    path = Path(c.data["bundle"])
    path.unlink()
    path.symlink_to(c.upstream / "source.py")
    with pytest.raises(c.module["PhotosSourceError"], match="linked_path"):
        converge(c)
    assert not c.root.exists()


def test_same_main_bundle_representation_does_not_force_source_drift(source: Any) -> None:
    c = source
    converge(c)
    original = Path(c.data["bundle"]).read_bytes()
    alternate = c.root.parent.parent.parent / "same-main-v3.bundle"
    c.git(c.upstream, "bundle", "create", "--version=3", str(alternate), "refs/heads/main")
    assert alternate.read_bytes() != original
    c.data["bundle_sha256"] = hashlib.sha256(alternate.read_bytes()).hexdigest()
    # This is a freshly repackaged controller representation, not a transfer of
    # the persisted bundle. Head+protected metadata determine currentness;
    # the independent upload predicate still requires its own exact digest.
    c.module["require_bundle"](c.data, c.probes)
    assert c.module["check_checkout"](c.data, c.probes)
    assert Path(c.data["bundle"]).read_bytes() == original
