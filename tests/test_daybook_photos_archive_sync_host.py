"""Owned Git/interpreter transitions and data-body refusal controls."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import types
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

PACKAGE = "ops_deploy.services.daybook_photos_archive_sync"


@pytest.fixture
def module(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    for name, package, resource in (
        ("ops_archive_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
        ("ops_archive_controls", "ops_deploy.services.daybook_photos_offload", "files/photos_controls.py"),
    ):
        value = types.ModuleType(name)
        exec(compile(files(package).joinpath(resource).read_text(), "<owned-context>", "exec"), value.__dict__)
        monkeypatch.setitem(sys.modules, name, value)
    spec = importlib.util.spec_from_file_location(
        "owned_archive", str(files(PACKAGE).joinpath("files/archive_host.py"))
    )
    assert spec is not None
    assert spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@pytest.fixture
def archive(module: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    uid, gid = os.getuid(), os.getgid()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(module.pwd, "getpwnam", lambda _: types.SimpleNamespace(pw_uid=uid, pw_name="fixture"))
    monkeypatch.setattr(module.grp, "getgrnam", lambda _: types.SimpleNamespace(gr_gid=gid))
    monkeypatch.setattr(
        module,
        "PhotosControls",
        lambda _: types.SimpleNamespace(
            require_quiescent=lambda: None,
            snapshot=lambda **_: {"domain_available": True, "disabled": True, "loaded": False, "known_absent": True},
        ),
    )
    install = home / "install"
    install.mkdir(mode=0o700)
    data = {
        "service_user": "fixture",
        "service_group": "staff",
        "service_home": str(home),
        "uid": uid,
        "checkout_path": str(install / "daybook"),
        "venv_path": str(install / "daybook/.venv"),
        "install_root": str(install),
        "repo_bundle_path": str(install / "source.bundle"),
        "runtime_dir": str(home / "runtime"),
        "config_dir": str(home / "config"),
        "log_dir": str(home / "runtime/logs"),
        "launchd_label": "example.owned.archive",
        "launchd_plist_path": str(home / "Library/LaunchAgents/owned.plist"),
        "path": os.environ.get("PATH", "/usr/bin:/bin"),
        "python_version": "3.14.7",
        "uv_bin": "/owned/uv",
        "resources": [],
        "source_hashes": {},
        "repo_ref": "a" * 40,
    }
    return module.Archive(data)


def git(root: Path, *argv: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *argv],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    ).stdout.strip()


def bundle(archive: Any, tmp_path: Path) -> Path:
    source = tmp_path / "controller"
    source.mkdir()
    (source / "owned.py").write_text("# owned inert source\n")
    (source / ".gitignore").write_text(".venv/\n")
    git(source, "init", "--quiet", "--template=", "-b", "main")
    git(source, "add", ".")
    git(source, "-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "owned")
    git(source, "bundle", "create", str(archive.bundle), "refs/heads/main")
    archive.bundle.chmod(0o600)
    archive.data["repo_ref"] = git(source, "rev-parse", "HEAD")
    archive.data["bundle_sha256"] = hashlib.sha256(archive.bundle.read_bytes()).hexdigest()
    archive.data["source_hashes"] = {"owned.py": hashlib.sha256((source / "owned.py").read_bytes()).hexdigest()}
    return source


def test_original_clone_exact_detached_ref_and_dirty_refusal_preserve_bytes(
    module: Any, archive: Any, tmp_path: Path
) -> None:
    bundle(archive, tmp_path)
    archive.source()
    assert archive.source_current()
    assert git(archive.root, "rev-parse", "HEAD") == archive.data["repo_ref"]
    (archive.root / "owned.py").write_text("# OWNED user modification\n")
    with pytest.raises(module.ArchiveError, match="dirty_checkout_refused"):
        archive.source()
    assert (archive.root / "owned.py").read_text() == "# OWNED user modification\n"


def test_original_interrupted_no_index_clone_resumes_without_reclone(archive: Any, tmp_path: Path) -> None:
    bundle(archive, tmp_path)
    subprocess.run(
        ["/usr/bin/git", "clone", "--no-checkout", "--branch", "main", str(archive.bundle), str(archive.root)],
        capture_output=True,
        check=True,
    )
    assert not (archive.root / ".git/index").exists()
    inode = (archive.root / ".git").stat().st_ino
    archive.source()
    assert archive.source_current()
    assert (archive.root / ".git").stat().st_ino == inode


def test_existing_empty_directory_supports_original_clone(archive: Any, tmp_path: Path) -> None:
    bundle(archive, tmp_path)
    archive.root.mkdir()
    archive.source()
    assert archive.source_current()


def test_nonstarting_environment_is_rebuilt_without_touching_other_paths(
    module: Any, archive: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive.venv.mkdir(parents=True)
    marker = archive.venv / "owned-stale"
    marker.write_text("OWNED stateless environment marker")
    protected = archive.root / "retained.py"
    protected.write_text("# OWNED retained source")
    monkeypatch.setattr(archive, "source_current", lambda: True)
    monkeypatch.setattr(
        archive, "run", lambda *a, **kw: (_ for _ in ()).throw(module.ArchiveError("archive_tool_unavailable"))
    )
    seen = []

    def sync(argv: list[str], **kwargs: Any) -> None:
        assert not marker.exists()
        seen.append(argv)

    monkeypatch.setattr(archive, "require", sync)
    monkeypatch.setattr(archive, "interpreter_current", lambda: True)
    monkeypatch.setattr(archive, "clean", lambda: None)
    archive.environment()
    assert seen[0][1:4] == ["sync", "--frozen", "--no-dev"]
    assert protected.read_text() == "# OWNED retained source"


def test_observation_never_opens_ledger_photo_database_folder_map_or_logs(
    module: Any, archive: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(archive, "validate_paths", lambda: None)
    monkeypatch.setattr(archive, "tools", lambda: None)
    monkeypatch.setattr(archive, "directories", lambda: [])
    monkeypatch.setattr(archive, "source_current", lambda: True)
    monkeypatch.setattr(archive, "environment_current", lambda: True)
    monkeypatch.setattr(archive, "bundle_current", lambda: True)
    original = os.open

    def guarded(path: Any, *args: Any, **kwargs: Any) -> int:
        if Path(str(path)).name in {
            "ledger.json",
            "folder-map.json",
            "Photos.sqlite",
            "archive-sync.log",
            "archive-sync.err.log",
        }:
            pytest.fail("observation opened a protected synthetic data-body path")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", guarded)
    assert all(archive.status().values())
