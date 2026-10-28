"""Real Git/source proofs preceding the protected Inbox replacement boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.daybook_voice_memo_inbox.config import PACKAGE


@pytest.fixture
def source() -> Any:
    spec = importlib.util.spec_from_file_location(
        "owned_inbox_source", str(files(PACKAGE).joinpath("files/inbox_source.py"))
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )
    return result.stdout.strip()


@pytest.fixture
def checkout(tmp_path: Path) -> tuple[Path, Path, str, str]:
    path = tmp_path.resolve() / "checkout"
    path.mkdir()
    git(path, "init", "--quiet", "--template=")
    (path / "src/daybook").mkdir(parents=True)
    (path / "src/daybook/__init__.py").write_text("# owned code\n")
    (path / "pyproject.toml").write_text("# owned project\n")
    (path / "uv.lock").write_text("# owned lock\n")
    (path / ".gitignore").write_text(".venv/\n")
    git(path, "add", ".")
    git(path, "-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "first")
    old = git(path, "rev-parse", "HEAD")
    (path / "src/daybook/__init__.py").write_text("# owned desired code\n")
    git(path, "add", ".")
    git(path, "-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "desired")
    desired = git(path, "rev-parse", "HEAD")
    bundle = tmp_path.resolve() / "source.bundle"
    git(path, "update-ref", "refs/remotes/origin/main", desired)
    git(path, "bundle", "create", str(bundle), "refs/remotes/origin/main")
    git(path, "checkout", "--detach", old)
    (path / ".venv/bin").mkdir(parents=True)
    (path / ".venv/bin/python").write_bytes(b"OWNED-PROTECTED-INTERPRETER")
    return path, bundle, old, desired


def protected(path: Path) -> dict[str, tuple[int, int, int, bytes]]:
    return {
        str(p): (p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_ctime_ns, p.read_bytes())
        for p in [path / "src/daybook/__init__.py", path / ".venv/bin/python"]
    }


def test_real_bundle_proof_leaves_old_protected_tree_unchanged(
    source: Any, checkout: tuple[Path, Path, str, str]
) -> None:
    path, bundle, old, desired = checkout
    before = protected(path)
    assert source.installed_revision(path) == old
    source.require_valid_bundle(bundle, desired, path)
    source.require_clean_checkout(path)
    assert source.installed_revision(path) == old
    assert protected(path) == before


def test_wrong_revision_refuses_before_any_protected_source_replacement(
    source: Any, checkout: tuple[Path, Path, str, str]
) -> None:
    path, bundle, old, _desired = checkout
    before = protected(path)
    with pytest.raises(source.InboxSourceError, match="inbox_source_bundle_wrong_revision"):
        source.require_valid_bundle(bundle, old, path)
    assert protected(path) == before


def test_unreadable_head_refuses_with_original_fda_interpreter_preserved(
    source: Any, checkout: tuple[Path, Path, str, str]
) -> None:
    path, _bundle, _old, _desired = checkout
    (path / ".git/HEAD").write_text("ref: refs/heads/absent\n")
    before = protected(path)
    with pytest.raises(source.InboxSourceError, match="inbox_source_installed_revision_unreadable"):
        source.installed_revision(path)
    assert protected(path) == before


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "missing"])
def test_unsafe_bundle_never_opens_protected_runtime_for_changes(
    source: Any, checkout: tuple[Path, Path, str, str], kind: str
) -> None:
    path, bundle, _old, desired = checkout
    before = protected(path)
    declared = bundle.with_name("other.bundle")
    if kind == "symlink":
        declared.symlink_to(bundle)
    elif kind == "hardlink":
        os.link(bundle, declared)
    with pytest.raises(source.InboxSourceError, match=r"inbox_source_bundle_(unsafe|unavailable)"):
        source.require_valid_bundle(declared, desired, path)
    assert protected(path) == before


def test_dirty_checkout_is_reported_without_private_paths_or_body(
    source: Any, checkout: tuple[Path, Path, str, str]
) -> None:
    path, _bundle, _old, _desired = checkout
    (path / "private-untracked-name").write_bytes(b"UNUSABLE-OWNED-CONTENT")
    with pytest.raises(source.InboxSourceError, match="inbox_source_checkout_modified") as error:
        source.require_clean_checkout(path)
    assert "private-untracked-name" not in str(error.value)
    assert "OWNED-CONTENT" not in str(error.value)


def test_exact_declared_code_and_lock_hashes_without_imports_or_record_reads(
    source: Any, checkout: tuple[Path, Path, str, str]
) -> None:
    path, _bundle, _old, _desired = checkout
    names = ["src/daybook/__init__.py", "pyproject.toml", "uv.lock"]
    expected = {name: hashlib.sha256((path / name).read_bytes()).hexdigest() for name in names}
    assert source.code_matches(path, expected) is True
    (path / "src/daybook/__init__.py").write_text("# changed source\n")
    assert source.code_matches(path, expected) is False
    with pytest.raises(source.InboxSourceError, match="inbox_source_manifest_incomplete"):
        source.code_matches(path, {})
    with pytest.raises(source.InboxSourceError, match="inbox_source_manifest_invalid"):
        source.code_matches(path, {"pyproject.toml": "a" * 64, "uv.lock": "b" * 64, "../../record": "a" * 64})


def control_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    import sys

    spec = importlib.util.spec_from_file_location(
        "ops_inbox_controls", str(files(PACKAGE).joinpath("files/inbox_controls.py"))
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setitem(sys.modules, "ops_inbox_controls", module)
    return module


def test_real_bundle_checkout_transition_and_repeat_use_original_stopped_dependency(
    source: Any, checkout: tuple[Path, Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_daybook_inbox_controls import DATA, Probes

    control_module(monkeypatch)
    path, bundle, _old, desired = checkout
    data = {**DATA, "checkout": str(path), "bundle": str(bundle), "revision": desired}
    source.converge_checkout(data, Probes())
    assert source.installed_revision(path) == desired
    assert (path / "src/daybook/__init__.py").read_text() == "# owned desired code\n"
    assert not (path / ".venv/bin/python").exists()  # explicit ORIGINAL drifted-tree replacement
    current = (path / "src/daybook/__init__.py").read_bytes()
    source.converge_checkout(data, Probes())
    assert source.installed_revision(path) == desired
    assert (path / "src/daybook/__init__.py").read_bytes() == current


@pytest.mark.parametrize("active", ["keeper", "serve", "not-disabled"])
def test_runtime_or_quiescence_guard_refuses_before_protected_checkout_replacement(
    source: Any, checkout: tuple[Path, Path, str, str], monkeypatch: pytest.MonkeyPatch, active: str
) -> None:
    from tests.test_daybook_inbox_controls import DATA, Probes

    controls = control_module(monkeypatch)
    path, bundle, _old, desired = checkout
    before = protected(path)
    overrides = (
        {"keeper": (0, b"\thost-keep\n")}
        if active == "keeper"
        else (
            {"serve": (0, b"1234\n")}
            if active == "serve"
            else {"disabled": (0, b'"owned" => false\n"owned-long" => true')}
        )
    )
    with pytest.raises(controls.InboxError, match=r"inbox_(operations_runtime_still_running|label_not_disabled)"):
        source.converge_checkout(
            {**DATA, "checkout": str(path), "bundle": str(bundle), "revision": desired}, Probes(**overrides)
        )
    assert protected(path) == before


def test_controller_payload_binds_real_main_bundle_and_original_root_python_tree(
    checkout: tuple[Path, Path, str, str],
) -> None:
    from ops_deploy.core.git_source import SourceTree
    from ops_deploy.services.daybook_voice_memo_inbox.source import source_payload
    from tests.test_daybook_inbox_declaration import config

    path, bundle, _, desired = checkout
    git(path, "checkout", "--detach", desired)
    cfg = config(daybook_voice_memo_inbox_repo_ref=desired, daybook_voice_memo_inbox_repo_bundle_src=str(bundle))
    before = protected(path)
    data = source_payload(cfg, SourceTree(path, desired), bundle, uid=501)
    assert data["owner"] == "root"
    assert Path(data["python_install_dir"]) == Path(data["checkout"]).parent.parent / "python"
    assert data["revision"] == desired
    assert set(data["source_hashes"]) == {"src/daybook/__init__.py", "pyproject.toml", "uv.lock"}
    assert not {"source_dir", "state_path", "credential_path", "activation_marker_path"} & data.keys()
    assert protected(path) == before
    wrong = path.parent / "wrong.bundle"
    git(path, "update-ref", "refs/heads/owned-old", checkout[2])
    git(path, "bundle", "create", str(wrong), "refs/heads/owned-old")
    with pytest.raises(ValueError, match="declared commit"):
        source_payload(cfg, SourceTree(path, desired), wrong, uid=501)
    assert protected(path) == before


@pytest.mark.parametrize("uid", [0, -1, True])
def test_controller_payload_refuses_root_or_invalid_gui_identity_before_source_work(
    checkout: tuple[Path, Path, str, str], uid: int
) -> None:
    from ops_deploy.core.git_source import SourceTree
    from ops_deploy.services.daybook_voice_memo_inbox.source import source_payload
    from tests.test_daybook_inbox_declaration import config

    path, bundle, _, desired = checkout
    # Checkout deliberately remains old: uid refusal must precede source probes.
    cfg = config(daybook_voice_memo_inbox_repo_ref=desired)
    before = protected(path)
    with pytest.raises(ValueError, match="non-root GUI account uid"):
        source_payload(cfg, SourceTree(path, desired), bundle, uid=uid)
    assert protected(path) == before
