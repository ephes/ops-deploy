"""Actual SDK caller, original owner connection and explicit managed --help."""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pyinfra.connectors.fake import FakeConnector

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_photos_archive_sync import DaybookPhotosArchiveSyncConfig
from ops_deploy.services.daybook_photos_archive_sync import deploy as api
from ops_deploy.testing import run_deploy_fake
from tests.test_daybook_photos_archive_sync_config import config


@pytest.fixture
def source(tmp_path: Path) -> tuple[SourceTree, Path]:
    root = tmp_path / "controller-source"
    (root / "src/daybook").mkdir(parents=True)
    (root / "src/daybook/__init__.py").write_text("# owned inert code\n")
    (root / "pyproject.toml").write_text("# owned declaration\n")
    (root / "uv.lock").write_text("# owned lock\n")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}

    def git(*args: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(root), *args], env=env, capture_output=True, text=True, check=True
        ).stdout.strip()

    git("init", "--quiet", "--template=", "-b", "main")
    git("add", ".")
    git("-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "owned")
    commit = git("rev-parse", "HEAD")
    bundle = tmp_path / "main.bundle"
    git("bundle", "create", str(bundle), "refs/heads/main")
    return SourceTree(root, commit), bundle


def run(prepared_source: tuple[SourceTree, Path], monkeypatch: pytest.MonkeyPatch, **state: bool) -> Any:
    tree, bundle = prepared_source
    cfg = config(
        daybook_photos_archive_sync_repo_ref=tree.commit, daybook_photos_archive_sync_repo_bundle_src=str(bundle)
    )
    monkeypatch.setattr(
        api,
        "observe",
        lambda _: {
            "quiescent": True,
            "directories": True,
            "bundle": True,
            "source": True,
            "environment": True,
            "resources": True,
            **state,
        },
    )
    return run_deploy_fake(
        api.install_daybook_photos_archive_sync,
        cfg,
        tree,
        bundle,
        responses={"uname -s": ["Darwin"], "/usr/bin/id -un": ["fixture"], "/usr/bin/id -u": ["501"]},
    )


def actions(result: Any) -> list[str]:
    return [
        shlex.split(event.value)[-1]
        for event in result.events
        if event.phase == "execute" and event.kind == "shell" and "<archive-component>" in event.value
    ]


def test_current_disabled_repeat_keeps_real_managed_cli_smoke(source: Any, monkeypatch: Any) -> None:
    result = run(source, monkeypatch)
    assert result.succeeded, result.error
    assert actions(result) == ["smoke", "verify"]
    assert len(result.mutating_changed_ops) == 1
    assert result.uploaded_paths == []
    assert result.ops[-1].read_only


def test_fresh_install_uses_original_order_and_never_activates(source: Any, monkeypatch: Any) -> None:
    result = run(
        source,
        monkeypatch,
        **dict.fromkeys(("quiescent", "directories", "bundle", "source", "environment", "resources"), False),
    )
    assert result.succeeded, result.error
    assert actions(result) == ["quiesce", "directories", "source", "environment", "smoke", "resources", "verify"]
    assert len(result.uploaded_paths) == 1
    assert not result.fish_unsafe_commands


def test_disabled_flag_is_inert_without_source_or_any_fact() -> None:
    result = run_deploy_fake(api.install_daybook_photos_archive_sync, DaybookPhotosArchiveSyncConfig())
    assert result.succeeded
    assert result.ops == []
    assert result.events == []


def test_original_owner_path_clears_every_inherited_privilege_switch(source: Any, monkeypatch: Any) -> None:
    tree, bundle = source
    cfg = config(
        daybook_photos_archive_sync_repo_ref=tree.commit, daybook_photos_archive_sync_repo_bundle_src=str(bundle)
    )
    monkeypatch.setattr(
        api,
        "observe",
        lambda _: {
            "quiescent": True,
            "directories": True,
            "bundle": False,
            "source": True,
            "environment": True,
            "resources": True,
        },
    )
    original_shell, original_put = FakeConnector.run_shell_command, FakeConnector.put_file
    calls = []

    def direct(kwargs: Any) -> None:
        assert all(kwargs.get(key) in {False, None} for key in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs.get(key) in {"", None} for key in ("_sudo_user", "_doas_user", "_dzdo_user", "_su_user"))

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        direct(kwargs)
        calls.append("shell")
        return original_shell(connector, *args, **kwargs)

    def put(connector: Any, *args: Any, **kwargs: Any) -> Any:
        direct(kwargs)
        calls.append("upload")
        return original_put(connector, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", shell)
    monkeypatch.setattr(FakeConnector, "put_file", put)
    result = run_deploy_fake(
        api.install_daybook_photos_archive_sync,
        cfg,
        tree,
        bundle,
        responses={"uname -s": ["Darwin"], "/usr/bin/id -un": ["fixture"], "/usr/bin/id -u": ["501"]},
        _sudo=True,
        _sudo_user="root",
        _doas=True,
        _doas_user="root",
        _dzdo=True,
        _dzdo_user="root",
        _su_user="root",
    )
    assert result.succeeded, result.error
    assert "shell" in calls
    assert calls.count("upload") == 1


@pytest.mark.parametrize(("name", "uid"), [("root", "0"), ("other", "501"), ("fixture", "0")])
def test_original_wrong_connecting_identity_refuses_before_source_or_operations(
    source: Any, name: str, uid: str
) -> None:
    tree, bundle = source
    cfg = config(
        daybook_photos_archive_sync_repo_ref=tree.commit, daybook_photos_archive_sync_repo_bundle_src=str(bundle)
    )
    result = run_deploy_fake(
        api.install_daybook_photos_archive_sync,
        cfg,
        tree,
        bundle,
        responses={"uname -s": ["Darwin"], "/usr/bin/id -un": [name], "/usr/bin/id -u": [uid]},
    )
    assert not result.succeeded
    assert result.ops == []
    assert result.uploaded_paths == []
