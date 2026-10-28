"""Public component controller planning; owned native covers real execution."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_voice_memo_inbox import deploy as api
from ops_deploy.testing import run_deploy_fake
from tests.test_daybook_inbox_declaration import config, secrets


@pytest.fixture
def source(tmp_path: Path) -> tuple[SourceTree, Path]:
    root = tmp_path / "source"
    root.mkdir()
    (root / "src/daybook").mkdir(parents=True)
    (root / "src/daybook/__init__.py").write_text("# owned inert source\n")
    (root / "pyproject.toml").write_text("# owned project\n")
    (root / "uv.lock").write_text("# owned lock\n")
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}

    def git(*args: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(root), *args], capture_output=True, text=True, env=environment, check=True
        ).stdout.strip()

    git("init", "--quiet", "--template=")
    git("add", ".")
    git("-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "owned")
    revision = git("rev-parse", "HEAD")
    git("update-ref", "refs/remotes/origin/main", revision)
    bundle = tmp_path / "source.bundle"
    git("bundle", "create", str(bundle), "refs/remotes/origin/main")
    return SourceTree(root, revision), bundle


def state(**values: bool) -> dict[str, bool]:
    return {
        "source_current": True,
        "directories_current": True,
        "resources_current": True,
        "install_resources_current": True,
        "runtime_stopped": False,
        "quiescent": False,
        **values,
    }


def test_current_keeper_has_only_pure_component_verify_no_stop_source_or_app_call(
    source: tuple[SourceTree, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    tree, bundle = source
    cfg = config(daybook_voice_memo_inbox_repo_ref=tree.commit)
    monkeypatch.setattr(api, "inspect_inbox", lambda _: state())
    run = run_deploy_fake(
        api.install_daybook_inbox,
        cfg,
        secrets(),
        tree,
        bundle,
        responses={"uname -s": ["Darwin"], "/usr/bin/id -u fixture": ["501"]},
    )
    assert run.succeeded, run.error
    assert len(run.ops) == 1
    assert len(run.mutating_changed_ops) == 0
    assert run.uploaded_paths == []
    assert run.fish_unsafe_commands == []


def test_noncurrent_keeper_refuses_before_preparation_upload_stop_or_app_call(
    source: tuple[SourceTree, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    tree, bundle = source
    monkeypatch.setattr(api, "inspect_inbox", lambda _: state(source_current=False))
    run = run_deploy_fake(
        api.install_daybook_inbox,
        config(daybook_voice_memo_inbox_repo_ref=tree.commit),
        secrets(),
        tree,
        bundle,
        responses={"uname -s": ["Darwin"], "/usr/bin/id -u fixture": ["501"]},
    )
    assert not run.succeeded
    assert "original operations runtime stop/update" in str(run.error)
    assert run.ops == []
    assert run.uploaded_paths == []


def test_fresh_stopped_install_queues_original_order_and_one_existing_identity_upload(
    source: tuple[SourceTree, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    tree, bundle = source
    monkeypatch.setattr(
        api,
        "inspect_inbox",
        lambda _: state(
            source_current=False,
            directories_current=False,
            resources_current=False,
            install_resources_current=False,
            runtime_stopped=True,
        ),
    )
    run = run_deploy_fake(
        api.install_daybook_inbox,
        config(daybook_voice_memo_inbox_repo_ref=tree.commit),
        secrets(),
        tree,
        bundle,
        responses={"uname -s": ["Darwin"], "/usr/bin/id -u fixture": ["501"], "/usr/bin/id -u": ["0"]},
    )
    assert run.succeeded, run.error
    assert len(run.mutating_changed_ops) == 8
    assert len(run.uploaded_paths) == 1
    assert run.uploaded_paths[0].endswith("/source.bundle")
    assert run.fish_unsafe_commands == []


def test_component_payload_carries_only_declared_resources_and_public_code(source: tuple[SourceTree, Path]) -> None:
    tree, bundle = source
    cfg = config(daybook_voice_memo_inbox_repo_ref=tree.commit)
    data = api.component_payload(cfg, secrets(), tree, bundle, uid=501)
    assert data["revision"] == tree.commit
    assert data["owner"] == "root"
    assert (
        data["source_hashes"]["src/daybook/__init__.py"]
        == hashlib.sha256((tree.path / "src/daybook/__init__.py").read_bytes()).hexdigest()
    )
    assert set(data["source_hashes"]) == {"src/daybook/__init__.py", "pyproject.toml", "uv.lock"}
    for forbidden in ("ledger", "source_dir", "activation_marker", "activation_proof", "recordings", "journal"):
        assert forbidden not in data
    assert "UNUSABLE-OWNED-CREDENTIAL" in json.dumps(data)  # protected stdin, never argv/log
    command = api.component_command("status")
    assert "UNUSABLE-OWNED-CREDENTIAL" not in command


def test_action_is_a_fixed_interface_not_an_arbitrary_command() -> None:
    with pytest.raises(ValueError, match="Unsupported Inbox"):
        api.component_command("voice-memos status --summary-only")


def test_stopped_but_enabled_resource_drift_selects_original_installer_postcondition(
    source: tuple[SourceTree, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    import shlex

    tree, bundle = source
    monkeypatch.setattr(
        api,
        "inspect_inbox",
        lambda _: state(resources_current=False, install_resources_current=False, runtime_stopped=True, quiescent=True),
    )
    run = run_deploy_fake(
        api.install_daybook_inbox,
        config(daybook_voice_memo_inbox_repo_ref=tree.commit),
        secrets(),
        tree,
        bundle,
        responses={"uname -s": ["Darwin"], "/usr/bin/id -u fixture": ["501"]},
    )
    assert run.succeeded, run.error
    assert len(run.mutating_changed_ops) == 1
    actions = [
        shlex.split(event.value)[-1] for event in run.events if event.phase == "execute" and event.kind == "shell"
    ]
    assert actions == ["resources", "verify-installed"]
    assert run.ops[-1].read_only is True
