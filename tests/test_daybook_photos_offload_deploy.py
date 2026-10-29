"""Photos real controller entrypoint planning and actual SDK command boundaries."""

from __future__ import annotations

import inspect
import json
import os
import shlex
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pyinfra.api import DeployError
from pyinfra.api.arguments import ConnectorArguments

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_photos_offload import deploy as api
from ops_deploy.services.daybook_photos_offload.payload import component_payload
from ops_deploy.testing import run_deploy_fake
from tests.test_daybook_photos_offload_resources import config


@pytest.fixture
def source(tmp_path: Path) -> tuple[SourceTree, Path]:
    root = tmp_path / "source"
    root.mkdir()
    (root / "src/daybook").mkdir(parents=True)
    (root / "src/daybook/__init__.py").write_text("# owned inert source\n")
    (root / "pyproject.toml").write_text("# owned project\n")
    (root / "uv.lock").write_text("# owned lock\n")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}

    def git(*args: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(root), *args], env=env, capture_output=True, text=True, check=True
        ).stdout.strip()

    git("init", "--quiet", "--template=", "-b", "main")
    git("add", ".")
    git("-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "owned")
    revision = git("rev-parse", "HEAD")
    bundle = tmp_path / "source.bundle"
    git("bundle", "create", str(bundle), "refs/heads/main")
    return SourceTree(root, revision), bundle


def state(**values: bool) -> dict[str, bool]:
    return {
        "source_current": True,
        "environment_current": True,
        "directories_current": True,
        "resources_current": True,
        "quiescent": True,
        "state_current": True,
        **values,
    }


def run(
    source: tuple[SourceTree, Path], monkeypatch: pytest.MonkeyPatch, flags: dict[str, bool], *, enabled: bool = False
) -> Any:
    tree, bundle = source
    cfg = config(
        daybook_photos_offload_repo_ref=tree.commit,
        daybook_photos_offload_repo_bundle_src=str(bundle),
        daybook_photos_offload_launchd_enabled=enabled,
    )
    monkeypatch.setattr(api, "inspect_photos", lambda _: state(**flags))
    return run_deploy_fake(
        api.install_daybook_photos_offload,
        cfg,
        tree,
        bundle,
        responses={"uname -s": ["Darwin"], "/usr/bin/id -u fixture": ["501"], "/usr/bin/id -u": ["0"]},
    )


def actions(result: Any) -> list[str]:
    return [
        shlex.split(event.value)[-1] for event in result.events if event.phase == "execute" and event.kind == "shell"
    ]


def test_exact_current_disabled_install_only_queues_pure_verification(
    source: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(source, monkeypatch, {})
    assert result.succeeded, result.error
    assert actions(result) == ["verify"]
    assert len(result.ops) == 1
    assert result.ops[0].read_only
    assert result.mutating_changed_ops == []
    assert result.uploaded_paths == []
    assert result.fish_unsafe_commands == []


def test_full_fresh_original_order_upload_and_disabled_postcondition(
    source: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(source, monkeypatch, {key: False for key in state()})
    assert result.succeeded, result.error
    selected = actions(result)
    assert selected[2].startswith("/private/var/tmp/ops-deploy-daybook-photos-")
    assert selected[2].endswith("/source.bundle")  # actual SDK chmod stage
    assert selected[:2] + selected[3:] == [
        "quiesce",
        "prepare-transfer",
        "source",
        "python",
        "directories",
        "resources",
        "verify",
    ]
    assert len(result.uploaded_paths) == 1
    assert len(result.mutating_changed_ops) == 7
    assert result.ops[-1].read_only
    assert result.fish_unsafe_commands == []


def test_resource_only_drift_does_not_sync_source_or_venv(source: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    result = run(source, monkeypatch, {"resources_current": False})
    assert result.succeeded, result.error
    assert actions(result) == ["resources", "verify"]
    assert len(result.mutating_changed_ops) == 1
    assert result.uploaded_paths == []


def test_optional_activation_is_after_original_resources_and_failure_checks(
    source: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(source, monkeypatch, {"resources_current": False, "quiescent": False}, enabled=True)
    assert result.succeeded, result.error
    assert actions(result) == ["quiesce", "resources", "activate", "verify"]
    assert result.uploaded_paths == []


def test_current_enabled_state_does_not_quiesce_or_reactivate(source: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    result = run(source, monkeypatch, {"quiescent": False}, enabled=True)
    assert result.succeeded, result.error
    assert actions(result) == ["verify"]


def test_payload_is_original_generated_code_and_declared_metadata_only(source: Any) -> None:
    tree, bundle = source
    cfg = config(daybook_photos_offload_repo_ref=tree.commit, daybook_photos_offload_repo_bundle_src=str(bundle))
    data = component_payload(cfg, tree, bundle, uid=501)
    assert data["revision"] == tree.commit
    assert data["library"] == "/Users/fixture/Pictures/Photos Library.photoslibrary"
    assert data["launchd_enabled"] is False
    assert len(data["resources"]) == 2
    assert len(data["directories"]) == 4
    assert len(data["logs"]) == 2
    assert not {"ledger", "source_dir", "activation_marker", "recordings", "journal"}.intersection(data)
    assert "ledger.json" in data["resources"][0]["content"]  # literal configured path, never its body
    assert data["bundle_sha256"] not in api.component_command("status")
    assert "photos_source" in api.component_command("status")
    assert not any(name in api.component_command("status") for name in ("ops_daybook_observer", "ops_inbox_controls"))
    with pytest.raises(ValueError, match="Unsupported Photos"):
        api.component_command("offload-reconcile")
    with pytest.raises(ValueError, match="Unsupported Photos"):
        api.component_command("source", user="fixture")
    assert shlex.split(api.component_command("resources", user="fixture"))[:8] == [
        "/usr/bin/sudo",
        "-n",
        "-H",
        "-i",
        "-u",
        "fixture",
        "--",
        "/usr/bin/python3",
    ]


def test_actual_sdk_upload_and_chmod_clear_all_seven_inherited_escalation_fields() -> None:
    observed: list[dict[str, Any]] = []

    def upload(*args: Any, **kwargs: Any) -> bool:
        observed.append(kwargs)
        return True

    def shell(*args: Any, **kwargs: Any) -> tuple[bool, object]:
        observed.append(kwargs)
        return True, object()

    target = SimpleNamespace(put_file=upload, run_shell_command=shell)
    sdk_state = SimpleNamespace(print_output=False, print_input=False)
    for command in inspect.unwrap(api.upload_photos_bundle)("/owned/source.bundle", "/owned/private/source.bundle"):
        inherited = cast(
            ConnectorArguments,
            {
                "_sudo": True,
                "_sudo_user": "root",
                "_su_user": "root",
                "_doas": True,
                "_doas_user": "root",
                "_dzdo": True,
                "_dzdo_user": "root",
            },
        )
        assert command.execute(sdk_state, target, inherited)
    assert len(observed) == 2
    for kwargs in observed:
        assert all(kwargs[key] is False for key in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs[key] == "" for key in ("_sudo_user", "_doas_user", "_dzdo_user", "_su_user"))


def test_observer_rejects_unknown_or_nonboolean_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        api, "host", SimpleNamespace(get_fact=lambda *a, **kw: json.dumps({"source_current": True, "extra": False}))
    )
    with pytest.raises(DeployError, match="observation is unavailable"):
        api.inspect_photos({})
