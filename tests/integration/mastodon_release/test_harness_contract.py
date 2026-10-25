"""Local checks of fixture construction; these do not claim real Linux execution."""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).parent


def load_harness() -> Any:
    spec = importlib.util.spec_from_file_location("mastodon_linux_harness", HERE / "harness.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_candidate_contract_reads_both_real_git_migration_trees(tmp_path: Path) -> None:
    harness = load_harness()
    harness.fixture(tmp_path, "4.0.5", "24.17")
    (tmp_path / "Gemfile.lock").write_text("fixture source contract only\n")
    (tmp_path / "yarn.lock").write_text("fixture source contract only\n")
    post = tmp_path / "db/post_migrate/20250103000000_post.rb"
    post.parent.mkdir()
    post.write_text("# candidate post migration\n")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    commit = harness.git_commit(tmp_path, "candidate fixture")
    cfg = harness.config(tmp_path, tmp_path.as_uri(), "HEAD")
    assert cfg["source_commit"] == commit
    assert cfg["migration_versions"] == ["20250101000000", "20250103000000"]
    assert "db/post_migrate/20250103000000_post.rb" in cfg["source_tracked_paths"]
    assert set(cfg["source_files"]) == {"Gemfile.lock", "yarn.lock", "package.json", ".ruby-version", ".nvmrc"}
    assert cfg["runtime_tool_commits"]["ruby_build"] == harness.RUBY_BUILD


def test_host_runner_refuses_before_provisioning_outside_owned_vm() -> None:
    env = dict(os.environ, GITHUB_ACTIONS="false", RUNNER_ENVIRONMENT="")
    result = subprocess.run(["bash", str(HERE / "run.sh")], env=env, capture_output=True, check=False)
    assert result.returncode != 0
    assert b"OWNED_VM_PROVISION_START" not in result.stdout


def test_direct_harness_rejects_self_hosted_before_destructive_steps(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = load_harness()
    monkeypatch.setattr(harness.os, "getuid", lambda: 0)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    with pytest.raises(SystemExit, match="self-hosted runner forbidden"):
        harness.assert_owned_vm()


@pytest.mark.parametrize("flags", [[], ["-O"]])
def test_direct_execution_guards_survive_optimization(flags: list[str]) -> None:
    import sys

    code = (
        "import os,runpy,sys; "
        "module=runpy.run_path(sys.argv[1]); os.getuid=lambda:0; "
        "os.environ['GITHUB_ACTIONS']='true'; os.environ['RUNNER_ENVIRONMENT']='self-hosted'; "
        "module['assert_owned_vm']()"
    )
    result = subprocess.run(
        [sys.executable, *flags, "-c", code, str(HERE / "harness.py")], capture_output=True, check=False
    )
    assert result.returncode != 0
    assert b"self-hosted runner forbidden" in result.stderr


def test_marker_is_private_exclusive_and_preserves_umask(tmp_path: Path) -> None:
    import stat

    harness = load_harness()
    marker = tmp_path / "marker.json"
    previous = os.umask(0o027)
    try:
        harness.create_vm_marker(marker, "123", "fixture-machine")
        after = os.umask(0o027)
        assert after == 0o027
        assert stat.S_IMODE(marker.stat().st_mode) == 0o600
        with pytest.raises(FileExistsError):
            harness.create_vm_marker(marker, "456", "other-machine")
    finally:
        os.umask(previous)


def test_operation_invariants_survive_optimization() -> None:
    import sys

    code = (
        "import runpy,sys; module=runpy.run_path(sys.argv[1]); "
        "module['services'].__globals__['command']=lambda *args:'inactive'; module['services']()"
    )
    result = subprocess.run(
        [sys.executable, "-O", "-c", code, str(HERE / "harness.py")], capture_output=True, check=False
    )
    assert result.returncode != 0
    assert b"AssertionError" in result.stderr
