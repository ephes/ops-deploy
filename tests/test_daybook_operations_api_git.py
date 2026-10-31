"""Actual Git and SDK regression for exact target revisions, without inventory IO."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from ops_deploy.services.daybook_operations_api import OperationsApiConfig
from ops_deploy.services.daybook_operations_api.git import checkout, install_commands, source_state
from ops_deploy.testing import run_deploy_fake


def test_real_git_fresh_detached_repeat_update_and_dirty_refusal(tmp_path: Path) -> None:
    env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")

    def run(argv: list[str], cwd: Path | None = None) -> str:
        return subprocess.run(argv, cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()

    origin = tmp_path / "origin"
    origin.mkdir()
    run(["git", "init", "--quiet"], origin)
    run(["git", "config", "user.name", "Owned fixture"], origin)
    run(["git", "config", "user.email", "owned@example.invalid"], origin)
    (origin / "source.py").write_text("first\n")
    run(["git", "add", "source.py"], origin)
    run(["git", "commit", "-qm", "first"], origin)
    first = run(["git", "rev-parse", "HEAD"], origin)
    (origin / "source.py").write_text("second\n")
    run(["git", "commit", "-qam", "second"], origin)
    second = run(["git", "rev-parse", "HEAD"], origin)
    # Actual behavior of the pre-repair SDK clone branch argument.
    bad = subprocess.run(
        ["git", "clone", "--branch", first, str(origin), str(tmp_path / "bad")], capture_output=True, env=env
    )
    assert bad.returncode != 0
    # Reproduce the R2 interruption: a no-checkout clone has no index and
    # therefore appears dirty. The repaired normal clone is resumable without
    # ignoring any genuine tracked modification or introducing a state marker.
    old_partial = tmp_path / "old-partial"
    run(["git", "clone", "--no-checkout", str(origin), str(old_partial)])
    old_cfg = OperationsApiConfig(deploy_method="git", git_repo=str(origin), git_revision=first, site=str(old_partial))
    assert run(["/bin/sh", "-c", source_state(old_cfg)]) == "dirty"
    partial = tmp_path / "partial"
    partial.mkdir()
    resumed = old_cfg.model_copy(update={"site": str(partial)})
    run(["/bin/sh", "-c", install_commands(resumed)[1]])
    unavailable = tmp_path / "temporarily-unavailable-origin"
    origin.rename(unavailable)
    try:
        failed_fetch = subprocess.run(["/bin/sh", "-c", install_commands(resumed)[2]], capture_output=True, env=env)
        assert failed_fetch.returncode != 0
        assert run(["/bin/sh", "-c", source_state(resumed)]) == second
    finally:
        unavailable.rename(origin)
    for command in install_commands(resumed):
        run(["/bin/sh", "-c", command])
    assert run(["/bin/sh", "-c", source_state(resumed)]) == first
    assert (partial / "source.py").read_text() == "first\n"
    site = tmp_path / "site"
    site.mkdir()
    cfg = OperationsApiConfig(deploy_method="git", git_repo=str(origin), git_revision=first, site=str(site))
    assert run(["/bin/sh", "-c", source_state(cfg)]) == "missing"
    for command in install_commands(cfg):
        run(["/bin/sh", "-c", command])
    assert run(["/bin/sh", "-c", source_state(cfg)]) == first
    assert (site / "source.py").read_text() == "first\n"
    assert run(["git", "-C", str(site), "rev-parse", "--abbrev-ref", "HEAD"]) == "HEAD"
    baseline = {str(p.relative_to(site)): p.stat().st_mtime_ns for p in site.rglob("*") if p.is_file()}
    assert run(["/bin/sh", "-c", source_state(cfg)]) == first
    assert {str(p.relative_to(site)): p.stat().st_mtime_ns for p in site.rglob("*") if p.is_file()} == baseline
    cfg = cfg.model_copy(update={"git_revision": second})
    for command in install_commands(cfg):
        run(["/bin/sh", "-c", command])
    assert run(["/bin/sh", "-c", source_state(cfg)]) == second
    (site / "source.py").write_text("owned dirty\n")
    assert run(["/bin/sh", "-c", source_state(cfg)]) == "dirty"
    refused = subprocess.run(["/bin/sh", "-c", install_commands(cfg)[0]], capture_output=True, env=env)
    assert refused.returncode != 0
    assert (site / "source.py").read_text() == "owned dirty\n"


@pytest.mark.parametrize("state", ["missing", "a" * 40, "b" * 40, "origin", "dirty", "unexpected"])
def test_actual_sdk_exact_git_admission_and_original_service_identity(state: str) -> None:
    cfg = OperationsApiConfig(deploy_method="git", git_revision="a" * 40)
    result = run_deploy_fake(checkout, cfg, responses={"if id -u daybook-operations": [state]})
    assert result.succeeded is (state not in {"dirty", "unexpected"})
    if state in {"dirty", "unexpected", "a" * 40}:
        assert not result.executed_commands
        assert not result.mutating_changed_ops
    else:
        assert len(result.mutating_changed_ops) == 1
        body = "\n".join(result.executed_commands)
        assert "runuser -u daybook-operations -- env HOME=/home/daybook-operations" in body
        assert "git clone -- " in body
        assert "--no-checkout" not in body
        assert "checkout --detach " + "a" * 40 in body
        assert "git pull" not in body
        assert "--branch" not in body
