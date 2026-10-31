"""Real owned Git refs, dirty tracked files and recursive submodule triggers."""

from __future__ import annotations

import runpy
import subprocess
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / "src/ops_deploy/infra/files/otbr_source_host.py"


def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def commit(path: Path, name: str) -> str:
    git(path, "add", ".")
    git(path, "-c", "user.name=Owned fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", name)
    return git(path, "rev-parse", "HEAD")


@pytest.fixture
def source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "file")
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    git(upstream, "init", "-q", "-b", "main")
    (upstream / "tracked").write_text("first")
    first = commit(upstream, "first")
    return {
        "repo_url": upstream.as_uri(),
        "repo_version": "main",
        "install_dir": str(tmp_path / "install"),
        "_first": first,
    }


def test_clone_repeat_dirty_force_and_moving_main(source: dict[str, Any]) -> None:
    code = runpy.run_path(str(SCRIPT))
    initial = code["plan"](source)
    assert initial["changed"] is True
    code["apply"]({**source, "_source": initial})
    assert code["plan"](source)["changed"] is False
    directory = Path(source["install_dir"])
    (directory / "tracked").write_text("dirty tracked data")
    dirty = code["plan"](source)
    assert dirty["tracked_dirty"] is True
    code["apply"]({**source, "_source": dirty})
    assert (directory / "tracked").read_text() == "first"
    (directory / "generated-build-output").write_text("untracked build output is retained")
    assert code["plan"](source)["changed"] is False
    upstream = Path(source["repo_url"].removeprefix("file://"))
    (upstream / "tracked").write_text("second")
    second = commit(upstream, "second")
    advanced = code["plan"](source)
    assert advanced["before"] == source["_first"]
    assert advanced["resolved"] == second
    assert advanced["changed"] is True
    code["apply"]({**source, "_source": advanced})
    assert (directory / "generated-build-output").exists()
    assert code["plan"](source)["changed"] is False


def test_tag_and_full_commit_keep_configured_source(source: dict[str, Any]) -> None:
    code = runpy.run_path(str(SCRIPT))
    upstream = Path(source["repo_url"].removeprefix("file://"))
    git(upstream, "tag", "release")
    for version in ["release", source["_first"], "HEAD", source["_first"][:10]]:
        cfg = {**source, "repo_version": version}
        planned = code["plan"](cfg)
        assert planned["resolved"] == source["_first"]
        code["apply"]({**cfg, "_source": planned})
        assert code["plan"](cfg)["changed"] is False


def test_recursive_submodule_mismatch_and_tracked_modification(source: dict[str, Any], tmp_path: Path) -> None:
    code = runpy.run_path(str(SCRIPT))
    sub = tmp_path / "subrepo"
    sub.mkdir()
    git(sub, "init", "-q", "-b", "main")
    (sub / "nested").write_text("one")
    commit(sub, "sub one")
    upstream = Path(source["repo_url"].removeprefix("file://"))
    git(upstream, "submodule", "add", sub.as_uri(), "nested-source")
    commit(upstream, "add original recursive module")
    code["apply"]({**source, "_source": code["plan"](source)})
    nested = Path(source["install_dir"]) / "nested-source"
    (nested / "nested").write_text("tracked submodule modification")
    changed = code["plan"](source)
    assert changed["changed"] is True
    assert changed["submodule_changed"] is True
    code["apply"]({**source, "_source": changed})
    assert (nested / "nested").read_text() == "one"
    assert code["plan"](source)["changed"] is False


def test_HEAD_uses_original_existing_nondefault_branch_and_detached_remote_head(source: dict[str, Any]) -> None:
    code = runpy.run_path(str(SCRIPT))
    upstream = Path(source["repo_url"].removeprefix("file://"))
    git(upstream, "checkout", "-qb", "other")
    (upstream / "tracked").write_text("other branch")
    other = commit(upstream, "other branch commit")
    git(upstream, "checkout", "-q", "main")
    cfg = {**source, "repo_version": "other"}
    code["apply"]({**cfg, "_source": code["plan"](cfg)})
    head = {**source, "repo_version": "HEAD"}
    planned = code["plan"](head)
    assert planned["resolved"] == other
    assert planned["branch"] == "other"
    assert planned["changed"] is False
    code["apply"]({**head, "_source": planned})
    directory = Path(source["install_dir"])
    assert git(directory, "branch", "--show-current") == "other"
    git(directory, "checkout", "--detach", source["_first"])
    detached = code["plan"](head)
    assert detached["resolved"] == source["_first"]
    assert detached["branch"] == "main"
    code["apply"]({**head, "_source": detached})
    assert git(directory, "branch", "--show-current") == "main"


def test_historical_short_commit_is_pending_until_original_scheduled_fetch_then_quiet(source: dict[str, Any]) -> None:
    code = runpy.run_path(str(SCRIPT))
    upstream = Path(source["repo_url"].removeprefix("file://"))
    (upstream / "tracked").write_text("new advertised tip")
    commit(upstream, "advance beyond historical commit")
    cfg = {**source, "repo_version": source["_first"][:10]}
    pending = code["plan"](cfg)
    assert pending["resolved"] is None
    assert pending["resolution_pending_git_fetch"] is True
    assert pending["changed"] is True
    code["apply"]({**cfg, "_source": pending})
    repeated = code["plan"](cfg)
    assert repeated["resolved"] == source["_first"]
    assert repeated["resolution_pending_git_fetch"] is False
    assert repeated["changed"] is False


def test_planning_does_not_refresh_the_git_index(source: dict[str, Any]) -> None:
    import os

    code = runpy.run_path(str(SCRIPT))
    code["apply"]({**source, "_source": code["plan"](source)})
    directory = Path(source["install_dir"])
    index = directory / ".git/index"
    before = (index.read_bytes(), index.stat().st_mtime_ns)
    tracked = directory / "tracked"
    details = tracked.stat()
    os.utime(tracked, ns=(details.st_atime_ns, details.st_mtime_ns + 2_000_000_000))
    assert code["plan"](source)["changed"] is False
    assert (index.read_bytes(), index.stat().st_mtime_ns) == before


def test_relative_local_mirror_normalized_once_before_plan_clone_fetch_repeat(
    source: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code = runpy.run_path(str(SCRIPT))
    monkeypatch.chdir(tmp_path)
    cfg = {**source, "repo_url": "upstream"}
    first = code["plan"](cfg)
    assert first["changed"] is True
    code["apply"]({**cfg, "_source": first})
    assert git(Path(cfg["install_dir"]), "remote", "get-url", "origin") == str(tmp_path / "upstream")
    repeat = code["plan"](cfg)
    assert repeat["changed"] is False
    code["apply"]({**cfg, "_source": repeat})
    assert code["plan"](cfg)["changed"] is False


def test_source_option_value_never_executes_as_git_argument(source: dict[str, Any], tmp_path: Path) -> None:
    code = runpy.run_path(str(SCRIPT))
    marker = tmp_path / "must-not-be-created"
    with pytest.raises(ValueError, match="Git options"):
        code["plan"]({**source, "repo_url": "--upload-pack=touch " + str(marker)})
    with pytest.raises(ValueError, match="Git options"):
        code["plan"]({**source, "repo_version": "--output=" + str(marker)})
    assert not marker.exists()
