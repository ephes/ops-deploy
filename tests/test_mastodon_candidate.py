"""Immutable selected trees and ruby-build provenance, using real Git objects."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.mastodon import describe_candidate
from tests.test_mastodon_release_source import git


def repository(path: Path) -> str:
    path.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "master", str(path)], check=True)
    git(path, "config", "user.email", "fixture@example.org")
    git(path, "config", "user.name", "Fixture")
    (path / "README").write_text("fixture\n")
    git(path, "add", ".")
    git(path, "commit", "-qm", "fixture")
    return git(path, "rev-parse", "HEAD")


def test_candidate_freezes_tool_commit_and_all_migration_ids(tmp_path: Path) -> None:
    source = tmp_path / "source"
    repository(source)
    for name, value in {
        "Gemfile.lock": "locked",
        "yarn.lock": "locked",
        "package.json": "{}",
        ".ruby-version": "4.0.5",
        ".nvmrc": "24.17",
    }.items():
        (source / name).write_text(value)
    for kind, version in (("migrate", "20260101000000"), ("post_migrate", "20260102000000")):
        path = source / "db" / kind
        path.mkdir(parents=True)
        (path / (version + "_fixture.rb")).write_text("# fixture migration\n")
    git(source, "add", ".")
    git(source, "commit", "-qm", "selected")
    tool = tmp_path / "ruby-build"
    first = repository(tool)
    tree = SourceTree(path=source, commit=git(source, "rev-parse", "HEAD"))
    arguments: dict[str, Any] = {"git_repo": source.as_uri(), "git_ref": "master", "ruby_build_repo": tool.as_uri()}
    manifest = describe_candidate(tree, **arguments)
    assert manifest["runtime_tool_commits"] == {"ruby_build": first}
    assert manifest["migration_versions"] == ["20260101000000", "20260102000000"]
    assert manifest["source_tracked_paths"] == git(source, "ls-tree", "-r", "--name-only", "HEAD").splitlines()
    (tool / "README").write_text("advanced tool\n")
    git(tool, "add", ".")
    git(tool, "commit", "-qm", "advanced")
    # An independent normal invocation can select the new master. The repeat
    # explicitly carries the recorded exact tool object, even after advancement.
    next_manifest = describe_candidate(tree, **arguments)
    assert next_manifest["runtime_tool_commits"] != manifest["runtime_tool_commits"]
    repeat = describe_candidate(tree, runtime_tool_commits=manifest["runtime_tool_commits"], **arguments)
    assert repeat == manifest
