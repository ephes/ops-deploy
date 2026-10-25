"""Describe the selected source and freeze mutable ruby-build input once."""

from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ops_deploy.core.git_source import GitSource, SourceTree, fetch_source

SOURCE_FILES = ("Gemfile.lock", "yarn.lock", "package.json", ".ruby-version", ".nvmrc")


def describe_candidate(
    tree: SourceTree,
    *,
    git_repo: str,
    git_ref: str,
    ruby_build_repo: str = "https://github.com/rbenv/ruby-build.git",
    ruby_build_update: bool = True,
    runtime_tool_commits: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Read candidate identities without executing candidate application code.

    An explicit tool commit is fetched from its declared repository before host
    access. Otherwise ruby-build's master is resolved once by ``fetch_source``.
    The returned manifest is the same deliberate input for apply and repeat.
    """
    source = GitSource(repo=git_repo, ref=git_ref)
    tracked = subprocess.check_output(
        ["git", "-C", str(tree.path), "ls-tree", "-r", "--name-only", "-z", tree.commit], text=True
    ).split("\x00")[:-1]
    versions: list[str] = []
    for directory in ("db/migrate", "db/post_migrate"):
        for path in sorted((tree.path / directory).glob("*.rb")):
            match = re.fullmatch(r"([0-9]+)_.+\.rb", path.name)
            if match is None:
                raise ValueError("mastodon: a candidate migration has no version identity")
            versions.append(match.group(1))
    if len(set(versions)) != len(versions):
        raise ValueError("mastodon: duplicate migration identity in the candidate tree")
    supplied = dict(runtime_tool_commits) if runtime_tool_commits is not None else None
    commits: dict[str, str] = {}
    if ruby_build_update:
        if supplied is not None and (
            set(supplied) != {"ruby_build"} or not re.fullmatch(r"[0-9a-f]{40}", supplied["ruby_build"])
        ):
            raise ValueError("mastodon: runtime_tool_commits needs one exact ruby_build Git object")
        ref = supplied["ruby_build"] if supplied is not None else "master"
        with tempfile.TemporaryDirectory(prefix="mastodon-ruby-build-") as temporary:
            tool = fetch_source(GitSource(repo=ruby_build_repo, ref=ref), Path(temporary) / "tool")
            if supplied is not None and tool.commit != ref:
                raise ValueError("mastodon: ruby_build object does not match its declared repository")
            commits["ruby_build"] = tool.commit
    elif supplied:
        raise ValueError("mastodon: ruby_build_update=false retains the installed tool, without a supplied update")
    return {
        "git_repo": source.repo,
        "git_ref": source.ref,
        "source_commit": tree.commit,
        "source_tracked_paths": tracked,
        "source_files": {name: hashlib.sha256((tree.path / name).read_bytes()).hexdigest() for name in SOURCE_FILES},
        "migration_versions": sorted(versions),
        "ruby_version": (tree.path / ".ruby-version").read_text().strip(),
        "node_version": (tree.path / ".nvmrc").read_text().strip().removeprefix("v"),
        "runtime_tool_commits": commits,
    }
