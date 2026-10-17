"""shared_tree (a group-writable media tree) against the fake connector."""

from __future__ import annotations

from typing import Any

import pytest

from ops_deploy.services.shared_tree import SharedTreeConfig, deploy_shared_tree
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

ROOT = "/srv/crypt/media"
DIRS = (ROOT, f"{ROOT}/video", f"{ROOT}/video/movies", f"{ROOT}/downloads")
CFG = SharedTreeConfig(
    root=ROOT, group="media", directories=DIRS, foreign=(f"{ROOT}/video/youtube",), mounts_required=("/srv/crypt",)
)
PREFIX = "Deploy shared tree | "


def converged(**overrides: Any) -> dict[str, Any]:
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        "cat /etc/group": ["root:x:0:", "media:x:965:"],
    }
    for path in DIRS:
        responses.update(fakehost.stat(path, user="root", group="media", mode="drwxrwsr-x"))
    responses.update(overrides)
    return responses


def deploy(responses: dict[str, Any]) -> FakeRun:
    run = run_deploy_fake(deploy_shared_tree, CFG, responses=responses)
    assert run.succeeded, run.error
    return run


def test_converged_tree_gets_no_mutating_operation() -> None:
    run = deploy(converged())

    assert run.mutating_changed_ops == []
    probes = [command for command in run.fact_commands if command.startswith(f"find {ROOT} ")]
    assert len(probes) == 3
    assert all(f"-path {ROOT}/video/youtube -prune -o" in command for command in probes)


def test_entries_outside_the_model_are_repaired_once_found() -> None:
    run = deploy(
        converged(
            **{
                "-group media -print -quit": [f"{ROOT}/video/movies/a.mkv"],
                "-perm -0060 -print -quit": [f"{ROOT}/video/movies/a.mkv"],
            }
        )
    )

    assert run.mutating_changed_ops == [
        f"{PREFIX}Give entries outside the group to media",
        f"{PREFIX}Make files group-writable",
    ]
    assert (
        f"find {ROOT} -path {ROOT}/video/youtube -prune -o '!' -group media -print0 | xargs -0 -r chgrp -h media"
        in run.executed_commands
    )


def test_a_fresh_host_gets_the_group_and_the_directories() -> None:
    run = deploy({**fakehost.LINUX})

    assert f"{PREFIX}Ensure group media" in run.mutating_changed_ops
    assert "chmod 2775 /srv/crypt/media/downloads" in run.executed_commands


def test_paths_outside_the_root_are_refused() -> None:
    with pytest.raises(ValueError, match="outside root"):
        SharedTreeConfig(root=ROOT, group="media", directories=(ROOT, "/srv/other"))


def test_a_tree_older_than_its_group_gets_the_group() -> None:
    responses = {**fakehost.LINUX, f"test -d {ROOT} && echo yes": ["yes"]}

    run = deploy(responses)

    assert f"{PREFIX}Give entries outside the group to media" in run.mutating_changed_ops
