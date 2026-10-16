"""``fetch_source`` against real local repositories (``file://`` remotes)."""

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core.git_source import GitResult, GitSource, GitSourceError, fetch_source, subprocess_git_runner

AUTHOR = ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"]


def git(repo: Path, *argv: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *AUTHOR, *argv], check=True, capture_output=True, text=True).stdout


@pytest.fixture
def remote(tmp_path: Path) -> dict[str, Any]:
    """A repository with two commits on ``main``, a ``feature`` branch and an annotated tag."""

    repo = tmp_path / "remote"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "manage.py").write_text("v1\n")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "one")
    first = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "tag", "--annotate", "-m", "release", "v1")
    (repo / "manage.py").write_text("v2\n")
    (repo / "app").mkdir()
    (repo / "app" / "views.py").write_text("views\n")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "two")
    second = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "branch", "feature", first)
    return {"url": f"file://{repo}", "first": first, "second": second}


def test_default_branch(remote: dict[str, Any], tmp_path: Path) -> None:
    tree = fetch_source(GitSource(repo=remote["url"]), tmp_path / "tree")

    assert tree.commit == remote["second"]
    assert tree.path == tmp_path / "tree"
    assert (tree.path / "manage.py").read_text() == "v2\n"
    assert (tree.path / "app" / "views.py").read_text() == "views\n"
    # Shallow: only the one commit was fetched.
    assert git(tree.path, "rev-list", "--count", "HEAD").strip() == "1"


@pytest.mark.parametrize(("ref", "expected"), [("feature", "first"), ("v1", "first"), ("main", "second")])
def test_branch_and_annotated_tag(remote: dict[str, Any], tmp_path: Path, ref: str, expected: str) -> None:
    tree = fetch_source(GitSource(repo=remote["url"], ref=ref), tmp_path / "tree")

    assert tree.commit == remote[expected]
    assert (tree.path / "manage.py").read_text() == ("v1\n" if expected == "first" else "v2\n")


def test_full_commit(remote: dict[str, Any], tmp_path: Path) -> None:
    tree = fetch_source(GitSource(repo=remote["url"], ref=remote["first"]), tmp_path / "tree")

    assert tree.commit == remote["first"]
    assert not (tree.path / "app").exists()


@pytest.mark.parametrize(
    ("ref", "match"),
    [("missing", "has no branch or tag missing"), ("abc1234", "has no branch or tag"), ("0" * 40, "git fetch of")],
)
def test_missing_ref_fails_closed(remote: dict[str, Any], tmp_path: Path, ref: str, match: str) -> None:
    with pytest.raises(GitSourceError, match=match):
        fetch_source(GitSource(repo=remote["url"], ref=ref), tmp_path / "tree")


def test_a_name_that_is_both_branch_and_tag_is_refused(remote: dict[str, Any], tmp_path: Path) -> None:
    repo = Path(remote["url"].removeprefix("file://"))
    git(repo, "branch", "release", remote["first"])
    git(repo, "tag", "release", remote["second"])

    with pytest.raises(GitSourceError, match="both a branch and a tag"):
        fetch_source(GitSource(repo=remote["url"], ref="release"), tmp_path / "tree")


def commit_files(repo: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        (repo / name).write_text(content)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "more")


def test_attributes_and_filters_never_rewrite_files(
    remote: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = Path(remote["url"].removeprefix("file://"))
    attributes = "*.txt text eol=crlf\n*.dat filter=rot ident\n"
    commit_files(repo, {".gitattributes": attributes, "a.txt": "one\ntwo\n", "b.dat": "abc $Id$\n"})
    # A smudge filter in the operator's git config would rewrite b.dat.
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "filter.rot.smudge")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "tr a-z b-za")

    tree = fetch_source(GitSource(repo=remote["url"]), tmp_path / "tree")

    assert (tree.path / "a.txt").read_bytes() == b"one\ntwo\n"
    assert (tree.path / "b.dat").read_bytes() == b"abc $Id$\n"


def test_symlinks_and_executables_are_kept(remote: dict[str, Any], tmp_path: Path) -> None:
    repo = Path(remote["url"].removeprefix("file://"))
    (repo / "run.sh").write_text("#!/bin/sh\n")
    (repo / "run.sh").chmod(0o755)
    (repo / "link").symlink_to("manage.py")
    commit_files(repo, {})

    tree = fetch_source(GitSource(repo=remote["url"]), tmp_path / "tree")

    assert (tree.path / "link").readlink() == Path("manage.py")
    assert (tree.path / "run.sh").stat().st_mode & 0o111


def test_file_names_with_carriage_returns_and_spaces(remote: dict[str, Any], tmp_path: Path) -> None:
    repo = Path(remote["url"].removeprefix("file://"))
    commit_files(repo, {"asset\r.txt": "cr\r\n", "with space.txt": "x\n"})

    tree = fetch_source(GitSource(repo=remote["url"]), tmp_path / "tree")

    assert (tree.path / "asset\r.txt").read_bytes() == b"cr\r\n"
    assert (tree.path / "with space.txt").read_bytes() == b"x\n"


def test_lfs_pointers_are_refused(remote: dict[str, Any], tmp_path: Path) -> None:
    repo = Path(remote["url"].removeprefix("file://"))
    pointer = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 1\n"
    commit_files(repo, {"big.bin": pointer})

    with pytest.raises(GitSourceError, match=r"big\.bin is a Git LFS pointer"):
        fetch_source(GitSource(repo=remote["url"]), tmp_path / "tree")


@pytest.mark.parametrize(
    ("tamper", "match"),
    [
        (lambda tree: (tree / "manage.py").write_text("changed\n"), r"manage\.py differs from its committed content"),
        (lambda tree: (tree / "manage.py").chmod(0o755), r"manage\.py has another mode"),
    ],
    ids=["content", "mode"],
)
def test_files_that_differ_from_their_blob_fail_closed(
    remote: dict[str, Any], tmp_path: Path, tamper: Any, match: str
) -> None:
    # Whatever git status says (here: nothing), the bytes are checked.
    def runner(argv: Sequence[str]) -> GitResult:
        if "status" in argv:
            tamper(tmp_path / "tree")
            return GitResult(0)
        return subprocess_git_runner(argv)

    with pytest.raises(GitSourceError, match=match):
        fetch_source(GitSource(repo=remote["url"]), tmp_path / "tree", runner)


def test_existing_destination_is_refused(remote: dict[str, Any], tmp_path: Path) -> None:
    (tmp_path / "tree").mkdir()

    with pytest.raises(GitSourceError, match="already exists"):
        fetch_source(GitSource(repo=remote["url"]), tmp_path / "tree")


class Recording:
    """The real runner, with one step's result replaced."""

    def __init__(self, step: str, result: GitResult) -> None:
        self.step, self.result = step, result
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str]) -> GitResult:
        self.calls.append(list(argv))
        if self.step in argv:
            return self.result
        return subprocess_git_runner(argv)


def test_another_commit_than_asked_for_fails_closed(remote: dict[str, Any], tmp_path: Path) -> None:
    runner = Recording("rev-parse", GitResult(0, remote["second"] + "\n"))

    with pytest.raises(GitSourceError, match="another commit"):
        fetch_source(GitSource(repo=remote["url"], ref=remote["first"]), tmp_path / "tree", runner)


def test_dirty_checkout_fails_closed(remote: dict[str, Any], tmp_path: Path) -> None:
    runner = Recording("status", GitResult(0, " M manage.py\n"))

    with pytest.raises(GitSourceError, match="checkout differs"):
        fetch_source(GitSource(repo=remote["url"]), tmp_path / "tree", runner)


def test_git_runs_without_hooks_prompts_or_options(remote: dict[str, Any], tmp_path: Path) -> None:
    runner = Recording("never", GitResult(0))

    fetch_source(GitSource(repo=remote["url"], ref="main"), tmp_path / "tree", runner)

    prefix = ["git", "-C", str(tmp_path / "tree"), "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false"]
    for call in runner.calls:
        assert call[:7] == prefix
    init, ls_remote, fetch = runner.calls[0], runner.calls[1], runner.calls[2]
    assert "--template=" in init
    assert ls_remote[7:] == [
        "ls-remote",
        "--refs",
        "--end-of-options",
        remote["url"],
        "refs/heads/main",
        "refs/tags/main",
    ]
    # The one full ref name the remote listed, never a name git would guess at.
    assert fetch[7:] == [
        "fetch",
        "--quiet",
        "--depth=1",
        "--no-tags",
        "--end-of-options",
        remote["url"],
        "refs/heads/main",
    ]


def test_subprocess_runner_never_prompts(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    subprocess_git_runner(["git", "version"])

    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_failure_message_names_the_step_and_keeps_the_tail(tmp_path: Path) -> None:
    def failing(argv: Sequence[str]) -> GitResult:
        if "ls-remote" in argv:
            return GitResult(128, "", "line 1\nline 2\nline 3\nfatal: could not read from remote repository\n")
        return GitResult(0)

    with pytest.raises(GitSourceError) as excinfo:
        fetch_source(GitSource(repo="git@example.com:owner/app.git", ref="nope"), tmp_path / "tree", failing)

    message = str(excinfo.value)
    assert message.startswith("git ls-remote of git@example.com:owner/app.git at nope failed")
    assert "line 1" not in message
    assert message.endswith("fatal: could not read from remote repository")


@pytest.mark.parametrize(
    "repo",
    [
        "git@github.com:owner/app.git",
        "ssh://git@github.com/owner/app.git",
        "ssh://git@host.example:2222/owner/app.git",
        "https://github.com/owner/app.git",
        "file:///srv/git/app.git",
    ],
)
def test_accepted_repositories(repo: str) -> None:
    assert GitSource(repo=repo).repo == repo


@pytest.mark.parametrize(
    "repo",
    [
        "https://token-0123456789@github.com/owner/app.git",
        "https://user:hunter2-0123456789@github.com/owner/app.git",
        "ssh://git:hunter2-0123456789@github.com/owner/app.git",
        "-uhunter2-0123456789",
        "--upload-pack=touch /tmp/x",
        "ext::sh -c touch% /tmp/x",
        "http://github.com/owner/app.git",
        "/srv/git/app.git",
        "git@github.com:owner/app.git main",
    ],
)
def test_refused_repositories_are_not_echoed(repo: str) -> None:
    with pytest.raises(ValidationError) as excinfo:
        GitSource(repo=repo)

    assert "hunter2" not in str(excinfo.value)
    assert "token-0123456789" not in str(excinfo.value)


@pytest.mark.parametrize("ref", ["main", "release/2026.10", "v1.2.3", "feature-x", "a" * 40])
def test_accepted_refs(ref: str) -> None:
    assert GitSource(repo="git@github.com:owner/app.git", ref=ref).ref == ref


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "-main",
        "--upload-pack=x",
        "main:refs/heads/other",
        "+main",
        "HEAD~1",
        "HEAD^",
        "main@{1}",
        "a..b",
        "release/",
        "/main",
        "a//b",
        "x.lock",
        ".hidden",
        "a/.b",
        "feature x",
        "*",
    ],
)
def test_refused_refs(ref: str) -> None:
    with pytest.raises(ValidationError):
        GitSource(repo="git@github.com:owner/app.git", ref=ref)
