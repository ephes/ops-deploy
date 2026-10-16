"""Service code from a git remote, fetched on the controller.

:func:`fetch_source` makes a shallow fetch of one ref into a fresh directory
with the operator's own git and SSH setup and checks it out. The deploy then
syncs that tree like a local checkout (``sync_tree`` never transfers
``.git``), so hosts need no deploy keys or other credentials, and the deploy
records the commit it shipped (``record_source``).

Fails closed: a ref the remote does not have, a name that is both a branch
and a tag, a fetched commit other than the one asked for, or a checked-out
file that is not byte for byte its committed blob raises
:class:`GitSourceError`. Attributes cannot rewrite files (filters, line
endings); LFS pointers and submodules are refused. Repository URLs with
credentials in them are refused, so no error message or log line can show one.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

COMMIT_PATTERN = r"^[0-9a-f]{40}$"
# Branch, tag or full commit name: no refspec or revision syntax (``:``,
# ``+``, ``^``, ``~``, ``*``, ``@{``); checked further by ``_valid_ref``.
REF_PATTERN = r"^[A-Za-z0-9._/@-]+$"

CommitSha = Annotated[str, Field(pattern=COMMIT_PATTERN)]
GitRef = Annotated[str, Field(pattern=REF_PATTERN, max_length=255)]

# scp-like ``user@host:path`` or ``ssh://``/``https://``/``file://`` URLs.
_SCP_LIKE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._~/-]+$")
_URL = re.compile(r"^(ssh|https|file)://(?:([^@/\s]*)@)?([A-Za-z0-9.:\[\]-]*)(/[A-Za-z0-9._~/-]+)$")
# Written to ``.git/info/attributes`` (they override the tree's attributes):
# no smudge/clean filter, line-ending conversion, ident or encoding change.
NEUTRAL_ATTRIBUTES = ("-text", "-eol", "-filter", "-ident", "-working-tree-encoding")
LFS_POINTER = b"version https://git-lfs.github.com/spec/v1"
# Never ask on a terminal for a user name or password (https remotes).
_GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}


class GitSourceError(RuntimeError):
    """Fetching or checking out the source failed; carries no credentials."""


class GitSource(BaseModel):
    """Where a service's code comes from: ``repo`` at ``ref``.

    ``ref`` is a branch, a tag or a full 40-character commit; ``None`` is the
    remote's default branch (its ``HEAD``).
    """

    # hide_input_in_errors: a refused URL may hold a token; errors never echo it.
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    repo: str
    ref: GitRef | None = None

    @field_validator("ref")
    @classmethod
    def _valid_ref(cls, value: str | None) -> str | None:
        if value is not None and (
            value.startswith(("-", "/", "."))
            or value.endswith(("/", ".", ".lock"))
            or any(part in value for part in ("..", "//", "@{", "/."))
        ):
            raise ValueError("ref must be a branch, tag or full commit name")
        return value

    @field_validator("repo")
    @classmethod
    def _repo_without_credentials(cls, value: str) -> str:
        # Messages never echo the value: it may be a mistyped secret.
        if _SCP_LIKE.match(value):
            return value
        url = _URL.match(value)
        if url is None:
            raise ValueError("repo must be user@host:path or an ssh://, https:// or file:// URL")
        scheme, userinfo = url.group(1), url.group(2)
        if userinfo is not None and (scheme != "ssh" or ":" in userinfo):
            raise ValueError("repo must not carry credentials (use the SSH agent or a credential helper)")
        return value


@dataclass(frozen=True)
class SourceTree:
    """A checked-out tree and the commit it is."""

    path: Path
    commit: str


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class GitRunner(Protocol):
    def __call__(self, argv: Sequence[str]) -> GitResult: ...


def subprocess_git_runner(argv: Sequence[str]) -> GitResult:
    """Run git on the controller with the operator's config, agent and SSH setup."""

    env = {**os.environ, **_GIT_ENV}
    completed = subprocess.run(list(argv), check=False, capture_output=True, env=env)
    # Bytes, decoded without newline translation: a file name may hold a "\r"
    # (or bytes that are not UTF-8, kept as surrogates like os.fsdecode does).
    return GitResult(
        completed.returncode,
        completed.stdout.decode("utf-8", "surrogateescape"),
        completed.stderr.decode("utf-8", "replace"),
    )


def fetch_source(source: GitSource, dest: Path, runner: GitRunner = subprocess_git_runner) -> SourceTree:
    """Check ``source`` out into ``dest`` (created; must not exist) and return its commit."""

    if dest.exists():
        raise GitSourceError(f"{dest} already exists")
    label = f"{source.repo} at {source.ref or 'its default branch'}"
    git = ["git", "-C", str(dest), "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false"]

    def run(*argv: str, step: str) -> str:
        result = runner([*git, *argv])
        if result.returncode != 0:
            tail = (result.stderr.strip() or result.stdout.strip() or "no output").splitlines()[-3:]
            raise GitSourceError(f"{step} of {label} failed: {' / '.join(tail)}")
        return result.stdout

    dest.mkdir(parents=True)
    # No template: no sample hooks or other files from the operator's setup.
    run("init", "--quiet", "--template=", step="git init")
    ref = _remote_ref(source, lambda *argv: run(*argv, step="git ls-remote"))
    run("fetch", "--quiet", "--depth=1", "--no-tags", "--end-of-options", source.repo, ref, step="git fetch")
    commit = run("rev-parse", "--verify", "--end-of-options", "FETCH_HEAD^{commit}", step="git rev-parse").strip()
    if not re.match(COMMIT_PATTERN, commit):
        raise GitSourceError(f"git rev-parse of {label} returned no commit")
    if ref != "HEAD" and re.match(COMMIT_PATTERN, ref) and commit != ref:
        raise GitSourceError(f"{label}: the remote returned another commit ({commit})")
    # The highest-priority attributes: files are written exactly as committed,
    # whatever the tree's .gitattributes or the operator's config ask for.
    (dest / ".git" / "info").mkdir(exist_ok=True)
    (dest / ".git" / "info" / "attributes").write_text(f"* {' '.join(NEUTRAL_ATTRIBUTES)}\n")
    run("checkout", "--quiet", "--detach", commit, step="git checkout")
    if run("status", "--porcelain", "--untracked-files=all", step="git status").strip():
        raise GitSourceError(f"{label}: the checkout differs from commit {commit}")
    _verify_tree(dest, run("ls-files", "--stage", "-z", step="git ls-files"), f"{label} ({commit})")
    return SourceTree(path=dest, commit=commit)


def _remote_ref(source: GitSource, ls_remote: Callable[..., str]) -> str:
    """The one remote ref to fetch: ``HEAD``, a full commit, or the branch or tag ``ref`` names.

    A name that is both a branch and a tag is refused rather than guessed.
    """

    if source.ref is None:
        return "HEAD"
    if re.match(COMMIT_PATTERN, source.ref):
        return source.ref
    names = (f"refs/heads/{source.ref}", f"refs/tags/{source.ref}")
    listed = ls_remote("ls-remote", "--refs", "--end-of-options", source.repo, *names)
    found = sorted({line.split("\t", 1)[1] for line in listed.splitlines() if "\t" in line} & set(names))
    if not found:
        raise GitSourceError(f"{source.repo} has no branch or tag {source.ref}")
    if len(found) > 1:
        raise GitSourceError(f"{source.repo}: {source.ref} is both a branch and a tag; give the full commit")
    return found[0]


def _verify_tree(root: Path, staged: str, label: str) -> None:
    """Every checked-out file holds exactly its committed blob (no filter, no line-ending change)."""

    for entry in filter(None, staged.split("\0")):
        meta, path = entry.split("\t", 1)
        mode, blob, _stage = meta.split()
        target = root / path
        if mode == "120000":
            data = os.readlink(target).encode()
        elif mode in ("100644", "100755") and not target.is_symlink():
            data = target.read_bytes()
            if data.startswith(LFS_POINTER):
                raise GitSourceError(f"{label}: {path} is a Git LFS pointer; LFS is not supported")
            if (mode == "100755") != os.access(target, os.X_OK):
                raise GitSourceError(f"{label}: {path} has another mode than committed")
        else:
            raise GitSourceError(f"{label}: {path} is not a regular file or symlink (submodules are not supported)")
        if hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest() != blob:
            raise GitSourceError(f"{label}: {path} differs from its committed content")
