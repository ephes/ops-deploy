"""The controller half of the dotfiles step: fetch the repository and bundle it.

The role clones ``vibe_coding_dotfiles_repo`` on the host as root through
the operator's forwarded SSH agent. pyinfra opens no agent channel for its
commands, and ops-control's hosts get no GitHub credentials, so the
controller clones the repository instead (the operator's own git, SSH agent
and ``~/.ssh/config``, never prompting) and packs every branch and tag into
one ``git bundle``. The deploy ships the bundle only when the host's checkout
is not already at the default branch's tip.
"""

from __future__ import annotations

import re
from pathlib import Path

from ops_deploy.core.git_source import (
    COMMIT_PATTERN,
    GitRunner,
    GitSource,
    GitSourceError,
    subprocess_git_runner,
)
from ops_deploy.services.vibe_coding.config import Dotfiles


def prepare_dotfiles(repo: str, workdir: Path, runner: GitRunner = subprocess_git_runner) -> Dotfiles:
    """Clone ``repo`` (bare, full history) below ``workdir`` and bundle it.

    ``workdir`` must exist and is the caller's to remove. Fails closed with
    :class:`GitSourceError` (never showing credentials, which the URL check
    refuses anyway) when the clone fails, the remote has no default branch,
    or the default branch has submodules (the role's ``git`` module would
    initialise them on the host, which has no credentials here).
    """

    source = GitSource(repo=repo)
    bare = workdir / "dotfiles.git"
    bundle = workdir / "dotfiles.bundle"
    if bare.exists() or bundle.exists():
        raise GitSourceError(f"{workdir} already holds a dotfiles clone")

    def run(*argv: str, step: str) -> str:
        result = runner(["git", "-c", "core.hooksPath=/dev/null", *argv])
        if result.returncode != 0:
            tail = (result.stderr.strip() or result.stdout.strip() or "no output").splitlines()[-3:]
            raise GitSourceError(f"{step} of {source.repo} failed: {' / '.join(tail)}")
        return result.stdout

    run("clone", "--bare", "--quiet", "--template=", "--", source.repo, str(bare), step="git clone")
    git = ("-C", str(bare))
    branch = run(*git, "symbolic-ref", "--quiet", "--short", "HEAD", step="git symbolic-ref").strip()
    if not branch:
        raise GitSourceError(f"{source.repo} has no default branch")
    commit = run(
        *git, "rev-parse", "--verify", "--end-of-options", f"refs/heads/{branch}^{{commit}}", step="git rev-parse"
    )
    commit = commit.strip()
    if not re.match(COMMIT_PATTERN, commit):
        raise GitSourceError(f"git rev-parse of {source.repo} returned no commit")
    if runner(["git", *git, "cat-file", "-e", f"{commit}:.gitmodules"]).returncode == 0:
        raise GitSourceError(f"{source.repo} has submodules, which the host cannot fetch; not supported")
    run(*git, "bundle", "create", str(bundle), "--all", step="git bundle create")
    return Dotfiles(repo=source.repo, bundle=bundle, branch=branch, commit=commit)
