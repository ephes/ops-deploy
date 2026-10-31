"""Exact target Git revision commands for the original Operations API option."""

from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.helpers.python import _as_user
from ops_deploy.services.daybook_operations_api.config import OperationsApiConfig


def source_state(cfg: OperationsApiConfig) -> str:
    site = shlex.quote(str(cfg.site_path))
    repo = shlex.quote(cfg.git_repo)
    git = "git -C " + site
    return (
        "export GIT_OPTIONAL_LOCKS=0; "
        f"if test ! -e {site}/.git; then echo missing; "
        f"elif ! {git} diff --quiet || ! {git} diff --cached --quiet; then echo dirty; "
        f'elif test "$({git} remote get-url origin)" != {repo}; then echo origin; '
        f"else {git} rev-parse HEAD; fi"
    )


def install_commands(cfg: OperationsApiConfig) -> list[str]:
    site = shlex.quote(str(cfg.site_path))
    repo = shlex.quote(cfg.git_repo)
    revision = shlex.quote(cfg.git_revision)
    git = "git -C " + site
    return [
        # A normal clone leaves a valid index if the later exact-SHA fetch fails.
        # No branch-specific or no-checkout intermediate state needs recovery.
        # Refuse tracked worktree/index changes again at execution, before fetch.
        f"if test -e {site}/.git; then {git} diff --quiet && {git} diff --cached --quiet; fi",
        f"if test ! -e {site}/.git; then git clone -- {repo} {site}; "
        f'elif test "$({git} remote get-url origin)" != {repo}; then {git} remote set-url origin {repo}; fi',
        f"{git} fetch origin {revision}",
        f"{git} checkout --detach {revision}",
        f'test "$({git} rev-parse HEAD)" = {revision} && {git} diff --quiet && {git} diff --cached --quiet',
    ]


def checkout(cfg: OperationsApiConfig) -> OperationMeta:
    # SDK git.repo has no revision argument and cannot drop to the original
    # service identity without repository-banned global become arguments.
    # Reuse the established runuser helper and one ordinary shell operation.
    inspect = _as_user(cfg.user, PurePosixPath(cfg.home), {}, ["/bin/sh", "-c", source_state(cfg)])
    current = host.get_fact(
        Command,
        command=("if id -u " + shlex.quote(cfg.user) + " >/dev/null 2>&1; then " + inspect + "; else echo missing; fi"),
    )
    if current == "dirty":
        raise DeployError("Operations API Git checkout has tracked local changes")
    if current not in {"missing", "origin"} and not re.fullmatch(r"[0-9a-f]{40}", current or ""):
        raise DeployError("Operations API Git source inspection failed")
    return server.shell(
        name="Checkout exact Operations API revision",
        commands=[
            _as_user(
                cfg.user, PurePosixPath(cfg.home), {}, ["/bin/sh", "-c", "set -eu\n" + "\n".join(install_commands(cfg))]
            )
        ],
        _if=lambda: current != cfg.git_revision,
    )
