"""The tree, its group and the one-time repair of what was copied in before (``storage.yml``).

The repair finds entries outside the group model while planning (``find
... -print -quit``, read-only) and adds an operation only for what it found,
so a converged tree gets no operation: entries without the group get it
(``chgrp -h``), directories without group ``rwx`` and setgid get them, files
without group ``rw`` get them. ``foreign`` subtrees (owned by another deploy)
are left alone.
"""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import AfterValidator, Field, model_validator
from pyinfra.api import deploy
from pyinfra.operations import files, server

from ops_deploy.base._common import RoleConfig, output
from ops_deploy.core.config import UnixUser
from ops_deploy.helpers import mark_read_only
from ops_deploy.services.compose_app.config import plain_path

PlainPath = Annotated[PurePosixPath, AfterValidator(plain_path)]


class SharedTreeConfig(RoleConfig):
    root: PlainPath
    group: UnixUser
    mode: Annotated[str, Field(pattern=r"^0?[0-7]{4}$")] = "2775"
    # Every directory of the tree, the root included (created root:<group> with ``mode``).
    directories: tuple[PlainPath, ...] = Field(min_length=1)
    # Subtrees another deploy owns; the repair skips them.
    foreign: tuple[PlainPath, ...] = ()
    # Mount points the tree must live on (the deploy stops before any change otherwise).
    mounts_required: tuple[PlainPath, ...] = ()

    @model_validator(mode="after")
    def _inside(self) -> SharedTreeConfig:
        outside = [str(p) for p in (*self.directories, *self.foreign) if not p.is_relative_to(self.root)]
        if outside:
            raise ValueError(f"{', '.join(outside)} lie outside root {self.root}")
        if self.root not in self.directories:
            raise ValueError("directories must include root")
        return self


def _find(cfg: SharedTreeConfig, *condition: str) -> str:
    prune = [part for path in cfg.foreign for part in ("-path", str(path), "-prune", "-o")]
    return shlex.join(["find", str(cfg.root), *prune, *condition])


@deploy("Deploy shared tree")
def deploy_shared_tree(cfg: SharedTreeConfig) -> None:
    for mount in cfg.mounts_required:
        quoted = shlex.quote(str(mount))
        mark_read_only(
            server.shell(
                name=f"Require the mount {mount}",
                commands=[
                    f"findmnt --mountpoint {quoted} >/dev/null || {{ echo {quoted}' is not mounted' >&2; exit 1; }}"
                ],
            )
        )
    server.group(name=f"Ensure group {cfg.group}", group=cfg.group, system=True)
    mode = cfg.mode.rjust(4, "0")
    for path in cfg.directories:
        files.directory(name=f"Ensure directory {path}", path=str(path), user="root", group=cfg.group, mode=mode)
    repairs = (
        (f"Give entries outside the group to {cfg.group}", ("!", "-group", cfg.group), f"chgrp -h {cfg.group}"),
        ("Make directories group-writable and setgid", ("-type", "d", "!", "-perm", "-2070"), "chmod g+rwxs"),
        ("Make files group-writable", ("-type", "f", "!", "-perm", "-0060"), "chmod g+rw"),
    )
    # Without the group yet, `find ! -group` fails while planning: every entry needs it.
    root_exists = output(f"test -d {shlex.quote(str(cfg.root))} && echo yes").strip() == "yes"
    group_exists = bool(output(f"getent group {shlex.quote(cfg.group)}").strip())
    for name, condition, action in repairs:
        regroup = action.startswith("chgrp") and root_exists and not group_exists
        if regroup or output(_find(cfg, *condition, "-print", "-quit")).strip():
            server.shell(name=name, commands=[f"{_find(cfg, *condition, '-print0')} | xargs -0 -r {action}"])
