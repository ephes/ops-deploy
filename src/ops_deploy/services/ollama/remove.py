"""Port of the ``ollama_remove`` role (macOS): its defaults, checks and order.

Never dispatched without ``confirm`` (the role has no confirmation; every
caller of this port must pass one). It boots the LaunchDaemon out and deletes
its plist; with the role's flags it also deletes the models directory, the log
directory, the service user and group (``dscl``/``dseditgroup``, the user's
home stays, as with ``remove: false``) and the Homebrew package (``brew
uninstall --force``, as ``brew_user``). Every flag keeps the role's default
(off); a caller opts in exactly as with ``-e ollama_remove_*=true``.
"""

from __future__ import annotations

import shlex
from collections.abc import Generator
from pathlib import PurePosixPath
from typing import Annotated, Self

from pydantic import Field, StrictBool, model_validator
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.facts.server import Command, Os
from pyinfra.operations import server

from ops_deploy.base._common import RoleConfig, output
from ops_deploy.core.config import UnixUser
from ops_deploy.services._lifecycle.ansible_remove import absent

Path = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/+-]*$")]
Label = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")]
Package = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_@./+-]*$")]
BREWS = ("/opt/homebrew/bin/brew", "/usr/local/bin/brew")


class OllamaRemoveConfig(RoleConfig):
    """``ollama_remove``'s defaults; ``brew_user``/``brew_bin`` empty as there."""

    confirm: StrictBool = False
    launchd_label: Label = "com.ollama.ollama"
    launchd_plist_path: Path = ""
    service_user: UnixUser = "ollama"
    service_group: UnixUser = "ollama"
    service_home: Path = "/usr/local/var/ollama"
    models_dir: Path = "/usr/local/var/ollama/models"
    log_dir: Path = "/usr/local/var/ollama/logs"
    brew_package: Package = "ollama"
    brew_user: UnixUser | None = None
    brew_bin: Path | None = None
    remove_data: StrictBool = False
    remove_logs: StrictBool = False
    remove_user: StrictBool = False
    remove_brew_package: StrictBool = False

    @model_validator(mode="before")
    @classmethod
    def plist_from_label(cls, value: object) -> object:
        if isinstance(value, dict) and not value.get("launchd_plist_path"):
            label = value.get("launchd_label", "com.ollama.ollama")
            return {**value, "launchd_plist_path": f"/Library/LaunchDaemons/{label}.plist"}
        return value

    @model_validator(mode="after")
    def bounded(self) -> Self:
        for value in (self.launchd_plist_path, self.service_home, self.models_dir, self.log_dir, self.brew_bin):
            if value is None:
                continue
            path = PurePosixPath(value)
            if len(path.parts) < 3 or ".." in path.parts:
                raise ValueError("removal paths must not be root, a top-level directory or contain traversal")
        if "root" in (self.service_user, self.service_group):
            raise ValueError("root cannot be the Ollama service account")
        return self


def _present(path: str) -> bool:
    # ``state: absent`` also removes a dangling symlink.
    quoted = shlex.quote(path)
    return output(f"{{ test -e {quoted} || test -L {quoted}; }} && echo yes").strip() == "yes"


def _brew_bin(cfg: OllamaRemoveConfig) -> str:
    """The role's resolution: ``brew_bin``, else the first Homebrew prefix with a ``brew``."""

    if cfg.brew_bin:
        return cfg.brew_bin
    for candidate in BREWS:
        if _present(candidate):
            return candidate
    raise DeployError("Homebrew binary not found. Set brew_bin to the brew path.")


def _as_brew_user(cfg: OllamaRemoveConfig, brew: str, *args: str) -> str:
    # As the deploy runs Homebrew: sudo -H, no login shell (the user's may be fish).
    assert cfg.brew_user is not None
    return "cd / && " + shlex.join(
        [
            "/usr/bin/sudo",
            "-H",
            "-u",
            cfg.brew_user,
            "--",
            "/usr/bin/env",
            "HOMEBREW_NO_AUTO_UPDATE=1",
            "HOMEBREW_NO_ANALYTICS=1",
            brew,
            *args,
        ]
    )


@operation()
def _user_absent(user: str) -> Generator[StringCommand, None, None]:
    """``user: state=absent, remove: false`` on Darwin: ``dscl . -delete`` when the record has a UniqueID."""

    quoted = shlex.quote("/Users/" + user)
    state = host.get_fact(
        Command, command=f"/usr/bin/dscl . -read {quoted} UniqueID >/dev/null 2>&1 && echo present || echo absent"
    )
    if state == "present":
        yield StringCommand(f"/usr/bin/dscl . -delete {quoted}")


GROUP_PROBE = """import grp, sys
try:
    grp.getgrnam(sys.argv[1])
except KeyError:
    print('absent')
else:
    print('present')
"""


@operation()
def _group_absent(group: str) -> Generator[StringCommand, None, None]:
    """``group: state=absent`` on Darwin: ``dseditgroup -o delete`` when ``grp`` knows the group."""

    probe = shlex.join(["/usr/bin/python3", "-I", "-B", "-c", GROUP_PROBE, group])
    state = host.get_fact(Command, command=f"{probe} 2>/dev/null || echo error")
    if state not in ("present", "absent"):
        raise DeployError(f"Cannot inspect the group {group}")
    if state == "present":
        yield StringCommand(shlex.join(["/usr/sbin/dseditgroup", "-o", "delete", "-L", group]))


@operation()
def _brew_absent(cfg: OllamaRemoveConfig, brew: str) -> Generator[StringCommand, None, None]:
    """``community.general.homebrew`` ``state: absent``: ``uninstall --force`` only when installed.

    The module asks ``brew info`` for formulae and casks; here both listings
    must succeed (a failing sudo or brew is an error, never "not installed").
    """

    listings: list[str] = []
    for kind in ("--formula", "--cask"):
        listed = host.get_fact(
            Command,
            command=(
                f"if out=$({_as_brew_user(cfg, brew, 'list', kind, '-1')}); "
                "then printf 'listed\\n%s\\n' \"$out\"; else echo error; fi"
            ),
        )
        lines = (listed or "").splitlines()
        if not lines or lines[0] != "listed":
            raise DeployError("Cannot inspect the Ollama Homebrew package")
        listings.extend(line.strip() for line in lines[1:])
    if cfg.brew_package in listings:
        yield StringCommand(_as_brew_user(cfg, brew, "uninstall", "--force", cfg.brew_package))


@deploy("Remove Ollama (macOS)")
def remove_ollama(cfg: OllamaRemoveConfig) -> None:
    if not cfg.confirm:
        raise DeployError("Ollama removal requires confirm=true")
    if host.get_fact(Os) != "Darwin":
        raise DeployError("ollama_remove only supports macOS targets.")
    brew = ""
    if cfg.remove_brew_package:
        # The role requires it only as root (Homebrew refuses to run as root);
        # this port always runs Homebrew through sudo as brew_user.
        if not cfg.brew_user:
            raise DeployError("brew_user must be set for the Homebrew uninstall (Homebrew refuses to run as root).")
        brew = _brew_bin(cfg)
    # ``launchctl bootout system <plist>``: failures ignored, never a change;
    # without the plist it has nothing to read the job from.
    if _present(cfg.launchd_plist_path):
        server.shell(
            name="Stop and unload the Ollama LaunchDaemon",
            commands=[f"/bin/launchctl bootout system {shlex.quote(cfg.launchd_plist_path)} || true"],
        )
    absent(f"Remove {cfg.launchd_plist_path}", cfg.launchd_plist_path)
    if cfg.remove_data:
        absent(f"Remove {cfg.models_dir}", cfg.models_dir)
    if cfg.remove_logs:
        absent(f"Remove {cfg.log_dir}", cfg.log_dir)
    if cfg.remove_user:
        _user_absent(name=f"Remove user {cfg.service_user}", user=cfg.service_user)
        _group_absent(name=f"Remove group {cfg.service_group}", group=cfg.service_group)
    if cfg.remove_brew_package:
        _brew_absent(name=f"Uninstall the {cfg.brew_package} Homebrew package", cfg=cfg, brew=brew)
