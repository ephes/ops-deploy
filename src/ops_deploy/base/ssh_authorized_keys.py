"""Own a user's whole ``authorized_keys`` file (the ``ssh_authorized_keys_manage`` role)."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, field_validator
from pyinfra.api import deploy
from pyinfra.operations import files

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_file

# The role's header line, kept byte for byte so switching tools rewrites nothing.
HEADER = "# Managed by Ansible - local.ops_library.ssh_authorized_keys_manage\n"
OneLine = Annotated[str, Field(pattern=r"^[^\r\n]*$")]


class AuthorizedKey(RoleConfig):
    key: OneLine
    comment: OneLine = ""
    # e.g. ``command="...",no-pty``
    key_options: OneLine = ""

    @field_validator("key")
    @classmethod
    def _key_present(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("key must not be empty")
        return value

    def line(self) -> str:
        options, comment = self.key_options.strip(), self.comment.strip()
        return f"{options + ' ' if options else ''}{self.key.strip()}{' ' + comment if comment else ''}\n"


class SshAuthorizedKeysConfig(RoleConfig):
    user: UnixUser = "root"
    # Defaults: the user's name, and ``/root`` or ``/home/<user>``.
    group: UnixUser | None = None
    home: AbsolutePath | None = None
    entries: tuple[AuthorizedKey, ...] = Field(min_length=1)

    @property
    def owner_group(self) -> str:
        return self.group or self.user

    @property
    def ssh_dir(self) -> PurePosixPath:
        home = self.home or ("/root" if self.user == "root" else f"/home/{self.user}")
        return PurePosixPath(home) / ".ssh"


def render_authorized_keys(cfg: SshAuthorizedKeysConfig) -> str:
    return HEADER + "".join(entry.line() for entry in cfg.entries)


@deploy("SSH authorized keys")
def deploy_ssh_authorized_keys(cfg: SshAuthorizedKeysConfig) -> None:
    files.directory(
        name=f"Ensure {cfg.ssh_dir}",
        path=str(cfg.ssh_dir),
        user=cfg.user,
        group=cfg.owner_group,
        mode="0700",
    )
    # Not secret, but secret_file replaces the file atomically (temp file and
    # rename): an interrupted upload can never leave a truncated file that
    # locks the operator out.
    secret_file(
        name=f"Write {cfg.ssh_dir}/authorized_keys",
        path=cfg.ssh_dir / "authorized_keys",
        content=SecretContent(render_authorized_keys(cfg)),
        user=cfg.user,
        group=cfg.owner_group,
        mode="0600",
    )
