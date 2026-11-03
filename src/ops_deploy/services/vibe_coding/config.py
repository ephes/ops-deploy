"""``VibeCodingConfig``: the ``vibe_coding_deploy`` role's variables without the prefix."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar

from pydantic import Field, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, Sha256, Version
from ops_deploy.base.shell_basics import Package, ShellBasicsConfig
from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.git_source import CommitSha, GitSource

# One authorized_keys line: no line break, no NUL.
AuthorizedKey = Annotated[str, Field(pattern=r"^[^\r\n\x00]+$", max_length=16384)]
# An npm package spec as the role passes it to ``npm install -g --``: a name,
# optionally scoped, without version or path syntax.
NpmPackage = Annotated[str, Field(pattern=r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$", max_length=214)]
BranchName = Annotated[str, Field(pattern=r"^[A-Za-z0-9._/-]+$", max_length=255)]

# vibe_coding_deploy/defaults/main.yml (ops-library 8c5060e2, 2.75.x).
NPM_TOOLS = ("@anthropic-ai/claude-code", "@openai/codex", "opencode-ai", "@mariozechner/pi-coding-agent")
NEOVIM_CHECKSUMS = {
    "x86_64": "bce0f56eda1f1b1db6eee8f4133d7a38813ea07933837dd1777411ca384c6875",
    "arm64": "1aa5ca085249580ae0f91eb14f27ec0919773ff2d99a163d03f3d6c21ac29725",
}
LAZYGIT_CHECKSUMS = {
    "x86_64": "02beacbcda0fa342e50ae3480ba8147307353af3fb28e1d5f790e02329c201a6",
    "arm64": "49abecdf6adf4f2dfdb11bf7b9bfada267ea523612ed809d1c6d87f6c04000a7",
}
ZELLIJ_CHECKSUMS = {
    "x86_64": "40bcc2e03f5d5ae8e054e39f676081fe12ab70871506996ba595834c3718eefc",
    "aarch64": "05f0802afadd53f8db9514e7cae53c9ae8432fed1b35b8294aa816ee3044a16b",
}
ZELLIJ_BINARY_CHECKSUMS = {
    "x86_64": "d006c521dcb475a6005d741e9dd7c5758e5a23b28dd60a5c10cebfa4876319dd",
    "aarch64": "2a2c0621e6f3b11ecbb05d66939a48000a2508604620aa20727a5fd61c49f451",
}
RUSTUP_CHECKSUMS = {
    "x86_64": "5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4",
    "aarch64": "a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697",
}


class Dotfiles(GitSource):
    """The chezmoi source repository, fetched on the controller (:func:`prepare_dotfiles`).

    ``repo`` is the URL the host's checkout keeps as ``origin`` (the role's
    ``vibe_coding_dotfiles_repo``); ``bundle`` is a ``git bundle`` of every
    branch and tag on the controller, ``branch`` the remote's default branch
    and ``commit`` its tip, which the host's checkout ends up on.
    """

    bundle: Path
    branch: BranchName
    commit: CommitSha

    @field_validator("branch")
    @classmethod
    def _plain_branch(cls, value: str) -> str:
        if value.startswith(("-", "/", ".")) or value.endswith(("/", ".", ".lock")) or ".." in value:
            raise ValueError("branch must be a plain branch name")
        return value


class VibeCodingConfig(BaseServiceConfig):
    """The ``vibe_coding_*`` variables the deploy reads, without the prefix (the role's defaults).

    ``secrets`` (optional) names the file with ``github_username`` and
    ``github_token``; the GitHub CLI login is managed when the token is set
    (the playbook's ``vibe_coding_github_cli_auth_enabled``).
    """

    required_secret_keys: ClassVar[tuple[str, ...]] = ()

    service_name: ServiceName = "vibe_coding"
    user: UnixUser = "vibe"
    group: UnixUser = "vibe"
    # The user's home (``vibe_coding_user_home``).
    site_path: PurePosixPath = PurePosixPath("/mnt/cryptdata/vibe")
    shell: AbsolutePath = "/usr/bin/fish"
    # None: ``<home>/projects``.
    projects_dir: PurePosixPath | None = None
    ssh_authorized_keys: tuple[AuthorizedKey, ...] = ()
    # None: the role's chezmoi tasks are skipped (no ``vibe_coding_dotfiles_repo``).
    dotfiles: Dotfiles | None = None
    shell_basics_extra_packages: tuple[Package, ...] = ("gh", "zoxide")
    # shell_basics_deploy's own settings (host vars and role defaults); the
    # role's include always sets user, home, extra packages, no fish config
    # and the shell switch, so those five fields are replaced.
    shell_basics: ShellBasicsConfig = Field(default_factory=ShellBasicsConfig)
    install_node: bool = True
    node_major_version: Version = "22"
    neovim_version: Version = "0.12.5"
    lazygit_version: Version = "0.65.1"
    install_rust: bool = True
    rustup_version: Version = "1.29.2"
    # None: ``<home>/.npm-global``.
    npm_prefix: PurePosixPath | None = None
    npm_tools: tuple[NpmPackage, ...] = NPM_TOOLS
    zellij_install: bool = True
    zellij_version: Version = "0.45.1"
    sshd_hardening: bool = True
    neovim_checksums: dict[str, Sha256] = Field(default_factory=lambda: dict(NEOVIM_CHECKSUMS))
    lazygit_checksums: dict[str, Sha256] = Field(default_factory=lambda: dict(LAZYGIT_CHECKSUMS))
    zellij_checksums: dict[str, Sha256] = Field(default_factory=lambda: dict(ZELLIJ_CHECKSUMS))
    zellij_binary_checksums: dict[str, Sha256] = Field(default_factory=lambda: dict(ZELLIJ_BINARY_CHECKSUMS))
    rustup_checksums: dict[str, Sha256] = Field(default_factory=lambda: dict(RUSTUP_CHECKSUMS))

    @field_validator("projects_dir", "npm_prefix")
    @classmethod
    def _absolute(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        if value is not None and (not value.is_absolute() or ".." in value.parts or value == PurePosixPath("/")):
            raise ValueError("must be an absolute path below /")
        return value

    @field_validator("site_path")
    @classmethod
    def _plain_home(cls, value: PurePosixPath) -> PurePosixPath:
        # Rendered into the sshd Match block's neighbours, ~/.ssh/rc and shell
        # scripts: no characters a shell or template would read specially.
        if not re.fullmatch(r"/[A-Za-z0-9._/+-]*", str(value)):
            raise ValueError("site_path may only use letters, digits and . _ / + -")
        return value

    @model_validator(mode="after")
    def _role_asserts(self) -> VibeCodingConfig:
        # tasks/main.yml "Validate required variables" (the GitHub part is
        # checked against the secrets when the deploy starts).
        if not self.ssh_authorized_keys:
            raise ValueError(
                "ssh_authorized_keys must not be empty: the user has a locked password "
                "and needs at least one SSH key to be reachable"
            )
        if self.group != self.user:
            # shell_basics gives the user's files to the group named like the
            # user (as its role does), which would not exist.
            raise ValueError("group must be named like user: shell_basics uses the user's own group")
        if self.npm_tools and not self.install_node:
            raise ValueError("npm_tools requires install_node: the tools are installed with npm")
        return self

    @property
    def home(self) -> PurePosixPath:
        return self.site_path

    @property
    def projects_path(self) -> PurePosixPath:
        return self.projects_dir or self.home / "projects"

    @property
    def npm_prefix_path(self) -> PurePosixPath:
        return self.npm_prefix or self.home / ".npm-global"

    @property
    def chezmoi_source(self) -> PurePosixPath:
        return self.home / ".local/share/chezmoi"

    def effective_shell_basics(self) -> ShellBasicsConfig:
        """tasks/shell.yml: the include's five variables over shell_basics' own settings."""

        data: dict[str, Any] = self.shell_basics.model_dump()
        data.update(
            user=self.user,
            user_home=str(self.home),
            extra_packages=self.shell_basics_extra_packages,
            manage_fish_config=False,
            switch_shell=True,
            # Not set by the role's include (shell_basics' default is fish):
            # one login shell for both steps, so they never undo each other.
            shell_path=self.shell,
        )
        return ShellBasicsConfig(**data)
