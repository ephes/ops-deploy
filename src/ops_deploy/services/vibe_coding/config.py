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
    "x86_64": "474430d53e6264f6d6dd18db42d6dc9df3a1b56ca9e88a325bbf860e1a811d87",
    "arm64": "8f1f64a0bdb97247034038c3823c6cbad5bdf9ecd5751b85494b71c3ee04c815",
}
LAZYGIT_CHECKSUMS = {
    "x86_64": "0a23f429a95f0d09db298b3c291536d818de066aa5a85c255806f0490ff6656b",
    "arm64": "ac0b48237f3d0283813e7154ec063237e519532feb0470c0881a1793ee78fd42",
}
ZELLIJ_CHECKSUMS = {
    "x86_64": "a8ee599eb357b6142443c91506a4ece3aa8811cb75dcf2b28d194bd66853c79d",
    "aarch64": "c416b3d29ec9c71baf8754fe66663afe4f615395895e3f9b8b6e3bd0f7042427",
}
ZELLIJ_BINARY_CHECKSUMS = {
    "x86_64": "afb6bfb5f9fdc3d9e9d094ce21866bc99d37073a5fbe75bb612e21fc9b96033d",
    "aarch64": "09cc9f60eb122987c10221fa559aa00c441333a23ba53d727c807f36c5222147",
}
RUSTUP_CHECKSUMS = {
    "x86_64": "b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55",
    "aarch64": "9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282",
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
    neovim_version: Version = "0.12.6"
    lazygit_version: Version = "0.66.3"
    install_rust: bool = True
    rustup_version: Version = "1.29.3"
    # None: ``<home>/.npm-global``.
    npm_prefix: PurePosixPath | None = None
    npm_tools: tuple[NpmPackage, ...] = NPM_TOOLS
    zellij_install: bool = True
    zellij_version: Version = "0.46.0"
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
