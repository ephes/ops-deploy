"""vibe_coding: a dedicated interactive coding user (port of the ``vibe_coding_deploy`` role).

The steps run in the role's order (tasks/main.yml) and are decided while
planning from read-only probes, so a converged host gets no operation apart
from the role's always-run steps whose effect is nil (they are left out, see
docs/services/vibe_coding.md for the parity table and every difference):

user and group, ``~/.ssh`` (authorized_keys, rc, the agent-forwarding fish
snippet, no private keys), shell_basics (nested deploy), chezmoi from the
dotfiles repository, the GitHub CLI login, the projects directory, Node.js
from NodeSource, Neovim, lazygit, rustup with rust-analyzer, the per-user npm
tools, zellij, and the sshd ``Match User`` block.

The role clones the dotfiles on the host through a forwarded SSH agent. Here
the controller fetches them (:func:`prepare_dotfiles`, the operator's own git
and SSH setup) and ships a ``git bundle``; the host updates its checkout from
that bundle exactly as Ansible's ``git`` module would from the remote, and
keeps ``origin`` pointing at the repository. The host never needs the agent
or GitHub credentials.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory, File
from pyinfra.facts.server import Arch
from pyinfra.operations import apt, files, server

from ops_deploy.base._common import ensure_curl, output, release_install_script, require_linux
from ops_deploy.base.shell_basics import chezmoi_version, deploy_shell_basics
from ops_deploy.base.ssh_guard import reload_command
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.probes import probe
from ops_deploy.ops import secret_file
from ops_deploy.services.vibe_coding import host_scripts as scripts
from ops_deploy.services.vibe_coding.config import VibeCodingConfig
from ops_deploy.services.vibe_coding.render import (
    GITHUB_HOST,
    SSHD_MARKER,
    blockinfile,
    known_hosts,
    render,
    sshd_block,
)

FILES = Path(__file__).parent / "files"
NPM_TOOLS_SOURCE = (FILES / "npm_tools.py").read_text()
OWN_TREE_SOURCE = (FILES / "own_tree.py").read_text()
SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_SERVICE = "ssh"
CHEZMOI = "/usr/local/bin/chezmoi"
NODESOURCE_LIST = "/etc/apt/sources.list.d/nodesource.list"
NODESOURCE_KEYRING = "/etc/apt/keyrings/nodesource.gpg"
NODESOURCE_KEY_URL = "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
# Where the dotfiles bundle waits on the host while the checkout is updated.
STAGING_DIR = "/var/lib/ops-deploy/vibe-coding"
# Release architectures per tool (the role's arch maps).
NEOVIM_ARCH = {"x86_64": "x86_64", "aarch64": "arm64"}
LAZYGIT_ARCH = {"x86_64": "x86_64", "aarch64": "arm64"}
RUST_ARCH = {"x86_64": "x86_64", "aarch64": "aarch64"}


class _Dirs:
    """``ansible.builtin.file state=directory``: missing parents get the same owner and mode.

    Plans each missing directory once; a parent an earlier step creates is not
    planned again with another mode (it exists by the time Ansible gets there).
    """

    def __init__(self, cfg: VibeCodingConfig) -> None:
        self.cfg = cfg
        self.planned: set[str] = set()

    def ensure(self, path: PurePosixPath, mode: str, *, name: str | None = None) -> OperationMeta:
        missing = []
        for parent in reversed(path.parents):
            text = str(parent)
            if text == "/" or text in self.planned:
                continue
            if host.get_fact(Directory, path=text) is None and host.get_fact(File, path=text) is None:
                missing.append(text)
        for text in missing:
            self.planned.add(text)
            files.directory(name=f"Create {text}", path=text, user=self.cfg.user, group=self.cfg.group, mode=mode)
        self.planned.add(str(path))
        return files.directory(
            name=name or f"Ensure {path}", path=str(path), user=self.cfg.user, group=self.cfg.group, mode=mode
        )


def _arch() -> str:
    return host.get_fact(Arch) or ""


@deploy("Vibe coding")
def deploy_vibe_coding(cfg: VibeCodingConfig, secrets: SecretValues | None = None) -> None:
    require_linux("vibe_coding")
    values: Mapping[str, str] = secrets if secrets is not None else {}
    username = values.get("github_username", "")
    token = values.get("github_token", "")
    gh_enabled = bool(token)
    if gh_enabled and not username:
        raise DeployError("vibe_coding: a GitHub token needs github_username so gh can authenticate non-interactively")
    dirs = _Dirs(cfg)

    user_planned = _user(cfg)
    _ssh(cfg, dirs)
    deploy_shell_basics(cfg=cfg.effective_shell_basics(), user_planned=user_planned)
    if cfg.dotfiles is not None:
        _chezmoi(cfg)
    _github_cli(cfg, dirs, gh_enabled, username, token)
    dirs.ensure(cfg.projects_path, "0755", name=f"Ensure projects directory {cfg.projects_path}")
    if cfg.install_node:
        _nodejs(cfg)
    _neovim(cfg)
    _lazygit(cfg)
    if cfg.install_rust:
        _rust(cfg)
    if cfg.npm_tools:
        _coding_tools(cfg, dirs)
    if cfg.zellij_install:
        _zellij(cfg)
    if cfg.sshd_hardening:
        _sshd(cfg)


def _user(cfg: VibeCodingConfig) -> bool:
    """tasks/user.yml: the group and the login user with a locked password; True if created now."""

    state = scripts.parse_user(output(scripts.user_probe(cfg.user, cfg.group)))
    if not state.group_exists:
        server.shell(name=f"Ensure group {cfg.group}", commands=[f"groupadd {shlex.quote(cfg.group)}"])
    command = scripts.user_command(cfg, state)
    if command:
        server.shell(name=f"Ensure user {cfg.user}", commands=[command])
    return not state.user_exists


def _ssh(cfg: VibeCodingConfig, dirs: _Dirs) -> None:
    """tasks/ssh.yml."""

    ssh_dir = cfg.home / ".ssh"
    dirs.ensure(ssh_dir, "0700")
    for template, dest, mode in (
        ("authorized_keys.j2", ssh_dir / "authorized_keys", "0600"),
        ("ssh_rc.j2", ssh_dir / "rc", "0700"),
    ):
        files.put(
            name=f"Write {dest}",
            src=StringIO(render(template, cfg)),
            dest=str(dest),
            user=cfg.user,
            group=cfg.group,
            mode=mode,
        )
    conf_d = cfg.home / ".config/fish/conf.d"
    dirs.ensure(conf_d, "0755")
    snippet = conf_d / "ssh-agent-forward.fish"
    files.put(
        name=f"Write {snippet}",
        src=StringIO(render("ssh-agent-forward.fish.j2", cfg)),
        dest=str(snippet),
        user=cfg.user,
        group=cfg.group,
        mode="0644",
    )
    for key in scripts.private_keys(output(scripts.private_keys_probe(ssh_dir))):
        files.file(name=f"Remove SSH private key {key}", path=str(ssh_dir / key), present=False)


def _chezmoi(cfg: VibeCodingConfig) -> None:
    """tasks/chezmoi.yml, git flow: known hosts, the checkout, ownership, init and apply."""

    dotfiles = cfg.dotfiles
    assert dotfiles is not None
    source = cfg.chezmoi_source
    _known_hosts("/root/.ssh/known_hosts", "root", "root")
    _known_hosts(str(cfg.home / ".ssh/known_hosts"), cfg.user, cfg.group)

    checkout = scripts.parse_checkout(output(scripts.checkout_probe(cfg, source)))
    on_origin = checkout.is_git and checkout.origin == dotfiles.repo
    if on_origin and checkout.modified:
        raise DeployError(f"Local modifications exist in the destination: {source} (force=no).")

    safe = output("git config --global --get-all safe.directory").splitlines()
    if str(source) not in safe:
        server.shell(
            name=f"Mark {source} as a safe directory for root",
            commands=[f"git config --global --add safe.directory {shlex.quote(str(source))}"],
        )

    # The role's recursive ownership, before the update: the user's git needs
    # its own tree. A checkout the user's git wrote needs nothing afterwards.
    if output(scripts.foreign_owner_probe(source, cfg.user, cfg.group)):
        server.shell(
            name=f"Set ownership of {source}",
            commands=[scripts.own_tree_command(source, cfg.user, cfg.group, OWN_TREE_SOURCE)],
        )
    update = not on_origin or checkout.head != dotfiles.commit
    if update:
        files.directory(name=f"Ensure {STAGING_DIR}", path=STAGING_DIR, user="root", group="root", mode="0700")
        bundle = f"{STAGING_DIR}/dotfiles.bundle"
        files.put(
            name="Upload the dotfiles bundle",
            src=str(dotfiles.bundle),
            dest=bundle,
            user="root",
            group="root",
            mode="0600",
        )
        server.shell(
            name=(
                f"Update {source} to {dotfiles.commit[:12]}" if on_origin else f"Clone {dotfiles.repo} into {source}"
            ),
            commands=[scripts.checkout_command(cfg, source, bundle, dotfiles, reclone=not on_origin)],
        )

    basics = cfg.effective_shell_basics()
    chezmoi_changes = (
        update
        or (basics.manage_chezmoi and chezmoi_version(CHEZMOI) != basics.chezmoi_version)
        or probe(scripts.as_user(cfg, scripts.chezmoi_probe(source)), name="chezmoi pending changes") != "current"
    )
    if chezmoi_changes:
        server.shell(
            name="Initialize chezmoi and apply the dotfiles",
            commands=[scripts.as_user(cfg, scripts.chezmoi_apply(source))],
        )
    legacy = cfg.home / ".config/fish/functions/z.fish"
    files.file(name=f"Remove legacy {legacy}", path=str(legacy), present=False)


def _known_hosts(path: str, user: str, group: str) -> None:
    current = scripts.read_text(output(scripts.read_probe(path)))
    lookup = output(f"ssh-keygen -F {GITHUB_HOST} -f {shlex.quote(path)}") if current is not None else ""
    content = known_hosts(current, lookup)
    if content is None:
        return
    found = host.get_fact(File, path=path)
    info: Mapping[str, Any] = found or {}
    files.put(
        name=f"Trust GitHub's SSH host key in {path}",
        src=StringIO(content),
        dest=path,
        user=info.get("user", user),
        group=info.get("group", group),
        mode=str(info.get("mode", 644)),
    )


def _github_cli(cfg: VibeCodingConfig, dirs: _Dirs, enabled: bool, username: str, token: str) -> None:
    """tasks/github_cli.yml."""

    hosts = cfg.home / ".config/gh/hosts.yml"
    if not enabled:
        files.file(name=f"Remove {hosts} (GitHub CLI login not managed)", path=str(hosts), present=False)
        return
    dirs.ensure(hosts.parent, "0700")
    secret_file(
        name=f"Write {hosts}",
        path=str(hosts),
        content=SecretContent(render("gh-hosts.yml.j2", cfg, github_username=username, github_token=token)),
        user=cfg.user,
        group=cfg.group,
        mode="0600",
    )


def _nodejs(cfg: VibeCodingConfig) -> None:
    """tasks/nodejs.yml: NodeSource's line ``node_major_version`` (no apt pin, as the role)."""

    if not (host.get_fact(File, path=NODESOURCE_LIST) and host.get_fact(File, path=NODESOURCE_KEYRING)):
        apt.packages(name="Install NodeSource setup dependencies", packages=["ca-certificates", "curl", "gnupg"])
        files.directory(name="Ensure /etc/apt/keyrings", path="/etc/apt/keyrings", mode="0755")
        if not host.get_fact(File, path=NODESOURCE_KEYRING):
            server.shell(
                name="Install the NodeSource signing key",
                commands=[scripts.nodesource_key_command(NODESOURCE_KEY_URL, NODESOURCE_KEYRING)],
            )
    repo = files.put(
        name="Add NodeSource apt repository",
        src=StringIO(
            f"deb [signed-by={NODESOURCE_KEYRING}] https://deb.nodesource.com/node_{cfg.node_major_version}.x "
            "nodistro main\n"
        ),
        dest=NODESOURCE_LIST,
        mode="0644",
    )
    apt.update(name="Update apt cache after adding NodeSource", _if=repo.did_change)
    apt.packages(name="Install Node.js", packages=["nodejs"])


def _neovim(cfg: VibeCodingConfig) -> None:
    arch = NEOVIM_ARCH.get(_arch(), "")
    if not arch:
        raise DeployError(f"Unsupported architecture for Neovim release tarball: {_arch()}")
    first = output(scripts.secure("nvim --version")).split("\n", 1)[0]
    if scripts.search(f"NVIM v{cfg.neovim_version}", first):
        return
    if arch not in cfg.neovim_checksums:
        raise DeployError(f"vibe_coding: no Neovim checksum for {arch}")
    apt.packages(name="Remove apt neovim if present", packages=["neovim"], present=False)
    ensure_curl("vibe_coding")
    url = f"https://github.com/neovim/neovim/releases/download/v{cfg.neovim_version}/nvim-linux-{arch}.tar.gz"
    server.shell(
        name=f"Install Neovim {cfg.neovim_version} into /opt",
        commands=[scripts.extract_command(url, cfg.neovim_checksums[arch], "/opt")],
    )
    files.link(
        name="Symlink nvim to /usr/local/bin", path="/usr/local/bin/nvim", target=f"/opt/nvim-linux-{arch}/bin/nvim"
    )


def _lazygit(cfg: VibeCodingConfig) -> None:
    version = cfg.lazygit_version
    if scripts.search(scripts.regex_escape(version), output(scripts.secure("lazygit --version"))):
        return
    arch = LAZYGIT_ARCH.get(_arch(), "unsupported")
    if arch not in cfg.lazygit_checksums:
        raise DeployError(f"vibe_coding: no lazygit checksum for {arch}")
    ensure_curl("vibe_coding")
    url = f"https://github.com/jesseduffield/lazygit/releases/download/v{version}/lazygit_{version}_linux_{arch}.tar.gz"
    script = release_install_script(
        url=url, sha256=cfg.lazygit_checksums[arch], binaries={"lazygit": "lazygit"}, install_dir="/usr/local/bin"
    )
    server.shell(name=f"Install lazygit {version}", commands=[script])


def _rust(cfg: VibeCodingConfig) -> None:
    rustup = cfg.home / ".cargo/bin/rustup"
    installed = output(f"test -e {shlex.quote(str(rustup))} || test -L {shlex.quote(str(rustup))} && echo yes") == "yes"
    if not installed:
        arch = RUST_ARCH.get(_arch(), "unsupported")
        if arch not in cfg.rustup_checksums:
            raise DeployError(f"vibe_coding: no rustup checksum for {arch}")
        ensure_curl("vibe_coding")
        url = f"https://static.rust-lang.org/rustup/archive/{cfg.rustup_version}/{arch}-unknown-linux-gnu/rustup-init"
        server.shell(
            name=f"Install rustup {cfg.rustup_version} for {cfg.user}",
            commands=[scripts.as_user(cfg, scripts.rustup_command(url, cfg.rustup_checksums[arch]))],
        )
    components = (
        probe(scripts.as_user(cfg, f"{shlex.quote(str(rustup))} component list --installed"), name="rust components")
        if installed
        else None
    )
    if components is None or not any(line.startswith("rust-analyzer") for line in components.splitlines()):
        server.shell(
            name="Ensure rust-analyzer is installed",
            commands=[scripts.as_user(cfg, f"{shlex.quote(str(rustup))} component add rust-analyzer")],
        )


def _coding_tools(cfg: VibeCodingConfig, dirs: _Dirs) -> None:
    """tasks/coding_tools.yml."""

    prefix = cfg.npm_prefix_path
    dirs.ensure(prefix, "0755", name=f"Create per-user npm global directory {prefix}")
    current = probe(scripts.as_user(cfg, "npm config get prefix"), name="npm prefix")
    if current is None or current.strip() != str(prefix):
        server.shell(
            name=f"Configure npm global prefix {prefix} for {cfg.user}",
            commands=[scripts.as_user(cfg, f"npm config set prefix {shlex.quote(str(prefix))}")],
        )
    conf_d = cfg.home / ".config/fish/conf.d"
    dirs.ensure(conf_d, "0755")
    paths = conf_d / "npm-paths.fish"
    files.put(
        name=f"Write {paths}",
        src=StringIO(render("npm-paths.fish.j2", cfg)),
        dest=str(paths),
        user=cfg.user,
        group=cfg.group,
        mode="0644",
    )
    planned = probe(scripts.npm_tools_command("check", cfg, NPM_TOOLS_SOURCE), name="npm tools")
    if planned is None or planned.strip():
        server.shell(
            name="Install or update npm tools (system-wide copies removed)",
            commands=[scripts.npm_tools_command("apply", cfg, NPM_TOOLS_SOURCE)],
        )


def _zellij(cfg: VibeCodingConfig) -> None:
    if output(scripts.secure("which zellij")):
        return
    arch = RUST_ARCH.get(_arch(), "unsupported")
    if arch not in cfg.zellij_checksums or arch not in cfg.zellij_binary_checksums:
        raise DeployError(f"vibe_coding: no zellij checksums for {arch}")
    ensure_curl("vibe_coding")
    url = (
        f"https://github.com/zellij-org/zellij/releases/download/v{cfg.zellij_version}/"
        f"zellij-{arch}-unknown-linux-musl.tar.gz"
    )
    server.shell(
        name=f"Install zellij {cfg.zellij_version}",
        commands=[scripts.zellij_command(url, cfg.zellij_checksums[arch], cfg.zellij_binary_checksums[arch])],
    )


def _sshd(cfg: VibeCodingConfig) -> None:
    """tasks/sshd.yml and its handler, checked and rolled back on failure."""

    current = scripts.read_text(output(scripts.read_probe(SSHD_CONFIG, follow=True)))
    if current is None:
        raise DeployError(f"Path {SSHD_CONFIG} does not exist !")
    wanted = blockinfile(current, sshd_block(cfg.user), SSHD_MARKER)
    if wanted == current:
        return
    staged = "/etc/ssh/.sshd_config.ops-deploy-vibe-coding"
    files.put(name="Stage the sshd_config with the vibe Match block", src=StringIO(wanted), dest=staged, mode="0600")
    server.shell(
        name=f"Install {SSHD_CONFIG} after sshd -t and reload {SSHD_SERVICE}",
        commands=[scripts.sshd_install_command(staged, current, reload_command(SSHD_SERVICE))],
    )
