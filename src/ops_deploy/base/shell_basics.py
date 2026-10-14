"""CLI essentials, chezmoi and a fish login shell (the ``shell_basics_deploy`` role)."""

from __future__ import annotations

import ipaddress
import re
import shlex
from io import StringIO
from typing import Annotated

from pydantic import Field, field_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import Directory, File, FileContents
from pyinfra.facts.server import Arch, Users
from pyinfra.operations import apt, files, server

from ops_deploy.base._common import (
    AbsolutePath,
    RoleConfig,
    Sha256,
    Version,
    ensure_curl,
    output,
    release_install_script,
    require_linux,
)
from ops_deploy.core.config import UnixUser

PACKAGES = (
    "fish", "bat", "fzf", "ripgrep", "fd-find", "eza", "tmux", "tree", "tig", "lsof", "sudo", "file",
    "git", "strace", "psmisc", "vim", "btop", "bmon", "sysstat", "iotop", "tealdeer", "just",
)  # fmt: skip
# The role's blockinfile markers: both tools edit the same block.
BLOCK_BEGIN = "# BEGIN ANSIBLE SHELL BASICS"
BLOCK_END = "# END ANSIBLE SHELL BASICS"
CHEZMOI_ARCHES = {"x86_64": "amd64", "aarch64": "arm64"}
# Debian renames these binaries; the deploy links the usual names into ~/.local/bin.
RENAMED = {"bat": ("bat", "/usr/bin/batcat"), "fd": ("fd-find", "/usr/bin/fdfind")}
Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]+$")]
FishLine = Annotated[str, Field(pattern=r"^[^\r\n]*$")]


class ShellBasicsConfig(RoleConfig):
    user: UnixUser = "root"
    # Empty: the user's home from /etc/passwd.
    user_home: AbsolutePath | None = None
    shell_path: AbsolutePath = "/usr/bin/fish"
    packages: tuple[Package, ...] = PACKAGES
    extra_packages: tuple[Package, ...] = ()
    switch_shell: bool = True
    manage_fish_config: bool = True
    fish_extra_config: tuple[FishLine, ...] = ()
    manage_chezmoi: bool = True
    chezmoi_version: Version = "2.73.1"
    chezmoi_install_dir: AbsolutePath = "/usr/local/bin"
    chezmoi_checksums: dict[str, Sha256] = Field(
        default_factory=lambda: {
            "amd64": "a3f958acb7d0e5d53fa43c2eec9bc8ae3b4fba8bcbfdce29a8881ca3ffc20a53",
            "arm64": "e60275b27f505ae2086bfb87b144eacf7377a89803120f6bd933d1852a93b0c6",
        }
    )
    apt_cache_valid_time: int = Field(default=3600, ge=0)
    # Replace /etc/resolv.conf when it lists only loopback nameservers (or none).
    fix_resolv_conf: bool = True
    resolv_fallback_nameservers: tuple[str, ...] = ("192.168.178.1", "1.1.1.1", "9.9.9.9")
    set_default_editor: bool = True
    default_editor_path: AbsolutePath = "/usr/bin/vim.basic"

    @field_validator("resolv_fallback_nameservers")
    @classmethod
    def _ip_addresses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            ipaddress.ip_address(item)
        return value

    @property
    def all_packages(self) -> list[str]:
        return list(dict.fromkeys((*self.packages, *self.extra_packages)))


def resolv_conf(nameservers: tuple[str, ...]) -> str:
    return "# Managed by shell_basics_deploy (fallback)\n" + "".join(f"nameserver {ns}\n" for ns in nameservers)


def only_loopback(nameservers: list[str]) -> bool:
    """The role's test: every nameserver is 127.x or ::1 (also true for none)."""

    return all(re.match(r"^(127\.|::1)", ns) for ns in nameservers)


def fish_block(cfg: ShellBasicsConfig, local_bin: str) -> list[str]:
    return [BLOCK_BEGIN, f"fish_add_path -g {local_bin}", *cfg.fish_extra_config, BLOCK_END]


def with_block(existing: list[str] | None, block: list[str]) -> str:
    """``existing`` lines with the marked block replaced, or appended if absent."""

    lines = list(existing or [])
    if BLOCK_BEGIN in lines:
        start = lines.index(BLOCK_BEGIN)
        end = lines.index(BLOCK_END, start) if BLOCK_END in lines[start:] else start
        lines[start : end + 1] = block
    else:
        lines.extend(block)
    return "\n".join(lines) + "\n"


def chezmoi_version(binary: str) -> str:
    match = re.match(r"^chezmoi version v?([0-9.]+)", output(f"{binary} --version"))
    return match.group(1).rstrip(".") if match else ""


@deploy("Shell basics")
def deploy_shell_basics(cfg: ShellBasicsConfig) -> None:
    require_linux("shell_basics")
    account = host.get_fact(Users).get(cfg.user)
    if account is None:
        raise DeployError(f"shell_basics: user {cfg.user} must exist")
    home = cfg.user_home or account.get("home") or ""
    if not home.startswith("/"):
        raise DeployError(f"shell_basics: no home directory for {cfg.user}")
    local_bin = f"{home}/.local/bin"

    if cfg.fix_resolv_conf:
        nameservers = output("awk '/^nameserver/ {print $2}' /etc/resolv.conf").split()
        if only_loopback(nameservers):
            content = resolv_conf(cfg.resolv_fallback_nameservers)
            # Renamed into place: replaces a symlink (systemd-resolved's stub)
            # with a file, as the role's copy does.
            server.shell(
                name="Write fallback /etc/resolv.conf",
                commands=[
                    "tmp=$(mktemp /etc/.resolv.conf.XXXXXX) && "
                    f'printf %s {shlex.quote(content)} >"$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" /etc/resolv.conf'
                ],
            )

    apt.update(name="Refresh apt cache", cache_time=cfg.apt_cache_valid_time)
    apt.packages(name="Install shell basics packages", packages=cfg.all_packages)

    if cfg.manage_chezmoi:
        _chezmoi(cfg)

    # Like the role's file module, missing parents are created owned by the user too.
    for parent in (f"{home}/.local", f"{home}/.config" if cfg.manage_fish_config else None):
        # None: absent (False would be a file or a symlink, left alone).
        if parent and host.get_fact(Directory, path=parent) is None:
            files.directory(name=f"Ensure {parent}", path=parent, user=cfg.user, group=cfg.user, mode="0755")
    files.directory(name=f"Ensure {local_bin}", path=local_bin, user=cfg.user, group=cfg.user, mode="0755")
    for name, (package, target) in RENAMED.items():
        # Checked before the packages install, so also link when it will be installed.
        if package in cfg.all_packages or host.get_fact(File, path=target):
            files.link(name=f"Link {name} to {target}", path=f"{local_bin}/{name}", target=target, force=True)

    if cfg.manage_fish_config:
        fish_dir = f"{home}/.config/fish"
        files.directory(name=f"Ensure {fish_dir}", path=fish_dir, user=cfg.user, group=cfg.user, mode="0755")
        config = f"{fish_dir}/config.fish"
        existing = host.get_fact(FileContents, path=config)
        files.put(
            name=f"Ensure shell basics block in {config}",
            src=StringIO(with_block(existing, fish_block(cfg, local_bin))),
            dest=config,
            user=cfg.user,
            group=cfg.user,
            mode="0644",
        )

    if cfg.switch_shell and account.get("shell") != cfg.shell_path:
        shell = shlex.quote(cfg.shell_path)
        server.shell(
            name=f"Switch login shell of {cfg.user} to {cfg.shell_path}",
            commands=[
                f"test -x {shell} || {{ echo 'shell {cfg.shell_path} not found' >&2; exit 1; }}",
                f"usermod -s {shell} {shlex.quote(cfg.user)}",
            ],
        )

    if cfg.set_default_editor:
        current = re.search(r"^Value: (\S+)", output("update-alternatives --query editor"), re.MULTILINE)
        if current is None or current.group(1) != cfg.default_editor_path:
            server.shell(
                name=f"Set default editor {cfg.default_editor_path}",
                commands=[f"update-alternatives --set editor {shlex.quote(cfg.default_editor_path)}"],
            )


def _chezmoi(cfg: ShellBasicsConfig) -> None:
    files.directory(name=f"Ensure {cfg.chezmoi_install_dir}", path=cfg.chezmoi_install_dir, mode="0755")
    binary = f"{cfg.chezmoi_install_dir}/chezmoi"
    if chezmoi_version(binary) == cfg.chezmoi_version:
        return
    arch = CHEZMOI_ARCHES.get(host.get_fact(Arch) or "", "unsupported")
    if arch not in cfg.chezmoi_checksums:
        raise DeployError(f"shell_basics: no pinned chezmoi checksum for {arch}")
    version = cfg.chezmoi_version
    ensure_curl("shell_basics")
    script = release_install_script(
        url=f"https://github.com/twpayne/chezmoi/releases/download/v{version}/chezmoi_{version}_linux_{arch}.tar.gz",
        sha256=cfg.chezmoi_checksums[arch],
        binaries={"chezmoi": "chezmoi"},
        install_dir=cfg.chezmoi_install_dir,
    )
    server.shell(name=f"Install chezmoi {version}", commands=[f"{script} && {binary} --version"])
