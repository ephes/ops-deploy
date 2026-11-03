"""vibe_coding: config, rendering, the role's edits and plans on fake hosts.

The real-host behaviour (Ansible first, then pyinfra; fresh host; drift and
sshd rollback) is covered by ``tests/test_vibe_coding_docker.py``.
"""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from ops_deploy.base import ShellBasicsConfig
from ops_deploy.core.config import ConfigValidationError
from ops_deploy.core.git_source import GitSourceError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.vibe_coding import (
    Dotfiles,
    VibeCodingConfig,
    blockinfile,
    deploy_vibe_coding,
    known_hosts,
    prepare_dotfiles,
    render,
    sshd_block,
)
from ops_deploy.services.vibe_coding import host_scripts as scripts
from ops_deploy.services.vibe_coding.render import GITHUB_KEY, SSHD_MARKER
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISyntheticVibeCodingKey000000000000000 vibe@example.invalid"
HOME = "/mnt/cryptdata/vibe"
SOURCE = f"{HOME}/.local/share/chezmoi"
REPO = "git@github.com:example/dotfiles.git"
COMMIT = "1" * 40
TOKEN = "gho_" + "SyntheticFakeHostToken0000000000000000"  # pragma: allowlist secret
PACKAGE_TEMPLATES = Path(__file__).parents[1] / "src/ops_deploy/services/vibe_coding/templates"
SSHD_BASE = "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\n"


def dotfiles(tmp_path: Path) -> Dotfiles:
    bundle = tmp_path / "dotfiles.bundle"
    bundle.write_bytes(b"# v2 git bundle\n")
    return Dotfiles(repo=REPO, bundle=bundle, branch="main", commit=COMMIT)


def cfg(tmp_path: Path, **overrides: Any) -> VibeCodingConfig:
    fields: dict[str, Any] = {"ssh_authorized_keys": (KEY,), "dotfiles": dotfiles(tmp_path)}
    fields.update(overrides)
    return VibeCodingConfig(**fields)


def secrets(username: str = "octo", token: str = TOKEN) -> SecretValues:
    return SecretValues(SecretRef("secrets/test/vibe-coding.yml"), {"github_username": username, "github_token": token})


def present(content: str) -> list[str]:
    return ["present", base64.b64encode(content.encode()).decode()]


def converged(config: VibeCodingConfig, **extra: Any) -> dict[str, Any]:
    """Fake responses for a host the deploy (or the role) fully converged."""

    home = str(config.home)
    sshd = blockinfile(SSHD_BASE, sshd_block("vibe"), SSHD_MARKER)
    known = GITHUB_KEY + "\n"
    responses: dict[str, Any] = {
        **LINUX,
        "uname -m": ["x86_64"],
        "u=vibe; g=vibe": [
            "group=yes",
            "groupgid=1001",
            "user=yes",
            f"passwd=vibe:x:1001:1001::{home}:/usr/bin/fish",
            "locked=yes",
            "pwmatch=yes",
            "members=",
        ],
        "cat /etc/passwd | cut": [
            "root:x:0:0:root:/root:/usr/bin/fish|root|root||!",
            f"vibe:x:1001:1001::{home}:/usr/bin/fish|vibe|vibe||!",
        ],
        "awk '/^nameserver/": ["192.168.178.1"],
        "/usr/local/bin/chezmoi --version": ["chezmoi version v2.73.1, commit abc, built at 2026-01-01T00:00:00Z"],
        "update-alternatives --query editor": ["Name: editor", "Status: manual", "Value: /usr/bin/vim.basic"],
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed(*config.effective_shell_basics().all_packages, "nodejs"),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory(f"{home}/.local"),
        **fakehost.directory(f"{home}/.local/bin", user="vibe"),
        **fakehost.symlink(f"{home}/.local/bin/bat", "/usr/bin/batcat"),
        **fakehost.symlink(f"{home}/.local/bin/fd", "/usr/bin/fdfind"),
        "p=/root/.ssh/known_hosts;": present(known),
        f"p={home}/.ssh/known_hosts;": present(known),
        "ssh-keygen -F github.com": ["# Host github.com found: line 1", GITHUB_KEY],
        "[ -e /mnt/cryptdata/vibe/.local/share/chezmoi/.git ]": [
            "git=yes",
            f"origin={REPO}",
            f"head={COMMIT}",
            "mods=no",
        ],
        "git config --global --get-all safe.directory": [SOURCE],
        "! -user vibe -print -quit": [],
        "bash -c 'set -o pipefail; C=/usr/local/bin/chezmoi": ["current"],
        "env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin nvim --version": [
            "NVIM v0.12.5",
            "Build type: Release",
        ],
        "lazygit --version": ["commit=abc, build date=x, version=0.65.1, os=linux, arch=amd64"],
        "/.cargo/bin/rustup || test -L": ["yes"],
        "component list --installed": ["rust-analyzer-x86_64-unknown-linux-gnu", "rustc-x86_64-unknown-linux-gnu"],
        "npm config get prefix": [f"{home}/.npm-global"],
        "python3 -I -c": [],
        "which zellij": ["/usr/local/bin/zellij"],
        "p=$(readlink -f /etc/ssh/sshd_config)": present(sshd),
        **fakehost.file("/etc/apt/keyrings/nodesource.gpg", "key"),
        **fakehost.file(
            "/etc/apt/sources.list.d/nodesource.list",
            "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main\n",
        ),
        **fakehost.file(
            f"{home}/.config/gh/hosts.yml",
            render("gh-hosts.yml.j2", config, github_username="octo", github_token=TOKEN),
            user="vibe",
            mode="-rw-------",
        ),
    }
    for path, mode in (
        ("/mnt", "drwxr-xr-x"),
        ("/mnt/cryptdata", "drwxr-xr-x"),
        (home, "drwxr-x---"),
        (f"{home}/.ssh", "drwx------"),
        (f"{home}/.config", "drwx------"),
        (f"{home}/.config/fish", "drwxr-xr-x"),
        (f"{home}/.config/fish/conf.d", "drwxr-xr-x"),
        (f"{home}/.config/gh", "drwx------"),
        (f"{home}/projects", "drwxr-xr-x"),
        (f"{home}/.npm-global", "drwxr-xr-x"),
        ("/etc/apt/keyrings", "drwxr-xr-x"),
        ("/etc/apt/sources.list.d", "drwxr-xr-x"),
    ):
        owner = "vibe" if path.startswith(home) else "root"
        responses.update(fakehost.stat(path, user=owner, mode=mode))
    for template, path, mode in (
        ("authorized_keys.j2", f"{home}/.ssh/authorized_keys", "-rw-------"),
        ("ssh_rc.j2", f"{home}/.ssh/rc", "-rwx------"),
        ("ssh-agent-forward.fish.j2", f"{home}/.config/fish/conf.d/ssh-agent-forward.fish", "-rw-r--r--"),
        ("npm-paths.fish.j2", f"{home}/.config/fish/conf.d/npm-paths.fish", "-rw-r--r--"),
    ):
        responses.update(fakehost.file(path, render(template, config), user="vibe", mode=mode))
    responses.update(extra)
    return responses


# -- config ---------------------------------------------------------------------


def test_defaults_are_the_roles() -> None:
    config = VibeCodingConfig(ssh_authorized_keys=(KEY,))
    assert (config.user, config.group, str(config.home), config.shell) == ("vibe", "vibe", HOME, "/usr/bin/fish")
    assert config.projects_path == PurePosixPath(f"{HOME}/projects")
    assert config.npm_prefix_path == PurePosixPath(f"{HOME}/.npm-global")
    assert config.npm_tools == (
        "@anthropic-ai/claude-code",
        "@openai/codex",
        "opencode-ai",
        "@mariozechner/pi-coding-agent",
    )
    assert (config.node_major_version, config.neovim_version, config.lazygit_version) == ("22", "0.12.5", "0.65.1")
    assert (config.rustup_version, config.zellij_version) == ("1.29.2", "0.45.1")
    assert config.dotfiles is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"ssh_authorized_keys": ()}, "ssh_authorized_keys must not be empty"),
        ({"install_node": False}, "npm_tools requires install_node"),
        ({"site_path": "/mnt/vibe home"}, "site_path may only use"),
        ({"ssh_authorized_keys": ("ssh-ed25519 AAAA\nssh-rsa BBBB",)}, "string_pattern_mismatch"),
        ({"npm_tools": ("left-pad@1.0.0",)}, "string_pattern_mismatch"),
        ({"projects_dir": "relative"}, "absolute"),
        ({"group": "coders"}, "group must be named like user"),
    ],
)
def test_role_asserts_and_strict_inputs(overrides: dict[str, Any], message: str) -> None:
    fields: dict[str, Any] = {"ssh_authorized_keys": (KEY,), **overrides}
    with pytest.raises(ConfigValidationError, match=message):
        VibeCodingConfig(**fields)


def test_npm_tools_without_node_is_fine_when_empty() -> None:
    assert VibeCodingConfig(ssh_authorized_keys=(KEY,), install_node=False, npm_tools=()).npm_tools == ()


def test_shell_basics_include_overrides_five_fields() -> None:
    base = ShellBasicsConfig(fix_resolv_conf=False, extra_packages=("htop",), manage_fish_config=True)
    effective = VibeCodingConfig(ssh_authorized_keys=(KEY,), shell_basics=base).effective_shell_basics()
    assert (effective.user, effective.user_home, effective.extra_packages) == ("vibe", HOME, ("gh", "zoxide"))
    assert (effective.manage_fish_config, effective.switch_shell, effective.fix_resolv_conf) == (False, True, False)
    bash = VibeCodingConfig(ssh_authorized_keys=(KEY,), shell="/bin/bash").effective_shell_basics()
    assert bash.shell_path == "/bin/bash"


# -- rendering --------------------------------------------------------------------


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
@pytest.mark.parametrize("name", sorted(path.name for path in PACKAGE_TEMPLATES.iterdir()))
def test_templates_are_the_roles(name: str) -> None:
    role = Path(os.environ["OPS_LIBRARY_PATH"], "roles/vibe_coding_deploy/templates", name)
    assert (PACKAGE_TEMPLATES / name).read_bytes() == role.read_bytes()


def test_rendered_files(tmp_path: Path) -> None:
    config = cfg(tmp_path, ssh_authorized_keys=(KEY, "ssh-rsa AAAAB3Nza second"))
    assert render("authorized_keys.j2", config) == (
        f"# Managed by Ansible — vibe_coding_deploy role\n{KEY}\nssh-rsa AAAAB3Nza second\n"
    )
    assert render("ssh_rc.j2", config).endswith(f'    ln -sf "$SSH_AUTH_SOCK" "{HOME}/.ssh/auth_sock"\nfi\n')
    assert render("gh-hosts.yml.j2", config, github_username="octo", github_token=TOKEN) == (
        f'github.com:\n  user: "octo"\n  oauth_token: "{TOKEN}"\n  git_protocol: ssh\n  users:\n    "octo": {{}}\n'
    )
    assert f'set -gx PATH "{HOME}/.npm-global/bin" $PATH' in render("npm-paths.fish.j2", config)


# -- blockinfile and known_hosts ------------------------------------------------------

BLOCK = (
    f"# BEGIN ANSIBLE MANAGED — vibe_coding_deploy\n{sshd_block('vibe')}# END ANSIBLE MANAGED — vibe_coding_deploy\n"
)


def test_blockinfile_appends_replaces_and_is_stable() -> None:
    assert blockinfile(SSHD_BASE, sshd_block("vibe"), SSHD_MARKER) == SSHD_BASE + BLOCK
    # A last line without a newline gets one before the block.
    assert blockinfile("UsePAM yes", sshd_block("vibe"), SSHD_MARKER) == "UsePAM yes\n" + BLOCK
    # An existing block is replaced in place; what follows it stays.
    old = SSHD_BASE + BLOCK.replace("AllowTcpForwarding no", "AllowTcpForwarding yes") + "Subsystem sftp x\n"
    assert blockinfile(old, sshd_block("vibe"), SSHD_MARKER) == SSHD_BASE + BLOCK + "Subsystem sftp x\n"
    converged = SSHD_BASE + BLOCK
    assert blockinfile(converged, sshd_block("vibe"), SSHD_MARKER) == converged
    # Only a BEGIN marker: treated as absent, the block is appended (Ansible's behaviour).
    begin_only = SSHD_BASE + BLOCK.splitlines(True)[0]
    assert blockinfile(begin_only, sshd_block("vibe"), SSHD_MARKER) == begin_only + BLOCK


def test_known_hosts_like_ansible() -> None:
    line = GITHUB_KEY + "\n"
    assert known_hosts(None, "") == line
    assert known_hosts("other ssh-ed25519 AAAA\n", "") == "other ssh-ed25519 AAAA\n" + line
    # The same key: nothing to do.
    assert known_hosts("x\n" + line, f"# Host github.com found: line 2\n{GITHUB_KEY}\n") is None
    # Another ed25519 key for the host: that line is replaced (moved to the end).
    stale = "github.com ssh-ed25519 AAAAstale\n"
    assert known_hosts(
        "a\n" + stale + "b\n", "# Host github.com found: line 2\ngithub.com ssh-ed25519 AAAAstale\n"
    ) == ("a\nb\n" + line)
    # A key of another type only: appended.
    rsa = "github.com ssh-rsa AAAArsa\n"
    assert known_hosts(rsa, "# Host github.com found: line 1\ngithub.com ssh-rsa AAAArsa\n") == rsa + line
    # A hashed entry with the same key: Ansible compares host fields too and
    # adopts a hashed one only for a hashed new key, so it is replaced in clear.
    hashed = "|1|c2FsdA==|aGFzaA== ssh-ed25519 " + GITHUB_KEY.split()[2] + "\n"
    assert known_hosts(hashed, "# Host github.com found: line 1\n" + hashed) == line


# -- host scripts --------------------------------------------------------------------


def state(**overrides: Any) -> scripts.UserState:
    fields: dict[str, Any] = {
        "group_exists": True,
        "group_gid": "1001",
        "user_exists": True,
        "gid": "1001",
        "home": HOME,
        "shell": "/usr/bin/fish",
        "locked": True,
        "password_matches": True,
        "members": (),
    }
    fields.update(overrides)
    return scripts.UserState(**fields)


def test_user_commands_follow_the_user_module() -> None:
    config = VibeCodingConfig(ssh_authorized_keys=(KEY,))
    assert scripts.user_command(config, state()) is None
    assert scripts.user_command(config, scripts.UserState(True, "1001", False)) == (
        "{ [ -d /mnt/cryptdata ] || mkdir -p /mnt/cryptdata; } && "
        "useradd -g vibe -d /mnt/cryptdata/vibe -s /usr/bin/fish -p '!!' -m vibe"
    )
    assert scripts.user_command(config, state(shell="/bin/bash", members=("docker",))) == (
        "usermod -G '' -s /usr/bin/fish vibe"
    )
    assert scripts.user_command(config, state(locked=False, password_matches=False)) == "usermod -p '!!' vibe"
    assert scripts.user_command(config, state(locked=False)) == "usermod -L vibe"
    assert scripts.user_command(config, state(gid="100", home="/home/vibe")) == (
        "usermod -g vibe -d /mnt/cryptdata/vibe vibe"
    )


def test_user_probe_answer_parsing() -> None:
    parsed = scripts.parse_user(
        "group=yes\ngroupgid=1001\nuser=yes\npasswd=vibe:x:1001:1001::/h:/usr/bin/fish\n"
        "locked=yes\npwmatch=no\nmembers=docker,adm\n"
    )
    assert parsed == scripts.UserState(
        True, "1001", True, "1001", "/h", "/usr/bin/fish", True, False, ("docker", "adm")
    )
    with pytest.raises(Exception, match="could not read the user"):
        scripts.parse_user("")


def test_unreadable_file_fails_instead_of_counting_as_absent() -> None:
    assert scripts.read_text("absent") is None
    assert scripts.read_text("present\n" + base64.b64encode(b"x\n").decode()) == "x\n"
    with pytest.raises(Exception, match="could not read a file"):
        scripts.read_text("")


def test_user_commands_switch_like_become() -> None:
    config = VibeCodingConfig(ssh_authorized_keys=(KEY,))
    assert scripts.as_user(config, "true") == "sudo -H -n -u vibe -- bash -c true"


# -- controller dotfiles ----------------------------------------------------------------


def git(*argv: str, cwd: Path) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "t", "GIT_COMMITTER_NAME": "t"}
    env |= {"GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    return subprocess.run(["git", *argv], cwd=cwd, capture_output=True, text=True, check=True, env=env).stdout


def bare_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    git("init", "-q", "-b", "trunk", cwd=work)
    for name, content in files.items():
        (work / name).write_text(content)
    git("add", "-A", cwd=work)
    git("commit", "-qm", "init", cwd=work)
    git("tag", "v1", cwd=work)
    bare = tmp_path / "dotfiles.git"
    git("clone", "-q", "--bare", str(work), str(bare), cwd=tmp_path)
    return bare


def test_prepare_dotfiles_bundles_every_ref(tmp_path: Path) -> None:
    bare = bare_repo(tmp_path, {"dot_x": "x\n"})
    out = tmp_path / "out"
    out.mkdir()
    prepared = prepare_dotfiles(f"file://{bare}", out)
    assert prepared.branch == "trunk"
    assert prepared.commit == git("rev-parse", "trunk", cwd=bare).strip()
    clone = tmp_path / "clone"
    git("clone", "-q", "--branch", "trunk", str(prepared.bundle), str(clone), cwd=tmp_path)
    assert git("rev-parse", "HEAD", cwd=clone).strip() == prepared.commit
    assert "v1" in git("tag", cwd=clone)
    with pytest.raises(GitSourceError, match="already holds"):
        prepare_dotfiles(f"file://{bare}", out)


def test_prepare_dotfiles_refuses_submodules_and_credentials(tmp_path: Path) -> None:
    bare = bare_repo(tmp_path, {".gitmodules": '[submodule "x"]\n\tpath = x\n\turl = ../x\n'})
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(GitSourceError, match="submodules"):
        prepare_dotfiles(f"file://{bare}", out)
    with pytest.raises(ValueError, match="credentials"):
        prepare_dotfiles("https://user:pw@example.invalid/x.git", tmp_path)  # pragma: allowlist secret


# -- deploys on fake hosts -------------------------------------------------------------------


def test_converged_host_changes_nothing(tmp_path: Path) -> None:
    config = cfg(tmp_path)
    run = run_deploy_fake(deploy_vibe_coding, config, secrets(), responses=converged(config))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.executed_commands == []
    assert run.uploads == []
    assert TOKEN not in run.all_text()


def test_fresh_host_plan(tmp_path: Path) -> None:
    config = cfg(tmp_path)
    run = run_deploy_fake(
        deploy_vibe_coding,
        config,
        secrets(),
        responses={**LINUX, "uname -m": ["aarch64"], "u=vibe; g=vibe": ["group=no", "user=no"]}
        | {"p=/root/.ssh/known_hosts;": ["absent"], f"p={HOME}/.ssh/known_hosts;": ["absent"]}
        | {"p=$(readlink -f /etc/ssh/sshd_config)": present(SSHD_BASE), "command -v apt-get": ["/usr/bin/apt-get"]}
        | {"tasks/coding_tools.yml": ["install @anthropic-ai/claude-code"]},
    )
    assert run.succeeded, run.error
    changed = run.mutating_changed_ops
    order = [
        "Vibe coding | Ensure group vibe",
        "Vibe coding | Ensure user vibe",
        f"Vibe coding | Write {HOME}/.ssh/authorized_keys",
        "Vibe coding | Shell basics | Install shell basics packages",
        "Vibe coding | Shell basics | Switch login shell of vibe to /usr/bin/fish",
        "Vibe coding | Trust GitHub's SSH host key in /root/.ssh/known_hosts",
        f"Vibe coding | Clone {REPO} into {SOURCE}",
        "Vibe coding | Initialize chezmoi and apply the dotfiles",
        f"Vibe coding | Write {HOME}/.config/gh/hosts.yml",
        "Vibe coding | Install Node.js",
        "Vibe coding | Install Neovim 0.12.5 into /opt",
        "Vibe coding | Install lazygit 0.65.1",
        "Vibe coding | Install rustup 1.29.2 for vibe",
        "Vibe coding | Ensure rust-analyzer is installed",
        "Vibe coding | Install or update npm tools (system-wide copies removed)",
        "Vibe coding | Install zellij 0.45.1",
        "Vibe coding | Install /etc/ssh/sshd_config after sshd -t and reload ssh",
    ]
    assert [name for name in changed if name in order] == order
    # arm64 assets, as the role's arch maps pick them.
    commands = "\n".join(run.executed_commands)
    assert "nvim-linux-arm64.tar.gz" in commands
    assert "lazygit_0.65.1_linux_arm64.tar.gz" in commands
    assert "zellij-aarch64-unknown-linux-musl.tar.gz" in commands
    assert "aarch64-unknown-linux-gnu/rustup-init" in commands
    assert TOKEN not in run.all_text()
    assert [path for path, _ in run.secret_files] == [f"{HOME}/.config/gh/hosts.yml"]
    assert run.upload("/etc/ssh/.sshd_config.ops-deploy-vibe-coding") == (SSHD_BASE + BLOCK).encode()


def test_drift_is_repaired_step_by_step(tmp_path: Path) -> None:
    config = cfg(tmp_path)
    run = run_deploy_fake(
        deploy_vibe_coding,
        config,
        secrets(),
        responses=converged(
            config,
            **{
                "[ -e /mnt/cryptdata/vibe/.local/share/chezmoi/.git ]": [
                    "git=yes",
                    f"origin={REPO}",
                    f"head={'2' * 40}",
                    "mods=no",
                ],
                "-maxdepth 1 -type f -name": ["id_ed25519", "id_rsa"],
                **fakehost.file(f"{HOME}/.ssh/id_ed25519", "k", user="vibe", mode="-rw-------"),
                **fakehost.file(f"{HOME}/.ssh/id_rsa", "k", user="vibe", mode="-rw-------"),
                "p=$(readlink -f /etc/ssh/sshd_config)": present(SSHD_BASE),
            },
        ),
    )
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [
        "Vibe coding | Remove SSH private key id_ed25519",
        "Vibe coding | Remove SSH private key id_rsa",
        "Vibe coding | Ensure /var/lib/ops-deploy/vibe-coding",
        "Vibe coding | Upload the dotfiles bundle",
        f"Vibe coding | Update {SOURCE} to 111111111111",
        "Vibe coding | Initialize chezmoi and apply the dotfiles",
        "Vibe coding | Stage the sshd_config with the vibe Match block",
        "Vibe coding | Install /etc/ssh/sshd_config after sshd -t and reload ssh",
    ]


def test_local_modifications_refuse_before_any_change(tmp_path: Path) -> None:
    config = cfg(tmp_path)
    responses = converged(
        config,
        **{
            "[ -e /mnt/cryptdata/vibe/.local/share/chezmoi/.git ]": [
                "git=yes",
                f"origin={REPO}",
                f"head={COMMIT}",
                "mods=yes",
            ]
        },
    )
    run = run_deploy_fake(deploy_vibe_coding, config, secrets(), responses=responses)
    assert "Local modifications exist in the destination" in str(run.error)
    assert run.executed_commands == []


def test_github_login_follows_the_token(tmp_path: Path) -> None:
    config = cfg(tmp_path)
    off = run_deploy_fake(
        deploy_vibe_coding,
        config,
        secrets(username="", token=""),
        responses=converged(config),
    )
    assert off.mutating_changed_ops == [
        f"Vibe coding | Remove {HOME}/.config/gh/hosts.yml (GitHub CLI login not managed)"
    ]
    refused = run_deploy_fake(deploy_vibe_coding, config, secrets(username=""), responses=converged(config))
    assert "needs github_username" in str(refused.error)
    assert refused.executed_commands == []
    without = run_deploy_fake(deploy_vibe_coding, config, None, responses=converged(config))
    assert without.mutating_changed_ops == off.mutating_changed_ops


def test_optional_parts_can_be_left_out(tmp_path: Path) -> None:
    config = cfg(
        tmp_path,
        dotfiles=None,
        install_node=False,
        npm_tools=(),
        install_rust=False,
        zellij_install=False,
        sshd_hardening=False,
    )
    run = run_deploy_fake(
        deploy_vibe_coding,
        config,
        secrets(),
        responses=converged(config, **{"which zellij": [], "p=$(readlink -f /etc/ssh/sshd_config)": ["absent"]}),
    )
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    facts = "\n".join(run.fact_commands)
    assert "chezmoi" not in facts.replace("/usr/local/bin/chezmoi --version", "")
    assert "which zellij" not in facts


def test_unsupported_architecture_fails_planning(tmp_path: Path) -> None:
    config = cfg(tmp_path)
    run = run_deploy_fake(
        deploy_vibe_coding, config, secrets(), responses=converged(config, **{"uname -m": ["riscv64"]})
    )
    assert "Unsupported architecture for Neovim release tarball: riscv64" in str(run.error)
    assert run.executed_commands == []
