"""``deploy_vibe_coding`` against real Ubuntu 24.04 hosts in owned Docker containers.

Skipped unless ``VIBE_CODING_DOCKER_IMAGE`` names an image built from
``tests/integration/vibe_coding/Dockerfile`` (systemd as PID 1, a running
sshd, Ansible). Each test starts its own container, named
``ops-deploy-vibe-coding-<random>`` and labelled
``ops-deploy.fixture=vibe-coding``, with network access (the deploy downloads
NodeSource's Node.js, Neovim, lazygit, zellij, chezmoi, rustup and an npm
package), and removes it at the end. The Docker CLI is wrapped so that pyinfra
can only inspect, exec into and copy into that container.

The dotfiles are a synthetic chezmoi repository in a bare repo on the
controller (``file://`` URL), copied to the same path inside the container
for the Ansible run. ``test_switch_from_the_role_changes_nothing`` needs
``OPS_LIBRARY_PATH`` (the role and shell_basics_deploy are copied in).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.operations import run_ops
from pyinfra.connectors.docker import DockerConnector

from ops_deploy.base import ShellBasicsConfig
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.vibe_coding import Dotfiles as PreparedDotfiles
from ops_deploy.services.vibe_coding import (
    VibeCodingConfig,
    blockinfile,
    deploy_vibe_coding,
    prepare_dotfiles,
    sshd_block,
)
from ops_deploy.services.vibe_coding.render import SSHD_MARKER
from ops_deploy.testing.harness import DeployRun, collect_ops

IMAGE = os.environ.get("VIBE_CODING_DOCKER_IMAGE", "")
pytestmark = pytest.mark.skipif(not IMAGE, reason="VIBE_CODING_DOCKER_IMAGE not set")

HOME = "/mnt/cryptdata/vibe"
SOURCE = f"{HOME}/.local/share/chezmoi"
GH_USER = "octo-synthetic"
GH_TOKEN = "gho_" + "SyntheticVibeCodingFixtureToken00000"  # pragma: allowlist secret
NPM_TOOL = "is-number"
CONFIG_TEMPLATE = '[data]\n  host = {{ .chezmoi.hostname | quote }}\n  user = {{ env "LOGNAME" | quote }}\n'


class Box:
    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.name = f"ops-deploy-vibe-coding-{secrets.token_hex(4)}"
        self.identifier = self.docker(
            "run", "-d", "--name", self.name, "--label", "ops-deploy.fixture=vibe-coding",
            "--cgroupns", "private", "--cap-add", "SYS_ADMIN", "--security-opt", "apparmor=unconfined",
            "--tmpfs", "/run", "--tmpfs", "/run/lock", IMAGE,
        ).stdout.strip()  # fmt: skip
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        for _ in range(60):
            if self.sh("systemctl is-active ssh", check=False).stdout.strip() == "active":
                break
            time.sleep(1)
        else:
            raise AssertionError("sshd did not start in the fixture")
        wrapper = tmp / "docker-guard"
        wrapper.write_text(
            '#!/bin/sh\ncase "$1:$2" in container:inspect|exec:*|cp:*) ;; *) exit 97 ;; esac\nexec '
            + shlex.quote(self.binary)
            + ' "$@"\n'
        )
        wrapper.chmod(0o700)
        monkeypatch.setattr(DockerConnector, "docker_cmd", shlex.quote(str(wrapper)))

    def docker(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.binary, *args], capture_output=True, text=True, check=True, timeout=timeout)

    def sh(self, command: str, *, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, "exec", self.identifier, "bash", "-c", command],
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    def out(self, command: str) -> str:
        return self.sh(command).stdout.strip()

    def remove(self) -> None:
        if os.environ.get("VIBE_CODING_DOCKER_KEEP"):  # debugging: leave the container for inspection
            return
        subprocess.run([self.binary, "rm", "-f", self.identifier], capture_output=True, check=False, timeout=120)

    def deploy(self, cfg: VibeCodingConfig, values: SecretValues | None) -> DeployRun:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        run = DeployRun()
        try:
            connect_all(state)
            assert state.activated_hosts
            add_deploy(state, deploy_vibe_coding, cfg, values)
            run_ops(state)
        except PyinfraError as exc:
            run.error = exc
        finally:
            run.ops = collect_ops(state, name)
            disconnect_all(state)
        return run

    def stat(self, path: str) -> str:
        return self.out(f"stat -c '%U:%G %a' {shlex.quote(path)}")

    def read(self, path: str) -> str:
        return self.sh(f"cat {shlex.quote(path)}").stdout

    def sshd_effective(self, user: str) -> dict[str, str]:
        text = self.out(f"sshd -T -C user={user},host=localhost,addr=127.0.0.1")
        return dict(line.split(" ", 1) for line in text.splitlines() if " " in line)


@pytest.fixture
def box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Box]:
    fixture = Box(tmp_path, monkeypatch)
    try:
        yield fixture
    finally:
        fixture.remove()


def git(*argv: str, cwd: Path) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid"}
    env |= {"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": "/dev/null"}
    return subprocess.run(["git", *argv], cwd=cwd, capture_output=True, text=True, check=True, env=env).stdout


class Dotfiles:
    """A synthetic chezmoi repository: a working copy and the bare repo the deploys read."""

    def __init__(self, root: Path) -> None:
        self.work = root / "work"
        self.bare = root / "dotfiles.git"
        self.work.mkdir()
        git("init", "-q", "-b", "main", cwd=self.work)
        (self.work / ".chezmoi.toml.tmpl").write_text(CONFIG_TEMPLATE)
        (self.work / "dot_vibe-hello").write_text("hello from the synthetic dotfiles\n")
        (self.work / "private_dot_config").mkdir()
        (self.work / "private_dot_config" / "vibe-note.txt").write_text("note\n")
        git("add", "-A", cwd=self.work)
        git("commit", "-qm", "init", cwd=self.work)
        git("clone", "-q", "--bare", str(self.work), str(self.bare), cwd=root)
        git("remote", "add", "origin", str(self.bare), cwd=self.work)
        self.url = f"file://{self.bare}"
        self.root = root
        self.rounds = 0

    def commit(self, name: str, content: str) -> None:
        (self.work / name).write_text(content)
        git("add", "-A", cwd=self.work)
        git("commit", "-qm", f"change {name}", cwd=self.work)
        git("push", "-q", "origin", "main", cwd=self.work)

    def prepare(self) -> PreparedDotfiles:
        self.rounds += 1
        workdir = self.root / f"prepared-{self.rounds}"
        workdir.mkdir()
        return prepare_dotfiles(self.url, workdir)


@pytest.fixture
def dotfiles(tmp_path: Path) -> Dotfiles:
    root = tmp_path / "dotfiles"
    root.mkdir()
    return Dotfiles(root)


def keypair(tmp: Path, name: str) -> tuple[Path, str]:
    key = tmp / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True)
    return key, (tmp / f"{name}.pub").read_text().strip()


def config(dotfiles_cfg: PreparedDotfiles | None, public_key: str, **overrides: object) -> VibeCodingConfig:
    fields: dict[str, object] = {
        "ssh_authorized_keys": (public_key,),
        "dotfiles": dotfiles_cfg,
        "npm_tools": (NPM_TOOL,),
        "shell_basics": ShellBasicsConfig(fix_resolv_conf=False),
    }
    fields.update(overrides)
    return VibeCodingConfig(**fields)


def github(username: str = GH_USER, token: str = GH_TOKEN) -> SecretValues:
    return SecretValues(SecretRef("secrets/test/vibe-coding.yml"), {"github_username": username, "github_token": token})


def login(box: Box, key: Path, user: str) -> str:
    """An SSH login from inside the container to its own sshd with ``key``."""

    box.docker("cp", str(key), f"{box.identifier}:/tmp/login-key")
    box.sh("chmod 0600 /tmp/login-key")
    return box.out(
        "ssh -i /tmp/login-key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"{user}@127.0.0.1 id -un"
    )


def test_fresh_host_converges_and_repeats_without_changes(box: Box, dotfiles: Dotfiles, tmp_path: Path) -> None:
    vibe_key, vibe_public = keypair(tmp_path, "vibe-login")
    root_key, root_public = keypair(tmp_path, "root-login")
    keys = "/root/.ssh/authorized_keys"
    box.sh(f"printf '%s\\n' {shlex.quote(root_public)} > {keys} && chmod 0600 {keys}")
    assert login(box, root_key, "root") == "root"
    sshd_before = box.read("/etc/ssh/sshd_config")
    root_before = box.sshd_effective("root")

    prepared = dotfiles.prepare()
    cfg = config(prepared, vibe_public)
    first = box.deploy(cfg, github())
    assert first.succeeded, first.error or [op for op in first.ops if not op.succeeded]
    changed = first.mutating_changed_ops
    for expected in (
        "Vibe coding | Ensure group vibe",
        "Vibe coding | Ensure user vibe",
        f"Vibe coding | Write {HOME}/.ssh/authorized_keys",
        f"Vibe coding | Clone {dotfiles.url} into {SOURCE}",
        "Vibe coding | Initialize chezmoi and apply the dotfiles",
        f"Vibe coding | Write {HOME}/.config/gh/hosts.yml",
        "Vibe coding | Install Node.js",
        "Vibe coding | Install Neovim 0.12.5 into /opt",
        "Vibe coding | Install lazygit 0.65.1",
        "Vibe coding | Install rustup 1.29.2 for vibe",
        "Vibe coding | Install or update npm tools (system-wide copies removed)",
        "Vibe coding | Install zellij 0.45.1",
        "Vibe coding | Install /etc/ssh/sshd_config after sshd -t and reload ssh",
    ):
        assert expected in changed, (expected, changed)

    second = box.deploy(cfg, github())
    assert second.succeeded, second.error
    assert second.mutating_changed_ops == []

    # The account: locked password, fish, only its own group.
    assert box.out("getent passwd vibe | cut -d: -f6,7") == f"{HOME}:/usr/bin/fish"
    assert box.out("getent shadow vibe | cut -d: -f2") == "!!"
    assert box.out("id -Gn vibe") == "vibe"
    # ~/.ssh and the fish snippets, byte for byte as the role's templates render.
    assert box.stat(f"{HOME}/.ssh") == "vibe:vibe 700"
    assert box.read(f"{HOME}/.ssh/authorized_keys") == (
        f"# Managed by Ansible — vibe_coding_deploy role\n{vibe_public}\n"
    )
    assert box.stat(f"{HOME}/.ssh/authorized_keys") == "vibe:vibe 600"
    assert box.stat(f"{HOME}/.ssh/rc") == "vibe:vibe 700"
    assert box.stat(f"{HOME}/.config/fish") == box.stat(f"{HOME}/.config/fish/conf.d") == "vibe:vibe 755"
    # Created 0755 for conf.d, then made private by the dotfiles' private_dot_config.
    assert box.stat(f"{HOME}/.config") == "vibe:vibe 700"
    assert "SSH_AUTH_SOCK" in box.read(f"{HOME}/.config/fish/conf.d/ssh-agent-forward.fish")
    assert f'set -gx npm_config_prefix "{HOME}/.npm-global"' in box.read(f"{HOME}/.config/fish/conf.d/npm-paths.fish")
    # GitHub CLI login: written with the secrets, never readable by others.
    assert box.stat(f"{HOME}/.config/gh") == "vibe:vibe 700"
    assert box.stat(f"{HOME}/.config/gh/hosts.yml") == "vibe:vibe 600"
    assert box.read(f"{HOME}/.config/gh/hosts.yml") == (
        f'github.com:\n  user: "{GH_USER}"\n  oauth_token: "{GH_TOKEN}"\n  git_protocol: ssh\n'
        f'  users:\n    "{GH_USER}": {{}}\n'
    )
    # chezmoi: a real checkout of the repository, owned by the user, applied.
    assert box.out(f"git -c safe.directory={SOURCE} -C {SOURCE} remote get-url origin") == dotfiles.url
    assert box.out(f"git -c safe.directory={SOURCE} -C {SOURCE} rev-parse HEAD") == prepared.commit
    assert box.out(f"git -c safe.directory={SOURCE} -C {SOURCE} branch --show-current") == "main"
    assert box.out(f"find {SOURCE} ! -user vibe -print -quit; find {SOURCE} ! -group vibe -print -quit") == ""
    assert box.read(f"{HOME}/.vibe-hello") == "hello from the synthetic dotfiles\n"
    assert 'user = "vibe"' in box.read(f"{HOME}/.config/chezmoi/chezmoi.toml")
    assert SOURCE in box.out("git config --global --get-all safe.directory")
    assert box.out("ls /var/lib/ops-deploy/vibe-coding") == ""
    for known in ("/root/.ssh/known_hosts", f"{HOME}/.ssh/known_hosts"):
        assert box.out(f"grep -c '^github.com ssh-ed25519 ' {known}") == "1"
    assert box.stat(f"{HOME}/.ssh/known_hosts") == "vibe:vibe 644"
    # Tools.
    assert box.out("nvim --version | head -n 1").startswith("NVIM v0.12.5")
    assert "0.65.1" in box.out("lazygit --version")
    assert box.out("zellij --version") == "zellij 0.45.1"
    assert box.stat("/usr/local/bin/zellij") == "root:root 755"
    assert box.out("readlink /usr/local/bin/nvim").startswith("/opt/nvim-linux-")
    assert box.out("node --version").startswith("v22.")
    assert (
        box.out(f"runuser -u vibe -- {HOME}/.cargo/bin/rustup component list --installed").count("rust-analyzer") == 1
    )
    assert box.out(f"test -f {HOME}/.npm-global/lib/node_modules/{NPM_TOOL}/package.json && echo yes") == "yes"
    assert box.out(f"runuser -u vibe -- env HOME={HOME} npm config get prefix") == f"{HOME}/.npm-global"
    assert box.stat(f"{HOME}/projects") == "vibe:vibe 755"
    # sshd: the role's block, the vibe settings in effect, root's untouched,
    # both logins work after the reload.
    assert box.read("/etc/ssh/sshd_config") == blockinfile(sshd_before, sshd_block("vibe"), SSHD_MARKER)
    vibe = box.sshd_effective("vibe")
    assert {key: vibe[key] for key in ("passwordauthentication", "allowagentforwarding", "permituserrc")} == {
        "passwordauthentication": "no",
        "allowagentforwarding": "yes",
        "permituserrc": "yes",
    }
    assert {vibe["x11forwarding"], vibe["allowtcpforwarding"], vibe["permitemptypasswords"]} == {"no"}
    assert box.sshd_effective("root") == root_before
    assert login(box, vibe_key, "vibe") == "vibe"
    assert login(box, root_key, "root") == "root"


def test_drift_dotfiles_github_and_sshd_failures(box: Box, dotfiles: Dotfiles, tmp_path: Path) -> None:
    _, vibe_public = keypair(tmp_path, "vibe-login")
    cfg = config(dotfiles.prepare(), vibe_public, install_rust=False, install_node=False, npm_tools=())
    assert box.deploy(cfg, github()).succeeded

    # A new commit upstream: bundle, fast-forward, ownership, chezmoi; then quiet.
    dotfiles.commit("dot_vibe-second", "second\n")
    updated = dotfiles.prepare()
    cfg = cfg.model_copy(update={"dotfiles": updated})
    run = box.deploy(cfg, github())
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [
        "Vibe coding | Upload the dotfiles bundle",
        f"Vibe coding | Update {SOURCE} to {updated.commit[:12]}",
        "Vibe coding | Initialize chezmoi and apply the dotfiles",
    ]
    assert box.read(f"{HOME}/.vibe-second") == "second\n"
    assert box.deploy(cfg, github()).mutating_changed_ops == []

    # A changed config template re-runs init (and apply) only.
    box.sh(f"runuser -u vibe -- sh -c 'printf \"  extra = 1\\n\" >> {HOME}/.config/chezmoi/chezmoi.toml'")
    assert box.deploy(cfg, github()).mutating_changed_ops == ["Vibe coding | Initialize chezmoi and apply the dotfiles"]
    assert "extra" not in box.read(f"{HOME}/.config/chezmoi/chezmoi.toml")

    # Local modifications in the checkout: refused before any change (force=no).
    box.sh(f"echo local >> {SOURCE}/dot_vibe-hello")
    refused = box.deploy(cfg, github())
    assert not refused.succeeded
    assert "Local modifications exist in the destination" in str(refused.error)
    box.sh(f"git -c safe.directory={SOURCE} -C {SOURCE} checkout -- dot_vibe-hello")

    # A checkout of another origin is replaced by a fresh clone (the role's removal).
    box.sh(f"git -c safe.directory={SOURCE} -C {SOURCE} remote set-url origin file:///nowhere.git")
    run = box.deploy(cfg, github())
    assert f"Vibe coding | Clone {dotfiles.url} into {SOURCE}" in run.mutating_changed_ops
    assert box.out(f"git -c safe.directory={SOURCE} -C {SOURCE} remote get-url origin") == dotfiles.url

    # Ownership drift alone: chown only.
    box.sh(f"chown root {SOURCE}/dot_vibe-hello")
    assert box.deploy(cfg, github()).mutating_changed_ops == [f"Vibe coding | Set ownership of {SOURCE}"]

    # git never runs as root in the user's checkout: a hostile core.fsmonitor
    # runs (if at all) with the user's rights, through probes and an update.
    box.sh(f"runuser -u vibe -- git -C {SOURCE} config core.fsmonitor 'touch /tmp/fsmonitor-ran; false'")
    dotfiles.commit("dot_vibe-third", "third\n")
    cfg = cfg.model_copy(update={"dotfiles": dotfiles.prepare()})
    assert box.deploy(cfg, github()).succeeded
    assert box.out("stat -c %U /tmp/fsmonitor-ran 2>/dev/null || echo none") in ("vibe", "none")
    box.sh(f"runuser -u vibe -- git -C {SOURCE} config --unset core.fsmonitor; rm -f /tmp/fsmonitor-ran")
    # A symlinked parent stops the ownership repair instead of following it.
    box.sh(
        f"chown root {SOURCE}/dot_vibe-hello && mv {HOME}/.local/share {HOME}/.local/share-real "
        f"&& ln -s {HOME}/.local/share-real {HOME}/.local/share"
    )
    assert not box.deploy(cfg, github()).succeeded
    box.sh(f"rm {HOME}/.local/share && mv {HOME}/.local/share-real {HOME}/.local/share")
    assert box.out(f"stat -c %U {SOURCE}/dot_vibe-hello") == "root"
    assert box.deploy(cfg, github()).mutating_changed_ops == [f"Vibe coding | Set ownership of {SOURCE}"]

    # GitHub login off (empty token, the playbook's switch): hosts.yml goes.
    off = box.deploy(cfg, github(username="", token=""))
    assert off.mutating_changed_ops == [
        f"Vibe coding | Remove {HOME}/.config/gh/hosts.yml (GitHub CLI login not managed)"
    ]
    assert box.sh(f"test -e {HOME}/.config/gh/hosts.yml", check=False).returncode == 1
    assert not box.deploy(cfg, github(username="", token=GH_TOKEN)).succeeded

    # Private keys in ~/.ssh go, public keys stay.
    box.sh(f"runuser -u vibe -- sh -c 'touch {HOME}/.ssh/id_ed25519 {HOME}/.ssh/id_ed25519.pub'")
    run = box.deploy(cfg, github())
    assert "Vibe coding | Remove SSH private key id_ed25519" in run.mutating_changed_ops
    assert box.out(f"ls {HOME}/.ssh | grep ^id_") == "id_ed25519.pub"

    # sshd: a candidate sshd -t rejects changes nothing.
    marked = box.read("/etc/ssh/sshd_config")
    plain = marked.split("# BEGIN ANSIBLE MANAGED", 1)[0]
    box.sh(f"printf %s {shlex.quote(plain + 'NoSuchDirective yes' + chr(10))} > /etc/ssh/sshd_config")
    broken = box.read("/etc/ssh/sshd_config")
    run = box.deploy(cfg, github())
    assert not run.succeeded
    assert box.read("/etc/ssh/sshd_config") == broken
    assert box.out("ls -a /etc/ssh | grep ops-deploy || true") == ""
    # A reload that fails puts the old file back and reloads again.
    box.sh(f"printf %s {shlex.quote(plain)} > /etc/ssh/sshd_config")
    box.sh(
        "mkdir -p /etc/systemd/system/ssh.service.d && printf '[Service]\\nExecReload=\\nExecReload=/bin/false\\n' "
        "> /etc/systemd/system/ssh.service.d/fail-reload.conf && systemctl daemon-reload"
    )
    run = box.deploy(cfg, github())
    assert not run.succeeded
    assert box.read("/etc/ssh/sshd_config") == plain
    assert box.out("ls -a /etc/ssh | grep ops-deploy || true") == ""
    assert box.out("systemctl is-active ssh") == "active"
    box.sh("rm /etc/systemd/system/ssh.service.d/fail-reload.conf && systemctl daemon-reload")
    run = box.deploy(cfg, github())
    assert run.mutating_changed_ops == [
        "Vibe coding | Stage the sshd_config with the vibe Match block",
        "Vibe coding | Install /etc/ssh/sshd_config after sshd -t and reload ssh",
    ]
    assert box.read("/etc/ssh/sshd_config") == marked
    assert box.deploy(cfg, github()).mutating_changed_ops == []


ROLE_PLAY = """\
- hosts: localhost
  become: true
  roles:
    - role: local.ops_library.vibe_coding_deploy
      vars:
        vibe_coding_user_home: "{home}"
        vibe_coding_ssh_authorized_keys:
          - "{key}"
        vibe_coding_dotfiles_repo: "{repo}"
        vibe_coding_github_cli_auth_enabled: true
        vibe_coding_github_username: "{username}"
        vibe_coding_github_token: "{token}"
        vibe_coding_npm_tools: ["{tool}"]
        vibe_coding_install_rust: false
        shell_basics_fix_resolv_conf: false
"""


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_switch_from_the_role_changes_nothing(box: Box, dotfiles: Dotfiles, tmp_path: Path) -> None:
    library = Path(os.environ["OPS_LIBRARY_PATH"])
    roles = "/opt/role-run/ansible_collections/local/ops_library/roles"
    box.sh(f"mkdir -p {roles} {shlex.quote(str(dotfiles.bare.parent))}")
    for role in ("vibe_coding_deploy", "shell_basics_deploy"):
        box.docker("cp", str(library / "roles" / role), f"{box.identifier}:{roles}/{role}")
    box.docker("cp", str(dotfiles.bare), f"{box.identifier}:{dotfiles.bare}")
    box.sh(f"chown -R root:root {shlex.quote(str(dotfiles.bare))}")
    _, vibe_public = keypair(tmp_path, "vibe-login")
    play = ROLE_PLAY.format(
        home=HOME, key=vibe_public, repo=dotfiles.url, username=GH_USER, token=GH_TOKEN, tool=NPM_TOOL
    )
    box.sh(f"printf %s {shlex.quote(play)} > /opt/role-run/play.yml")
    play_command = (
        "cd /opt/role-run && ANSIBLE_COLLECTIONS_PATH=/opt/role-run ANSIBLE_NOCOLOR=1 "
        "ansible-playbook -c local -i localhost, play.yml"
    )
    # The role cannot finish a first run: npm 10 fails `npm list -g` on the
    # empty per-user prefix (no lib directory yet). The host it serves has one.
    first = box.sh(play_command, check=False, timeout=1800)
    assert first.returncode != 0
    assert "coding_tools | Check installed npm global packages (JSON)] ***\nfatal" in first.stdout
    box.sh(f"runuser -u vibe -- mkdir {HOME}/.npm-global/lib")
    recap = box.sh(play_command, check=False, timeout=1800)
    assert recap.returncode == 0, recap.stdout[-4000:] + recap.stderr[-2000:]
    assert re.search(r"localhost\s+: ok=\d+\s+changed=[1-9]\d*\s+unreachable=0\s+failed=0", recap.stdout)
    snapshot = box.out(
        f"find {HOME} /etc/ssh/sshd_config /root/.ssh/known_hosts /usr/local/bin /etc/apt/sources.list.d "
        "-xdev -printf '%p %u:%g %m %s\\n' | sort | grep -v '/.npm/_' | sha256sum"
    )

    cfg = config(dotfiles.prepare(), vibe_public, install_rust=False)
    run = box.deploy(cfg, github())
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    after = box.out(
        f"find {HOME} /etc/ssh/sshd_config /root/.ssh/known_hosts /usr/local/bin /etc/apt/sources.list.d "
        "-xdev -printf '%p %u:%g %m %s\\n' | sort | grep -v '/.npm/_' | sha256sum"
    )
    assert after == snapshot
    assert json.loads(box.out(f"runuser -u vibe -- env HOME={HOME} npm list -g --depth=0 --json"))["dependencies"]
