"""Base deploys on the smoke VM: real end state, then a converged second run.

The VM is shared with the service smokes, so every test works on its own
throwaway user, unit or directory, or puts back what it changed (hostname,
default target). shell_basics leaves the resolver alone and targets the smoke
user; nodejs_install runs over the NodeSource setup the VM already has.
"""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.base import (
    AuthorizedKey,
    HeadlessModeConfig,
    HostnameConfig,
    NodejsInstallConfig,
    ShellBasicsConfig,
    SshAuthorizedKeysConfig,
    SystemdUnitMasksConfig,
    UnitMask,
    UvInstallConfig,
    deploy_headless_mode,
    deploy_hostname,
    deploy_nodejs_install,
    deploy_shell_basics,
    deploy_ssh_authorized_keys,
    deploy_systemd_unit_masks,
    deploy_uv_install,
)
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

USER = "opsdeploysmoke"
SCRATCH = "/opt/ops-deploy-smoke"
# Not /etc/systemd/system: ``systemctl mask`` refuses a unit whose file lives there.
UNIT_DIR = "/usr/local/lib/systemd/system"


def twice(smoke_host: SmokeHost, label: str, deploy_fn: Callable[..., Any], cfg: Any) -> tuple[SshRun, SshRun]:
    runs = []
    for attempt in ("first", "second"):
        run = run_deploy_ssh(deploy_fn, cfg, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"{label} {attempt} run"] = run.seconds
        assert run.succeeded, run.error
        runs.append(run)
    assert runs[1].mutating_changed_ops == [], runs[1].mutating_changed_ops
    return runs[0], runs[1]


@pytest.fixture(scope="module")
def smoke_user(smoke_host: SmokeHost) -> Iterator[str]:
    smoke_host.run(f"id {USER} >/dev/null 2>&1 || useradd --create-home --shell /bin/bash {USER}")
    yield USER
    smoke_host.run(f"userdel --remove {USER} 2>/dev/null || true")


def write_unit(smoke_host: SmokeHost, name: str, exec_start: str) -> None:
    unit = (
        f"[Unit]\nDescription=ops-deploy smoke\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart={exec_start}\n"
    )
    smoke_host.run(f"mkdir -p {UNIT_DIR} && cat >{UNIT_DIR}/{name} && systemctl daemon-reload", input=unit)


def remove_units(smoke_host: SmokeHost, *names: str) -> None:
    for name in names:
        smoke_host.run(f"systemctl unmask {name}; systemctl stop {name}; systemctl reset-failed {name}", check=False)
        smoke_host.run(f"rm -f {UNIT_DIR}/{name}")
    smoke_host.run("systemctl daemon-reload")


def test_hostname(smoke_host: SmokeHost) -> None:
    original = smoke_host.out("hostname")
    try:
        first, _ = twice(smoke_host, "hostname", deploy_hostname, HostnameConfig(hostname="ops-deploy-smoke-p31"))
        assert first.mutating_changed_ops
        assert smoke_host.out("hostnamectl --static") == "ops-deploy-smoke-p31"
        assert smoke_host.out("uname -n") == "ops-deploy-smoke-p31"
    finally:
        smoke_host.run(f"hostnamectl set-hostname {shlex.quote(original)}")


def test_systemd_unit_masks(smoke_host: SmokeHost) -> None:
    running, failed = "ops-deploy-smoke-running.service", "ops-deploy-smoke-failed.service"
    write_unit(smoke_host, running, "/bin/true")
    write_unit(smoke_host, failed, "/bin/false")
    smoke_host.run(f"systemctl start {running}; systemctl start {failed} || true")
    assert smoke_host.out(f"systemctl is-failed {failed} || true") == "failed"
    try:
        cfg = SystemdUnitMasksConfig(units=(UnitMask(unit=running, reason="smoke"), UnitMask(unit=failed)))
        twice(smoke_host, "unit masks", deploy_systemd_unit_masks, cfg)
        for unit in (running, failed):
            assert smoke_host.out(f"systemctl is-enabled {unit} || true") == "masked"
            assert smoke_host.out(f"systemctl is-active {unit} || true") == "inactive"

        twice(smoke_host, "unit unmask", deploy_systemd_unit_masks, SystemdUnitMasksConfig(unmask=(running, failed)))
        for unit in (running, failed):
            assert smoke_host.out(f"systemctl is-enabled {unit} || true") != "masked"
    finally:
        remove_units(smoke_host, running, failed)


def test_headless_mode(smoke_host: SmokeHost) -> None:
    original = smoke_host.out("systemctl get-default")
    target = "graphical.target" if original == "multi-user.target" else "multi-user.target"
    dm = "ops-deploy-smoke-dm.service"
    write_unit(smoke_host, dm, "/bin/true")
    smoke_host.run(f"printf '[Install]\\nWantedBy=multi-user.target\\n' >>{UNIT_DIR}/{dm}")
    smoke_host.run(f"systemctl daemon-reload && systemctl enable --now {dm}")
    try:
        cfg = HeadlessModeConfig(default_target=target, display_manager_service=dm.removesuffix(".service"))
        twice(smoke_host, "headless mode", deploy_headless_mode, cfg)
        assert smoke_host.out("systemctl get-default") == target
        assert smoke_host.out(f"systemctl is-enabled {dm} || true") == "disabled"
        assert smoke_host.out(f"systemctl is-active {dm} || true") == "inactive"
    finally:
        smoke_host.run(f"systemctl set-default {shlex.quote(original)}")
        smoke_host.run(f"systemctl disable {dm}", check=False)
        remove_units(smoke_host, dm)


def test_ssh_authorized_keys_allow_login(smoke_host: SmokeHost, smoke_user: str, tmp_path: Path) -> None:
    key = tmp_path / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    public = key.with_suffix(".pub").read_text().split()
    entry = AuthorizedKey(key=f"{public[0]} {public[1]}", comment="ops-deploy smoke", key_options="no-pty")
    cfg = SshAuthorizedKeysConfig(user=smoke_user, entries=(entry,))

    twice(smoke_host, "authorized keys", deploy_ssh_authorized_keys, cfg)

    path = f"/home/{smoke_user}/.ssh/authorized_keys"
    assert smoke_host.out(f"stat -c '%a %U %G' /home/{smoke_user}/.ssh {path}").splitlines() == [
        f"700 {smoke_user} {smoke_user}",
        f"600 {smoke_user} {smoke_user}",
    ]
    login = SmokeHost(smoke_host.hostname, smoke_host.port, str(key), smoke_host.known_hosts, user=smoke_user)
    assert login.out("id -un") == smoke_user


def test_uv_install(smoke_host: SmokeHost) -> None:
    install_dir = f"{SCRATCH}/uv"
    smoke_host.run(f"install -d -m 0755 {SCRATCH}")
    try:
        first, _ = twice(smoke_host, "uv install", deploy_uv_install, UvInstallConfig(install_dir=install_dir))
        assert first.mutating_changed_ops
        assert smoke_host.out(f"{install_dir}/uv --version").startswith("uv 0.13.4 ")
        assert smoke_host.out(f"stat -c '%a %U' {install_dir}/uvx") == "755 root"
        assert smoke_host.out(f"ls -A {install_dir}") == "uv\nuvx"
    finally:
        smoke_host.run(f"rm -rf {SCRATCH}")


def test_nodejs_install_over_existing_nodesource_setup(smoke_host: SmokeHost) -> None:
    _, second = twice(smoke_host, "nodejs install", deploy_nodejs_install, NodejsInstallConfig())
    assert smoke_host.out("node --version").startswith("v24.")
    assert any(op.read_only and op.succeeded for op in second.ops)


def test_shell_basics_for_a_user(smoke_host: SmokeHost, smoke_user: str) -> None:
    bin_dir = f"{SCRATCH}/bin"
    cfg = ShellBasicsConfig(
        user=smoke_user,
        fix_resolv_conf=False,
        chezmoi_install_dir=bin_dir,
        fish_extra_config=("set -g fish_greeting",),
    )
    try:
        twice(smoke_host, "shell basics", deploy_shell_basics, cfg)
        home = f"/home/{smoke_user}"
        assert smoke_host.out(f"getent passwd {smoke_user} | cut -d: -f7") == "/usr/bin/fish"
        links = smoke_host.out(f"readlink {home}/.local/bin/bat {home}/.local/bin/fd")
        assert links == "/usr/bin/batcat\n/usr/bin/fdfind"
        assert smoke_host.out(f"{bin_dir}/chezmoi --version").startswith("chezmoi version v2.73.1")
        assert smoke_host.out(f"stat -c '%a %U' {home}/.config/fish/config.fish") == f"644 {smoke_user}"
        on_path = f"runuser -u {smoke_user} -- fish -c 'contains {home}/.local/bin $PATH; and echo yes'"
        assert smoke_host.out(on_path) == "yes"
        assert smoke_host.out("update-alternatives --query editor | sed -n 's/^Value: //p'") == "/usr/bin/vim.basic"
    finally:
        smoke_host.run(f"rm -rf {SCRATCH}")
        smoke_host.run("update-alternatives --auto editor")
