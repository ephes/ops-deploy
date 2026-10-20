"""``deploy_ssh_guard`` against real sshd, fail2ban and systemd in an owned Docker container.

Skipped unless ``SSH_GUARD_DOCKER_CONTAINER`` names the full ID of a running
container labelled ``ops-deploy.fixture=ssh-guard`` with no network, systemd
as PID 1 and ``openssh-server`` plus ``fail2ban`` installed (``docs/base.md``
describes one). The test rewrites the container's sshd drop-in and fail2ban
jail; it never touches anything outside the container. The Docker CLI is
wrapped so that pyinfra can only inspect, exec and copy into that container:
the connector's fallbacks (start, run, commit, rm) fail instead.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.operations import run_ops
from pyinfra.connectors.docker import DockerConnector

from ops_deploy.base import SshGuardConfig, deploy_ssh_guard
from ops_deploy.base.ssh_guard import JAIL_PATH, render_dropin, render_jail
from ops_deploy.testing.harness import DeployRun, collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("SSH_GUARD_DOCKER_CONTAINER"), reason="no owned ssh_guard Docker container"
)

DEFAULT = SshGuardConfig()
DROPIN = DEFAULT.sshd_dropin_path
WRITE_JAIL = f"SSH guard | Write {JAIL_PATH}"
RESTART = "SSH guard | Restart fail2ban for the new jail"
WRITE_DROPIN = f"SSH guard | Write {DROPIN}"
VALIDATE = "SSH guard | Validate the sshd configuration"
RELOAD = "SSH guard | Reload ssh for the new drop-in"


class Container:
    def __init__(self) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.identifier = os.environ["SSH_GUARD_DOCKER_CONTAINER"]
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        info = json.loads(self.docker("container", "inspect", self.identifier).stdout)[0]
        assert info["Name"].startswith("/ops-deploy-ssh-guard-")
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "ssh-guard"
        assert info["HostConfig"]["NetworkMode"] == "none"
        assert info["HostConfig"]["Privileged"] is False
        assert not info["Mounts"]
        assert self.out("cat /proc/1/comm") == "systemd"

    def docker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.binary, *args], capture_output=True, text=True, check=True, timeout=60)

    def sh(self, command: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, "exec", self.identifier, "sh", "-c", command],
            capture_output=True,
            text=True,
            check=check,
            timeout=60,
        )

    def out(self, command: str) -> str:
        return self.sh(command).stdout.strip()

    def guard_connector(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = tmp / "docker-guard"
        wrapper.write_text(
            '#!/bin/sh\ncase "$1:$2" in container:inspect|exec:*|cp:*) ;; *) exit 97 ;; esac\nexec '
            + shlex.quote(self.binary)
            + ' "$@"\n'
        )
        wrapper.chmod(0o700)
        monkeypatch.setattr(DockerConnector, "docker_cmd", shlex.quote(str(wrapper)))

    def deploy(self, cfg: SshGuardConfig) -> DeployRun:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        run = DeployRun()
        try:
            connect_all(state)
            assert state.activated_hosts
            add_deploy(state, deploy_ssh_guard, cfg)
            run_ops(state)
        except PyinfraError as exc:
            run.error = exc
        finally:
            run.ops = collect_ops(state, name)
            disconnect_all(state)
        return run

    def pid(self, unit: str) -> str:
        return self.out(f"systemctl show -p MainPID --value {unit}")

    def sighups(self) -> int:
        # sshd logs this line on every reload.
        return int(self.out("journalctl -u ssh --no-pager -o cat | grep -c 'Received SIGHUP' || true"))

    def stat(self, path: str) -> str:
        return self.out(f"stat -c '%U:%G %a' {shlex.quote(path)}")

    def read(self, path: str) -> str:
        return self.sh(f"cat {shlex.quote(path)}").stdout


def test_ssh_guard_in_a_real_container(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Container()
    box.guard_connector(tmp_path, monkeypatch)
    box.sh(f"rm -f {JAIL_PATH} {DROPIN} && systemctl restart fail2ban ssh")

    # First run: both files written, fail2ban restarted, drop-in validated, ssh reloaded.
    f2b, ssh, hups = box.pid("fail2ban"), box.pid("ssh"), box.sighups()
    first = box.deploy(DEFAULT)
    assert first.succeeded, first.error
    assert first.mutating_changed_ops == [WRITE_JAIL, RESTART, WRITE_DROPIN, VALIDATE, RELOAD]
    assert box.read(JAIL_PATH) == render_jail(DEFAULT)
    assert box.read(DROPIN) == render_dropin(DEFAULT)
    assert box.stat(JAIL_PATH) == box.stat(DROPIN) == "root:root 644"
    assert box.pid("fail2ban") != f2b
    assert box.pid("ssh") == ssh
    assert box.sighups() == hups + 1
    assert box.out("fail2ban-client get sshd maxretry") == "5"
    assert "persourcemaxstartups 5" in box.out("sshd -T")

    # Second run: nothing changes, nothing is restarted or reloaded.
    f2b, hups = box.pid("fail2ban"), box.sighups()
    second = box.deploy(DEFAULT)
    assert second.succeeded, second.error
    assert second.changed_ops == []
    assert (box.pid("fail2ban"), box.sighups()) == (f2b, hups)

    # Jail drift: rewritten and fail2ban restarted; ssh untouched.
    box.sh(f"sed -i 's/^maxretry = 5$/maxretry = 9/' {JAIL_PATH} && systemctl restart fail2ban")
    f2b, hups = box.pid("fail2ban"), box.sighups()
    jail = box.deploy(DEFAULT)
    assert jail.succeeded, jail.error
    assert jail.mutating_changed_ops == [WRITE_JAIL, RESTART]
    assert box.pid("fail2ban") != f2b
    assert box.sighups() == hups
    assert box.out("fail2ban-client get sshd maxretry") == "5"

    # Drop-in drift: validated and reloaded; fail2ban untouched.
    box.sh(f"echo 'PerSourceMaxStartups 50' >> {DROPIN}")
    f2b, ssh, hups = box.pid("fail2ban"), box.pid("ssh"), box.sighups()
    dropin = box.deploy(DEFAULT)
    assert dropin.succeeded, dropin.error
    assert dropin.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]
    assert (box.pid("fail2ban"), box.pid("ssh")) == (f2b, ssh)
    assert box.sighups() == hups + 1

    # A value sshd rejects: the drop-in is removed, the deploy fails, ssh is not reloaded.
    hups = box.sighups()
    bad = box.deploy(SshGuardConfig(per_source_max_startups="not-a-number"))
    assert not bad.succeeded
    # Every op before the check succeeded; the check failed and the reload never ran.
    names = [op.name for op in bad.ops]
    assert all(op.succeeded for op in bad.ops[: names.index(VALIDATE)])
    assert bad.op(VALIDATE).succeeded is False
    assert not bad.op(RELOAD).changed
    assert box.sh(f"test -e {DROPIN}", check=False).returncode == 1
    assert box.sighups() == hups
    assert box.pid("ssh") == ssh
    assert box.out("systemctl is-active ssh") == "active"
    assert box.sh("sshd -t -f /etc/ssh/sshd_config", check=False).returncode == 0
    assert (box.pid("fail2ban"), box.read(JAIL_PATH)) == (f2b, render_jail(DEFAULT))

    # The next good run puts the drop-in back.
    fixed = box.deploy(DEFAULT)
    assert fixed.succeeded, fixed.error
    assert fixed.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]
    assert box.read(DROPIN) == render_dropin(DEFAULT)
    assert box.sighups() == hups + 1

    # With ssh stopped, Debian removes /run/sshd and ``sshd -t`` fails on that
    # alone: the drop-in is removed and the deploy fails, exactly as the role's
    # command does. Starting ssh and deploying again recovers.
    box.sh(f"systemctl stop ssh && echo 'MaxAuthTries 3' >> {DROPIN}")
    stopped = box.deploy(DEFAULT)
    assert not stopped.succeeded
    assert stopped.op(VALIDATE).succeeded is False
    assert box.sh(f"test -e {DROPIN}", check=False).returncode == 1
    assert box.out("systemctl is-active ssh || true") == "inactive"
    box.sh("systemctl start ssh")
    recovered = box.deploy(DEFAULT)
    assert recovered.succeeded, recovered.error
    assert recovered.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]

    # A stopped ssh whose privilege separation directory is still there is
    # started, as the role's ``state: reloaded`` handler does.
    box.sh(f"systemctl stop ssh && mkdir -p /run/sshd && echo 'MaxAuthTries 3' >> {DROPIN}")
    started = box.deploy(DEFAULT)
    assert started.succeeded, started.error
    assert started.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]
    assert box.out("systemctl is-active ssh") == "active"

    final = box.deploy(DEFAULT)
    assert final.succeeded, final.error
    assert final.changed_ops == []
