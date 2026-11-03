"""``ip_options_drop`` against real systemd and nftables in an owned Docker container.

Skipped unless ``IP_OPTIONS_DROP_DOCKER_CONTAINER`` holds the full ID of a
running container named ``ops-deploy-ip-options-drop-*``, labelled
``ops-deploy.fixture=ip-options-drop``, with no network (its own network
namespace, so the rules never reach the Docker host), not privileged, no
mounts, ``NET_ADMIN`` and systemd as PID 1, built from ``ubuntu:24.04`` with
``systemd systemd-sysv dbus nftables python3`` (``docs/base.md``). The Docker
CLI is wrapped so that pyinfra can only inspect, exec and copy into that
container; the test itself restarts the container once to boot it again.

It checks what the fake connector cannot: the kernel accepts the ruleset, a
SYN with IPv4 options to a loopback listener is dropped and counted while a
plain connection works, the table survives ``nftables.service`` reloads and
restarts (whose ``flush ruleset`` removes every table) and a reboot with
``nftables.service`` enabled, a flushed ruleset converges again, and
``absent`` removes everything while other tables stay.
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

from ops_deploy.base import IpOptionsDropConfig, deploy_ip_options_drop
from ops_deploy.base.ip_options_drop import RULESET_PATH, SERVICE, UNIT_PATH
from ops_deploy.testing.harness import DeployRun, collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("IP_OPTIONS_DROP_DOCKER_CONTAINER"), reason="no owned ip_options_drop Docker container"
)

P = "IPv4 options drop | "
FRESH = [
    P + "Ensure /etc/ops-deploy",
    P + f"Write {RULESET_PATH}",
    P + f"Install systemd unit {SERVICE}",
    P + f"Reload systemd for {SERVICE}",
    P + f"Enable {SERVICE}",
    P + f"Start {SERVICE}",
]
REMOVED = [
    P + f"Disable and stop {SERVICE}",
    P + f"Remove {UNIT_PATH}",
    P + f"Remove {RULESET_PATH}",
    P + f"Reload systemd after removing {SERVICE}",
    P + "Delete table ip ip_options_drop",
]
RESET = f"""\
systemctl disable --now {SERVICE} nftables.service 2>/dev/null || true
rm -f {UNIT_PATH} {RULESET_PATH}
rmdir /etc/ops-deploy 2>/dev/null || true
systemctl daemon-reload
nft flush ruleset
nft add table inet keepme
"""
# A SYN with IPv4 options (NOP, NOP, NOP, EOL: IHL 6) and a plain connection to a loopback listener.
PROBE = """\
import socket
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(4)
port = srv.getsockname()[1]
opt = socket.socket()
opt.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b"\\x01\\x01\\x01\\x00")
opt.settimeout(2)
try:
    opt.connect(("127.0.0.1", port))
    print("options:connected")
except OSError:
    print("options:dropped")
plain = socket.socket()
plain.settimeout(2)
plain.connect(("127.0.0.1", port))
print("plain:connected")
"""
COUNTER = re.compile(r"ip hdrlength > 5 counter packets ([0-9]+) bytes [0-9]+ drop")


class Container:
    def __init__(self) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.identifier = os.environ["IP_OPTIONS_DROP_DOCKER_CONTAINER"]
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        info = json.loads(self.docker("container", "inspect", self.identifier).stdout)[0]
        assert info["Name"].startswith("/ops-deploy-ip-options-drop-")
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "ip-options-drop"
        assert info["HostConfig"]["NetworkMode"] == "none"
        assert info["HostConfig"]["Privileged"] is False
        assert "NET_ADMIN" in [name.removeprefix("CAP_") for name in info["HostConfig"]["CapAdd"]]
        assert not info["Mounts"]
        assert self.out("cat /proc/1/comm") == "systemd"

    def docker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.binary, *args], capture_output=True, text=True, check=True, timeout=120)

    def sh(self, command: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, "exec", self.identifier, "bash", "-c", command],
            capture_output=True,
            text=True,
            check=check,
            timeout=120,
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

    def deploy(self, cfg: IpOptionsDropConfig) -> DeployRun:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        run = DeployRun()
        try:
            connect_all(state)
            assert state.activated_hosts
            add_deploy(state, deploy_ip_options_drop, cfg)
            run_ops(state)
        except PyinfraError as exc:
            run.error = exc
        finally:
            run.ops = collect_ops(state, name)
            disconnect_all(state)
        return run

    def reboot(self) -> None:
        self.docker("restart", self.identifier)
        self.sh("systemctl is-system-running --wait", check=False)

    def tables(self) -> list[str]:
        return self.out("nft list tables").splitlines()

    def counter(self) -> int:
        match = COUNTER.search(self.out("nft list table ip ip_options_drop"))
        assert match is not None
        return int(match[1])

    def probe(self) -> list[str]:
        return self.out(f"python3 -I -c {shlex.quote(PROBE)}").splitlines()


def test_ip_options_drop_in_a_real_container(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Container()
    box.guard_connector(tmp_path, monkeypatch)
    box.sh(RESET)
    assert box.probe() == ["options:connected", "plain:connected"]

    # Run 1 installs, enables and starts; the drop works and is counted.
    first = box.deploy(IpOptionsDropConfig())
    assert first.succeeded, first.error
    assert first.mutating_changed_ops == FRESH
    assert box.out(f"systemctl is-active {SERVICE}; systemctl is-enabled {SERVICE}").split() == ["active", "enabled"]
    assert box.tables() == ["table inet keepme", "table ip ip_options_drop"]
    assert box.probe() == ["options:dropped", "plain:connected"]
    assert box.counter() >= 1

    # Run 2 changes nothing and keeps the counter.
    dropped = box.counter()
    second = box.deploy(IpOptionsDropConfig())
    assert second.succeeded, second.error
    assert second.mutating_changed_ops == []
    assert box.counter() == dropped

    # A flushed ruleset converges again with one reload.
    box.sh("nft flush ruleset")
    flushed = box.deploy(IpOptionsDropConfig())
    assert flushed.succeeded, flushed.error
    assert flushed.mutating_changed_ops == [P + f"Reload {SERVICE} (table missing or changed)"]
    assert box.tables() == ["table ip ip_options_drop"]

    # nftables.service flushes the whole ruleset; its reload and restart re-apply ours.
    box.sh("systemctl enable --now nftables.service")
    box.deploy(IpOptionsDropConfig())
    for action in ("reload", "restart"):
        box.sh(f"systemctl {action} nftables.service")
        assert "table ip ip_options_drop" in box.tables(), action
        assert "table inet filter" in box.tables(), action

    # A boot with nftables.service enabled: ours loads after its flush.
    box.reboot()
    assert box.out(f"systemctl is-active {SERVICE}") == "active"
    assert "table ip ip_options_drop" in box.tables()
    assert box.probe() == ["options:dropped", "plain:connected"]
    after_boot = box.deploy(IpOptionsDropConfig())
    assert after_boot.succeeded, after_boot.error
    assert after_boot.mutating_changed_ops == []

    # absent removes the unit, the file and the table; other tables stay.
    box.sh("nft add table inet keepme")
    removed = box.deploy(IpOptionsDropConfig(state="absent"))
    assert removed.succeeded, removed.error
    assert removed.mutating_changed_ops == REMOVED
    assert box.sh(f"test -e {UNIT_PATH} || test -e {RULESET_PATH}", check=False).returncode == 1
    assert box.out(f"systemctl is-enabled {SERVICE} 2>&1 || true") != "enabled"
    assert "table ip ip_options_drop" not in box.tables()
    assert {"table inet filter", "table inet keepme"} <= set(box.tables())
    assert box.probe() == ["options:connected", "plain:connected"]

    # A second absent run changes nothing; nothing comes back at boot.
    again = box.deploy(IpOptionsDropConfig(state="absent"))
    assert again.succeeded, again.error
    assert again.mutating_changed_ops == []
    box.reboot()
    assert "table ip ip_options_drop" not in box.tables()
    box.sh("systemctl disable --now nftables.service; nft flush ruleset")
