"""``deploy_ssh_guard`` against real sshd, fail2ban, nftables and systemd in an owned Docker container.

Skipped unless ``SSH_GUARD_DOCKER_CONTAINER`` names the full ID of a running
container labelled ``ops-deploy.fixture=ssh-guard`` with no network, systemd
as PID 1, ``NET_ADMIN`` (for nftables) and Debian 13's ``openssh-server``,
``fail2ban`` and ``python3-systemd`` installed, with the ``nftables`` packages
in apt's cache but not installed (``docs/base.md`` describes one). That is
the shape of a host where fail2ban runs the vulnerable sshd filter of
CVE-2026-109786 with an nftables ban action whose ``nft`` is missing.

The test resets the container's sshd drop-ins, fail2ban files and nftables
package to that shape, then deploys; it never touches
anything outside the container. The Docker CLI is wrapped so that pyinfra can
only inspect, exec and copy into that container: the connector's fallbacks
(start, run, commit, rm) fail instead. Only documentation addresses
(RFC 5737/3849) appear in log lines or bans.
"""

from __future__ import annotations

import ast
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
from ops_deploy.base.ssh_guard import (
    FILTER_OVERRIDE,
    FILTER_OVERRIDE_CONTENT,
    JAIL_PATH,
    render_dropin,
    render_jail,
)
from ops_deploy.testing.harness import DeployRun, collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("SSH_GUARD_DOCKER_CONTAINER"), reason="no owned ssh_guard Docker container"
)

DEFAULT = SshGuardConfig()
NFT_HOST = SshGuardConfig(
    fail2ban_banaction="nftables",
    fail2ban_journalmatch="_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session",
    fail2ban_ban_only=True,
    fail2ban_no_recommends=True,
    fail2ban_ignoreip="127.0.0.1/8 ::1",
    per_source_net_block_size="32:64",
)
DROPIN = NFT_HOST.sshd_dropin_path
CONFLICT = "/etc/ssh/sshd_config.d/10-conflict.conf"
WRITE_FILTER = f"SSH guard | Write {FILTER_OVERRIDE} (CVE-2026-109786)"
WRITE_JAIL = f"SSH guard | Write {JAIL_PATH}"
RESTART = "SSH guard | Restart fail2ban for the new filter or jail"
GATE_EARLY = "SSH guard | Check the jail before the package installs"
INSTALL_NFT = "SSH guard | Install nftables"
RESTART_PACKAGES = "SSH guard | Restart fail2ban for the new packages"
GATE = "SSH guard | Check the jail"
WRITE_DROPIN = f"SSH guard | Write {DROPIN}"
VALIDATE = "SSH guard | Validate the sshd configuration"
RELOAD = "SSH guard | Reload ssh for the new drop-in"
ATTACKER, VICTIM = "203.0.113.7", "198.51.100.23"
ATTACKER6, VICTIM6 = "2001:db8:a::7", "2001:db8:b::23"

# CVE-2026-109786 sessions: the user name carries "<victim> on", so the stock
# filter attributes the close line to the victim. Each must attribute only
# the attacker with the fix; the legitimate sessions must stay as they are.
SPOOFS = {
    "close": [
        f"Invalid user x {VICTIM} on from {ATTACKER} port 4444",
        f"Connection closed by invalid user x {VICTIM} on {ATTACKER} port 4444 [preauth]",
    ],
    "password then close": [
        f"Failed password for invalid user x {VICTIM} on from {ATTACKER} port 4444 ssh2",
        f"Connection closed by invalid user x {VICTIM} on {ATTACKER} port 4444 [preauth]",
    ],
    "disconnected": [
        f"Invalid user x {VICTIM} on from {ATTACKER} port 4444",
        f"Disconnected from invalid user x {VICTIM} on {ATTACKER} port 4444 [preauth]",
    ],
    "authenticating user": [
        f"Failed password for x {VICTIM} on from {ATTACKER} port 4444 ssh2",
        f"Connection closed by authenticating user x {VICTIM} on {ATTACKER} port 4444 [preauth]",
    ],
    "ipv6": [
        f"Invalid user x {VICTIM6} on from {ATTACKER6} port 4444",
        f"Connection closed by invalid user x {VICTIM6} on {ATTACKER6} port 4444 [preauth]",
    ],
}
LEGIT = {
    "root password": (["Failed password for root from 203.0.113.9 port 51234 ssh2"], ["203.0.113.9"]),
    "invalid user": (
        [
            "Invalid user admin from 203.0.113.9 port 51234",
            "Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2",
        ],
        ["203.0.113.9", "203.0.113.9"],
    ),
    "ipv6 password": (["Failed password for root from 2001:db8:c::9 port 51234 ssh2"], ["2001:db8:c::9"]),
    "accepted key": (["Accepted publickey for root from 203.0.113.10 port 51234 ssh2: ED25519 SHA256:AAAA"], []),
}


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
        # Docker reports it as CAP_NET_ADMIN or NET_ADMIN, depending on the version.
        assert {"NET_ADMIN", "CAP_NET_ADMIN"} & set(info["HostConfig"]["CapAdd"] or [])
        assert not info["Mounts"]
        assert self.out("cat /proc/1/comm") == "systemd"

    def docker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.binary, *args], capture_output=True, text=True, check=True, timeout=60)

    def sh(self, command: str, *, check: bool = True, timeout: int = 180) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, "exec", self.identifier, "sh", "-c", command],
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
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

    def active(self, unit: str) -> str:
        return self.out(f"systemctl is-active {unit} || true")

    def sighups(self) -> int:
        # sshd logs this line on every reload.
        return int(self.out("journalctl -u ssh --no-pager -o cat | grep -c 'Received SIGHUP' || true"))

    def stat(self, path: str) -> str:
        return self.out(f"stat -c '%U:%G %a' {shlex.quote(path)}")

    def read(self, path: str) -> str:
        return self.sh(f"cat {shlex.quote(path)}").stdout

    def exists(self, path: str) -> bool:
        return self.sh(f"test -e {shlex.quote(path)}", check=False).returncode == 0

    def vulnerable_regexes(self) -> int:
        return int(self.out("fail2ban-client get sshd failregex | grep -cF 'on \\S+' || true"))

    def actions(self) -> str:
        return self.out("fail2ban-client get sshd actions | sed 1d")

    def wait_for_jail(self) -> None:
        self.sh("i=0; until fail2ban-client status sshd >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 60 ]; sleep 1; done")

    def attributed(self, lines: list[str]) -> list[str]:
        """Hosts the installed ``sshd`` filter attributes to one session, without writing a file.

        fail2ban-regex takes a log string with line breaks as that many lines.
        """

        stamped = "\n".join(f"Oct 24 08:00:01 host sshd-session[2001]: {line}" for line in lines)
        result = self.sh(f"fail2ban-regex -o row {shlex.quote(stamped)} sshd")
        hosts = []
        for row in result.stdout.splitlines():
            row = row.strip().rstrip(",")
            if row.startswith("["):
                hosts.append(str(ast.literal_eval(row)[0]))
        return hosts

    def nft_table(self) -> str:
        return self.out("nft list table inet f2b-table 2>/dev/null || true")

    def reset(self) -> None:
        """An exposed host: stock filter, Debian's nftables default ban action, no nft, no guard files."""

        self.sh(
            f"rm -f {FILTER_OVERRIDE} {JAIL_PATH} {DROPIN} {CONFLICT}; "
            "if dpkg -s nftables >/dev/null 2>&1; then "
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq nftables; fi; "
            "systemctl start ssh; systemctl restart fail2ban",
            timeout=300,
        )
        self.wait_for_jail()


def test_ssh_guard_in_a_real_container(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Container()
    box.guard_connector(tmp_path, monkeypatch)
    box.reset()

    # The fixture reproduces the CVE: the stock filter is loaded and blames the victim.
    assert box.vulnerable_regexes() == 18
    assert box.actions() == "nftables"
    assert box.sh("command -v nft", check=False).returncode != 0
    for lines in SPOOFS.values():
        assert box.attributed(lines)[-1] in (VICTIM, VICTIM6)

    # Run 1: override and jail, restart and check, then nftables, restart and
    # check again, then the drop-in with sshd -t/-T and one reload.
    ssh, hups = box.pid("ssh"), box.sighups()
    first = box.deploy(NFT_HOST)
    assert first.succeeded, first.error
    assert first.mutating_changed_ops == [
        WRITE_FILTER,
        WRITE_JAIL,
        RESTART,
        GATE_EARLY,
        INSTALL_NFT,
        RESTART_PACKAGES,
        GATE,
        WRITE_DROPIN,
        VALIDATE,
        RELOAD,
    ]
    assert box.read(FILTER_OVERRIDE) == FILTER_OVERRIDE_CONTENT
    assert box.read(JAIL_PATH) == render_jail(NFT_HOST)
    assert box.read(DROPIN) == render_dropin(NFT_HOST)
    assert box.stat(FILTER_OVERRIDE) == box.stat(JAIL_PATH) == box.stat(DROPIN) == "root:root 644"
    assert box.vulnerable_regexes() == 0
    assert box.actions() == "nftables"
    assert box.out("fail2ban-client get sshd journalmatch | tail -n 1") == NFT_HOST.fail2ban_journalmatch
    assert box.out("fail2ban-client get sshd ignoreip | sed 1d | tr -d ' |`-' | sort | tr '\\n' ' '").split() == [
        "127.0.0.0/8",  # fail2ban prints the network of 127.0.0.1/8
        "::1",
    ]
    assert box.out("command -v nft") == "/usr/sbin/nft"
    assert box.out("systemctl is-enabled nftables.service || true") == "disabled"
    assert box.pid("ssh") == ssh
    assert box.sighups() == hups + 1
    assert "persourcenetblocksize 32:64" in box.out("sshd -T")

    # The spoof regression on the installed filter, and the legitimate sessions.
    for case, lines in SPOOFS.items():
        attacker = ATTACKER6 if case == "ipv6" else ATTACKER
        assert set(box.attributed(lines)) == {attacker}, case
    for case, (lines, expected) in LEGIT.items():
        assert box.attributed(lines) == expected, case

    # Bans reach nftables for both families and an unban removes them.
    box.sh(f"fail2ban-client set sshd banip {ATTACKER} {ATTACKER6}")
    table = box.nft_table()
    assert re.search(rf"set addr-set-sshd \{{.*elements = \{{ {re.escape(ATTACKER)} \}}", table, re.S)
    assert re.search(rf"set addr6-set-sshd \{{.*elements = \{{ {re.escape(ATTACKER6)} \}}", table, re.S)
    assert "tcp dport 22 ip saddr @addr-set-sshd reject" in table
    assert "tcp dport 22 ip6 saddr @addr6-set-sshd reject" in table
    box.sh(f"fail2ban-client set sshd unbanip {ATTACKER} {ATTACKER6}")
    assert ATTACKER not in box.nft_table()
    assert ATTACKER6 not in box.nft_table()

    # Run 2: nothing changes, nothing is restarted or reloaded.
    f2b, hups = box.pid("fail2ban"), box.sighups()
    second = box.deploy(NFT_HOST)
    assert second.succeeded, second.error
    assert second.changed_ops == []
    assert (box.pid("fail2ban"), box.sighups()) == (f2b, hups)

    # Files right, but fail2ban still runs the vulnerable filter (a run
    # interrupted before its restart): restarted and checked, nothing written.
    box.sh(
        f"mv {FILTER_OVERRIDE} /root/override && systemctl restart fail2ban && "
        "i=0; until fail2ban-client status sshd >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 60 ]; sleep 1; done; "
        f"mv /root/override {FILTER_OVERRIDE}"
    )
    assert box.vulnerable_regexes() == 18
    stale = box.deploy(NFT_HOST)
    assert stale.succeeded, stale.error
    assert stale.mutating_changed_ops == [RESTART, GATE_EARLY, GATE]
    assert box.vulnerable_regexes() == 0
    assert box.sighups() == hups

    # Jail drift: rewritten, fail2ban restarted and checked; ssh untouched.
    box.sh(f"sed -i 's/^maxretry = 5$/maxretry = 9/' {JAIL_PATH} && systemctl restart fail2ban")
    box.wait_for_jail()
    f2b, hups = box.pid("fail2ban"), box.sighups()
    jail = box.deploy(NFT_HOST)
    assert jail.succeeded, jail.error
    assert jail.mutating_changed_ops == [WRITE_JAIL, RESTART, GATE_EARLY, GATE]
    assert box.pid("fail2ban") != f2b
    assert box.sighups() == hups
    assert box.out("fail2ban-client get sshd maxretry") == "5"

    # A vulnerable filter that gets loaded is caught: with the fix off and the
    # override gone, the gate stops fail2ban (its nftables table goes too).
    box.sh(f"fail2ban-client set sshd banip {ATTACKER}")
    assert ATTACKER in box.nft_table()
    box.sh(f"rm -f {FILTER_OVERRIDE} && sed -i 's/^maxretry = 5$/maxretry = 9/' {JAIL_PATH}")
    hups = box.sighups()
    exposed = box.deploy(NFT_HOST.model_copy(update={"fail2ban_sshd_filter_fix": "off"}))
    assert not exposed.succeeded
    assert exposed.op(GATE_EARLY).succeeded is False
    assert box.active("fail2ban") == "inactive"
    assert box.nft_table() == ""
    assert box.sighups() == hups
    # The next run with the fix puts the override back and starts fail2ban
    # (the failed run had already rewritten the jail).
    fixed = box.deploy(NFT_HOST)
    assert fixed.succeeded, fixed.error
    assert fixed.mutating_changed_ops == [WRITE_FILTER, RESTART, GATE_EARLY, GATE]
    assert box.active("fail2ban") == "active"
    assert box.vulnerable_regexes() == 0

    # Drop-in drift: checked and reloaded; fail2ban untouched.
    box.sh(f"echo 'MaxAuthTries 50' >> {DROPIN}")
    f2b, ssh, hups = box.pid("fail2ban"), box.pid("ssh"), box.sighups()
    dropin = box.deploy(NFT_HOST)
    assert dropin.succeeded, dropin.error
    assert dropin.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]
    assert (box.pid("fail2ban"), box.pid("ssh")) == (f2b, ssh)
    assert box.sighups() == hups + 1

    # An earlier drop-in that sets the same directive wins in sshd (the first
    # value counts for PerSourceMaxStartups; OpenSSH 10.0 takes the last
    # PerSourceNetBlockSize): sshd -t passes, sshd -T shows the other value,
    # so the drop-in is removed and ssh is not reloaded.
    box.sh(f"printf 'PerSourceMaxStartups 7\\n' > {CONFLICT} && echo '# drift' >> {DROPIN}")
    hups = box.sighups()
    shadowed = box.deploy(NFT_HOST)
    assert not shadowed.succeeded
    assert shadowed.op(VALIDATE).succeeded is False
    assert not shadowed.op(RELOAD).changed
    assert not box.exists(DROPIN)
    assert box.sighups() == hups
    box.sh(f"rm -f {CONFLICT}")
    restored = box.deploy(NFT_HOST)
    assert restored.succeeded, restored.error
    assert restored.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]

    # A value sshd rejects: the drop-in is removed, the deploy fails, ssh is not reloaded.
    hups = box.sighups()
    bad = box.deploy(NFT_HOST.model_copy(update={"per_source_max_startups": "not-a-number"}))
    assert not bad.succeeded
    names = [op.name for op in bad.ops]
    assert all(op.succeeded for op in bad.ops[: names.index(VALIDATE)])
    assert bad.op(VALIDATE).succeeded is False
    assert not bad.op(RELOAD).changed
    assert not box.exists(DROPIN)
    assert box.sighups() == hups
    assert box.pid("ssh") == ssh
    assert box.active("ssh") == "active"
    assert box.sh("sshd -t -f /etc/ssh/sshd_config", check=False).returncode == 0
    recovered = box.deploy(NFT_HOST)
    assert recovered.succeeded, recovered.error
    assert recovered.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]
    assert box.read(DROPIN) == render_dropin(NFT_HOST)

    # With ssh stopped, Debian removes /run/sshd and ``sshd -t`` fails on that
    # alone: the drop-in is removed and the deploy fails, exactly as the role's
    # command does. Starting ssh and deploying again recovers.
    box.sh(f"systemctl stop ssh && echo 'MaxAuthTries 3' >> {DROPIN}")
    stopped = box.deploy(NFT_HOST)
    assert not stopped.succeeded
    assert stopped.op(VALIDATE).succeeded is False
    assert not box.exists(DROPIN)
    assert box.active("ssh") == "inactive"
    box.sh("systemctl start ssh")
    recovered = box.deploy(NFT_HOST)
    assert recovered.succeeded, recovered.error
    assert recovered.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]

    # A stopped ssh whose privilege separation directory is still there is
    # started, as the role's ``state: reloaded`` handler does.
    box.sh(f"systemctl stop ssh && mkdir -p /run/sshd && echo 'MaxAuthTries 3' >> {DROPIN}")
    started = box.deploy(NFT_HOST)
    assert started.succeeded, started.error
    assert started.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]
    assert box.active("ssh") == "active"

    final = box.deploy(NFT_HOST)
    assert final.succeeded, final.error
    assert final.changed_ops == []

    # The role's defaults on an exposed host: no ban action configured, the
    # jail runs Debian's nftables default, so nftables is installed as well.
    box.reset()
    default = box.deploy(DEFAULT)
    assert default.succeeded, default.error
    assert default.mutating_changed_ops == [
        WRITE_FILTER,
        WRITE_JAIL,
        RESTART,
        GATE_EARLY,
        INSTALL_NFT,
        RESTART_PACKAGES,
        GATE,
        WRITE_DROPIN,
        VALIDATE,
        RELOAD,
    ]
    assert box.vulnerable_regexes() == 0
    assert box.actions() == "nftables"
    assert box.deploy(DEFAULT).changed_ops == []


def test_existing_bans_survive_filter_only_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Heis shape: existing policy/enforcement, no package/jail/drop-in change."""
    box = Container()
    box.guard_connector(tmp_path, monkeypatch)
    box.reset()
    box.sh("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download --no-install-recommends nftables")
    for path, text in ((JAIL_PATH, render_jail(DEFAULT)), (DROPIN, render_dropin(DEFAULT))):
        box.sh(f"printf %s {shlex.quote(text)} > {shlex.quote(path)}; chmod 0644 {shlex.quote(path)}")
    box.sh("systemctl restart fail2ban")
    box.wait_for_jail()
    assert box.vulnerable_regexes() > 0
    assert box.actions() == "nftables"
    box.sh(f"fail2ban-client set sshd banip {ATTACKER} {ATTACKER6}")
    assert ATTACKER in box.nft_table()
    assert ATTACKER6 in box.nft_table()
    before = {
        "package": box.out("dpkg-query -W -f='${Version}' fail2ban"),
        "ssh": box.pid("ssh"),
        "jail": box.read(JAIL_PATH),
        "dropin": box.read(DROPIN),
    }
    old_pid = box.pid("fail2ban")
    repaired = box.deploy(DEFAULT)
    assert repaired.succeeded, repaired.error
    assert repaired.mutating_changed_ops == [WRITE_FILTER, RESTART, GATE_EARLY, GATE]
    assert box.pid("fail2ban") != old_pid
    assert box.vulnerable_regexes() == 0
    assert box.out("dpkg-query -W -f='${Version}' fail2ban") == before["package"]
    assert box.pid("ssh") == before["ssh"]
    assert box.read(JAIL_PATH) == before["jail"]
    assert box.read(DROPIN) == before["dropin"]
    # The real fail2ban database restores bans after its required restart;
    # both IPv4 and IPv6 must again be enforced, not just listed by the jail.
    for _ in range(30):
        if ATTACKER in box.nft_table() and ATTACKER6 in box.nft_table():
            break
        box.sh("sleep 1")
    assert ATTACKER in box.nft_table()
    assert ATTACKER6 in box.nft_table()
    assert box.deploy(DEFAULT).changed_ops == []
    box.sh(f"fail2ban-client set sshd unbanip {ATTACKER} {ATTACKER6}")
