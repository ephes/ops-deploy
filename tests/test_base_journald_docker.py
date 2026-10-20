"""``journald_config`` against a real systemd and journald in an owned Docker fixture.

Skipped unless ``JOURNALD_SYSTEMD_DOCKER_CONTAINER`` names the full ID of a
running fixture container (see ``docs/base.md``, "journald_config"). It checks
what the fake connector cannot: journald really restarts (new invocation and
PID) only when the drop-in changed, a converged run leaves the running
journald alone, and the flush moves a volatile journal to ``/var/log/journal``.
With ``OPS_LIBRARY_PATH`` set, the role itself writes the drop-in first and
the deploy must then change nothing.
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
from pyinfra.api.operations import run_ops
from pyinfra.connectors.docker import DockerConnector

from ops_deploy.base import JournaldConfig, deploy_journald_config
from ops_deploy.base.journald_config import DEFAULT_DROPIN, render_journald_dropin
from ops_deploy.testing.harness import OpResult, collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("JOURNALD_SYSTEMD_DOCKER_CONTAINER"), reason="no explicitly owned systemd Docker fixture"
)

NAME = "/ops-deploy-systemd-journald-20261020"
RUN_LABEL = "journald-20261020"
# The role's Molecule values, plus one extra setting.
CFG = JournaldConfig(
    system_max_use="2G",
    system_max_file_size="64M",
    system_max_files=500,
    max_retention_sec="21day",
    extra_settings={"Compress": True},
)
CHANGED = [
    "journald config | Ensure /etc/systemd/journald.conf.d",
    f"journald config | Write {DEFAULT_DROPIN}",
    "journald config | Restart systemd-journald",
    "journald config | Flush journal to persistent storage",
]


class Fixture:
    def __init__(self) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.identifier = os.environ["JOURNALD_SYSTEMD_DOCKER_CONTAINER"]
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        info = json.loads(self.docker("container", "inspect", self.identifier).stdout)[0]
        # Only the owned, isolated fixture: no network, mounts, ports or devices.
        assert info["Name"] == NAME
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "journald-systemd"
        assert info["Config"]["Labels"]["ops-deploy.run"] == RUN_LABEL
        cfg = info["HostConfig"]
        assert cfg["NetworkMode"] == "none"
        assert cfg["Privileged"] is False
        assert cfg["CgroupnsMode"] == "private"
        assert not cfg["Binds"]
        assert not cfg.get("Mounts")
        assert not cfg["PortBindings"]
        assert not cfg["Devices"]
        assert [name.removeprefix("CAP_") for name in cfg["CapAdd"]] == ["SYS_ADMIN"]
        assert self.sh("cat /proc/1/comm") == "systemd"

    def docker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.binary, *args], capture_output=True, text=True, check=True, timeout=120)

    def sh(self, command: str) -> str:
        return self.docker("exec", "-i", self.identifier, "sh", "-c", command).stdout.strip()

    def journald(self) -> tuple[str, str]:
        """(InvocationID, MainPID): both change on every (re)start."""

        invocation = self.sh("systemctl show -p InvocationID --value systemd-journald")
        pid = self.sh("systemctl show -p MainPID --value systemd-journald")
        assert invocation
        assert pid not in ("", "0")
        return invocation, pid

    def dropin(self) -> str:
        """Owner, mode, inode, mtime and content of the drop-in."""

        return self.sh(f"stat -c '%U:%G %a %i %Y' {DEFAULT_DROPIN} && cat {DEFAULT_DROPIN}")

    def guard_connector(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # pyinfra may only inspect, exec in and copy into the container: never start, commit or remove it.
        wrapper = tmp / "docker-transport"
        wrapper.write_text(
            '#!/bin/sh\ncase "$1:$2" in container:inspect|exec:*|cp:*) ;; *) exit 97 ;; esac\nexec '
            + shlex.quote(self.binary)
            + ' "$@"\n'
        )
        wrapper.chmod(0o700)
        monkeypatch.setattr(DockerConnector, "docker_cmd", shlex.quote(str(wrapper)))

    def settle(self) -> None:
        """Clear systemd's start rate limit (5 starts in 10 s), which these
        back-to-back restarts would hit; it is no part of the behaviour tested.
        The running journald (invocation, PID) is left alone."""

        self.sh("systemctl reset-failed systemd-journald systemd-journald.socket systemd-journald-dev-log.socket")

    def deploy(self, cfg: JournaldConfig) -> list[OpResult]:
        self.settle()
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        try:
            connect_all(state)
            assert state.activated_hosts
            add_deploy(state, deploy_journald_config, cfg)
            run_ops(state)
            ops = collect_ops(state, name)
        finally:
            disconnect_all(state)
        assert all(op.succeeded for op in ops), ops
        return ops

    def reset(self) -> None:
        """No drop-in (nor its directory), persistent journal, journald freshly started."""

        self.settle()
        self.sh(
            f"rm -f {DEFAULT_DROPIN} && (rmdir /etc/systemd/journald.conf.d 2>/dev/null || true) "
            "&& systemctl restart systemd-journald && journalctl --flush"
        )
        assert self.sh("systemctl is-active systemd-journald") == "active"


def mutating(ops: list[OpResult]) -> list[str]:
    return [op.name for op in ops if op.changed and not op.read_only]


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fixture:
    host = Fixture()
    host.guard_connector(tmp_path, monkeypatch)
    host.reset()
    return host


def test_restarts_and_flushes_only_when_the_drop_in_changes(fixture: Fixture) -> None:
    before = fixture.journald()

    assert mutating(fixture.deploy(CFG)) == CHANGED
    written = fixture.journald()
    assert written != before
    assert fixture.sh(f"cat {DEFAULT_DROPIN}") + "\n" == render_journald_dropin(CFG)
    assert fixture.sh(f"stat -c '%U:%G %a' {DEFAULT_DROPIN} /etc/systemd/journald.conf.d") == (
        "root:root 644\nroot:root 755"
    )
    effective = fixture.sh("systemd-analyze cat-config systemd/journald.conf")
    assert DEFAULT_DROPIN in effective
    assert "SystemMaxFiles=500" in effective

    # Converged: the same journald keeps running and the file is untouched.
    snapshot = fixture.dropin()
    ops = fixture.deploy(CFG)
    assert mutating(ops) == []
    assert [op.name for op in ops if op.changed] == ["journald config | Check systemd-journald is running"]
    assert fixture.journald() == written
    assert fixture.dropin() == snapshot

    # Mode drift alone restarts, as the role's template change would.
    fixture.sh(f"chmod 0600 {DEFAULT_DROPIN}")
    assert mutating(fixture.deploy(CFG)) == CHANGED[1:]
    assert fixture.sh(f"stat -c '%a' {DEFAULT_DROPIN}") == "644"
    drifted = fixture.journald()
    assert drifted != written

    # restart_on_change off: the new file is written, journald keeps running.
    quiet = CFG.model_copy(update={"system_max_files": "600", "restart_on_change": False})
    assert mutating(fixture.deploy(quiet)) == [f"journald config | Write {DEFAULT_DROPIN}"]
    assert fixture.journald() == drifted


def test_flush_moves_a_volatile_journal_to_disk(fixture: Fixture) -> None:
    volatile = CFG.model_copy(update={"storage": "volatile"})
    assert mutating(fixture.deploy(volatile)) == CHANGED[:3]

    # As on a host that has always been volatile: no flushed marker, no persistent journal.
    fixture.settle()
    fixture.sh(
        "systemctl stop systemd-journald && rm -f /run/systemd/journal/flushed "
        '&& mv /var/log/journal "$(mktemp -u /var/log/journal.before-volatile.XXXXXX)" '
        "&& systemctl start systemd-journald "
        "&& logger -t journald-config-docker 'volatile entry'"
    )
    assert fixture.sh("find /run/log/journal -name system.journal")
    assert fixture.sh("test -d /var/log/journal && echo present || echo absent") == "absent"

    assert mutating(fixture.deploy(CFG)) == CHANGED[1:]
    assert fixture.sh("find /var/log/journal -name system.journal")
    assert fixture.sh("find /run/log/journal -name system.journal 2>/dev/null || true") == ""
    assert "volatile entry" in fixture.sh("journalctl -t journald-config-docker --no-pager")


def test_absent_removes_the_drop_in_once(fixture: Fixture) -> None:
    fixture.deploy(CFG)
    present = fixture.journald()

    assert mutating(fixture.deploy(CFG.model_copy(update={"state": "absent"}))) == [
        f"journald config | Remove {DEFAULT_DROPIN}",
        "journald config | Restart systemd-journald",
    ]
    removed = fixture.journald()
    assert removed != present
    assert fixture.sh(f"test -e {DEFAULT_DROPIN} && echo present || echo absent") == "absent"

    assert mutating(fixture.deploy(JournaldConfig(state="absent"))) == []
    assert fixture.journald() == removed


def test_symlinked_drop_in_is_replaced_or_unlinked_never_followed(fixture: Fixture) -> None:
    target = fixture.sh("mktemp /root/journald-link-target.XXXXXX")
    fixture.sh(f"printf 'not journald' > {target} && chmod 0600 {target}")
    untouched = fixture.sh(f"stat -c '%U:%G %a %i %Y %s' {target} && cat {target}")
    link = f"mkdir -p /etc/systemd/journald.conf.d && ln -sfn {target} {DEFAULT_DROPIN}"

    fixture.sh(link)
    before = fixture.journald()
    assert mutating(fixture.deploy(CFG)) == [f"journald config | Remove {DEFAULT_DROPIN}", *CHANGED[1:]]
    assert fixture.sh(f"test ! -L {DEFAULT_DROPIN} && test -f {DEFAULT_DROPIN} && echo regular") == "regular"
    assert fixture.sh(f"cat {DEFAULT_DROPIN}") + "\n" == render_journald_dropin(CFG)
    assert fixture.sh(f"stat -c '%U:%G %a %i %Y %s' {target} && cat {target}") == untouched
    assert fixture.journald() != before

    fixture.sh(f"rm -f {DEFAULT_DROPIN} && {link}")
    linked = fixture.journald()
    assert mutating(fixture.deploy(JournaldConfig(state="absent"))) == [
        f"journald config | Remove {DEFAULT_DROPIN}",
        "journald config | Restart systemd-journald",
    ]
    assert fixture.sh(f"test -e {DEFAULT_DROPIN} || test -L {DEFAULT_DROPIN} || echo gone") == "gone"
    assert fixture.sh(f"stat -c '%U:%G %a %i %Y %s' {target} && cat {target}") == untouched
    assert fixture.journald() != linked


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_switching_from_the_role_changes_nothing(fixture: Fixture) -> None:
    role = Path(os.environ["OPS_LIBRARY_PATH"], "roles", "journald_config")
    assert role.is_dir()
    base = fixture.sh("mktemp -d /opt/journald-role.XXXXXX")
    fixture.sh(f"mkdir {base}/roles")
    fixture.docker("cp", str(role), f"{fixture.identifier}:{base}/roles/journald_config")
    play = (
        "- hosts: localhost\n  roles:\n    - role: journald_config\n      vars:\n"
        '        journald_config_system_max_use: "2G"\n        journald_config_system_max_file_size: "64M"\n'
        '        journald_config_system_max_files: 500\n        journald_config_max_retention_sec: "21day"\n'
        "        journald_config_extra_settings:\n          Compress: true\n"
    )
    fixture.sh(f"printf %s {shlex.quote(play)} > {base}/play.yml")
    before = fixture.journald()
    recap = fixture.sh(f"cd {base} && ANSIBLE_ROLES_PATH=roles ansible-playbook -c local -i localhost, play.yml")
    assert re.search(r"localhost\s+: ok=\d+\s+changed=[1-9]\d*\s+unreachable=0\s+failed=0", recap), recap
    by_role = fixture.journald()
    assert by_role != before
    snapshot = fixture.dropin()

    assert mutating(fixture.deploy(CFG)) == []
    assert fixture.journald() == by_role
    assert fixture.dropin() == snapshot
    assert fixture.sh(f"cat {DEFAULT_DROPIN}") + "\n" == render_journald_dropin(CFG)
