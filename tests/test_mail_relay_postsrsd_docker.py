"""``mail_relay`` with postsrsd 2.x against real Postfix 3.10 and postsrsd 2.0 in an owned Docker fixture.

Skipped unless ``MAIL_RELAY_POSTSRSD_DOCKER_CONTAINER`` names the full ID of a
running fixture container (see ``docs/services/mail_relay.md``, "postsrsd 1.x
and 2.x"). The container has no network. It starts in the shape a release
upgrade leaves behind: postsrsd 2.x installed with its packaged
``/etc/postsrsd.conf``, the 1.x deploy's ``/etc/default/postsrsd`` and SRS
secret still in place. It checks what the fake connector cannot: the first run
switches postsrsd and Postfix to the socketmap, the secret file keeps its
bytes and inode, Postfix's own lookup tables (``postmap -q`` in the queue
directory, as the chrooted cleanup daemon resolves them) and a message through
``sendmail`` and cleanup rewrite forward and back, own domains stay untouched,
the second run changes nothing and keeps every daemon's PID, and a drifted
``postsrsd.conf`` is put back with a postsrsd restart.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.connectors.docker import DockerConnector

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.mail_relay import MailRelayConfig, deploy_mail_relay
from ops_deploy.services.mail_relay.render import render_role
from ops_deploy.testing.harness import OpResult, collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("MAIL_RELAY_POSTSRSD_DOCKER_CONTAINER"), reason="no explicitly owned postsrsd 2.x Docker fixture"
)

NAME = "/ops-deploy-mail-relay-postsrsd2-20261029"
RUN_LABEL = "mail-relay-postsrsd2-20261029"
SECRETS = SecretValues(
    SecretRef("fixture.yml"), {"sasl_password": "fixture-sasl-password", "srs_secret": "fixture-srs-signing-secret"}
)
CFG = MailRelayConfig(
    domains=("relay.example.test", "own.example.test"),
    hostname="mx.relay.example.test",
    mydomain="relay.example.test",
    backend_host="backend.example.test",
    tls_cert="/etc/ssl/certs/ssl-cert-snakeoil.pem",
    tls_key="/etc/ssl/private/ssl-cert-snakeoil.key",
    recipient_rewrites=({"from": "@alias.example.test", "to": "@own.example.test"},),
    srs_enabled=True,
    srs_domain="relay.example.test",
    srs_exclude_domains=("relay.example.test", "own.example.test"),
    verify_recipients=True,
    postscreen_enabled=True,
    submission_discard_spam=True,
)
DAEMONS = ("postfix", "postsrsd", "postgrey")


class Fixture:
    def __init__(self) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.identifier = os.environ["MAIL_RELAY_POSTSRSD_DOCKER_CONTAINER"]
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        info = json.loads(self.docker("container", "inspect", self.identifier).stdout)[0]
        # Only the owned, isolated fixture: no network, mounts, ports or devices.
        assert info["Name"] == NAME
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "mail-relay-postsrsd2"
        assert info["Config"]["Labels"]["ops-deploy.run"] == RUN_LABEL
        cfg = info["HostConfig"]
        assert cfg["NetworkMode"] == "none"
        assert cfg["Privileged"] is False
        assert cfg["CgroupnsMode"] == "private"
        assert not cfg["Binds"]
        assert not cfg.get("Mounts")
        assert not cfg["PortBindings"]
        assert not cfg["Devices"]
        assert sorted(name.removeprefix("CAP_") for name in cfg["CapAdd"]) == ["SYS_ADMIN", "SYS_PTRACE"]
        # Postfix's queue and postgrey's database live on tmpfs (non-root writers stay off the Docker disk).
        assert set(cfg["Tmpfs"]) == {"/run", "/run/lock", "/var/spool/postfix", "/var/lib/postgrey"}
        assert self.sh("cat /proc/1/comm") == "systemd"
        assert self.sh("dpkg-query -W -f='${Version}' postsrsd").startswith("2.")

    def docker(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, *args], input=stdin, capture_output=True, text=True, check=True, timeout=600
        )

    def sh(self, command: str, stdin: str | None = None) -> str:
        return self.docker("exec", "-i", self.identifier, "sh", "-c", command, stdin=stdin).stdout.strip()

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

    def reset(self) -> None:
        """The state a 24.04 -> 26.04 release upgrade leaves: 2.x on its packaged config, 1.x files kept."""

        self.sh(
            "systemctl stop postfix postsrsd; postsuper -d ALL >/dev/null 2>&1; "
            "rm -rf /var/lib/ops-deploy /etc/postfix/sasl/smtpd.conf /etc/sasldb2 "
            "&& cp /opt/postsrsd.conf.packaged /etc/postsrsd.conf "
            "&& printf '%s\\n' fixture-srs-signing-secret > /etc/postsrsd.secret && chmod 0600 /etc/postsrsd.secret"
        )
        # The 1.x deploy's files: postsrsd defaults and a main.cf with tcp: maps.
        self.sh("cat > /etc/default/postsrsd", stdin=render_role("postsrsd.default.j2", CFG, SECRETS))
        self.sh("cat > /etc/postfix/main.cf", stdin=render_role("main.cf.j2", CFG, SECRETS))
        # The package's postinst restarts postsrsd 2.x on its packaged configuration.
        self.sh("systemctl restart postsrsd; systemctl start postfix; true")

    def deploy(self) -> list[OpResult]:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        connect_all(state)
        assert state.activated_hosts
        try:
            add_deploy(state, deploy_mail_relay, CFG, SECRETS)
            run_ops(state)
            ops = collect_ops(state, name)
        finally:
            disconnect_all(state)
        assert all(op.succeeded for op in ops), [op for op in ops if not op.succeeded]
        return ops

    def pids(self) -> dict[str, str]:
        return {unit: self.sh(f"systemctl show -p MainPID --value {unit}") for unit in DAEMONS}

    def lookup(self, key: str, parameter: str) -> str:
        """The first answer of the parameter's tables, in order, as Postfix searches them."""

        for table in self.sh(f"postconf -h {parameter}").split(", "):
            # Postfix daemons resolve the relative socketmap path in the queue directory.
            answer = self.sh(f"cd /var/spool/postfix && postmap -q {shlex.quote(key)} {shlex.quote(table)} || true")
            if answer:
                return answer
        return ""

    def queued(self, sender: str, recipient: str) -> dict[str, Any]:
        message = f"From: {sender or 'MAILER-DAEMON'}\nTo: {recipient}\nSubject: srs fixture\n\nbody\n"
        self.sh(f"sendmail -f {shlex.quote(sender)} {shlex.quote(recipient)}", stdin=message)
        for _ in range(30):
            entries: list[dict[str, Any]] = [json.loads(line) for line in self.sh("postqueue -j").splitlines() if line]
            # A maildrop entry has not been through cleanup (and its canonical maps) yet.
            if entries and all(entry["queue_name"] != "maildrop" for entry in entries):
                self.sh("postsuper -d ALL >/dev/null 2>&1")
                assert len(entries) == 1, entries
                return entries[0]
            time.sleep(1)
        raise AssertionError("message never got through cleanup into the queue")


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fixture:
    host = Fixture()
    host.guard_connector(tmp_path, monkeypatch)
    host.reset()
    return host


def managed(ops: list[OpResult]) -> list[str]:
    return [op.name for op in ops if op.changed and not op.read_only]


def test_switch_to_socketmap_then_converged(fixture: Fixture) -> None:
    secret_before = fixture.sh("stat -c '%i %s %a %U' /etc/postsrsd.secret && sha256sum /etc/postsrsd.secret")
    ops = fixture.deploy()
    names = [op.name.split(" | ", 1)[1] for op in ops]
    assert names.index("Verify relay SRS socketmap round trip") < names.index("Restart postfix.service")
    assert fixture.sh("test -e /etc/default/postsrsd && echo present || echo absent") == "absent"
    assert fixture.sh("cat /etc/postsrsd.conf") + "\n" == render_role(
        "postsrsd.conf.j2", CFG, SECRETS, postsrsd_major=2
    )
    assert fixture.sh("stat -c '%i %s %a %U' /etc/postsrsd.secret && sha256sum /etc/postsrsd.secret") == secret_before
    assert fixture.sh("postconf -h sender_canonical_maps") == "socketmap:unix:srs:forward"
    assert fixture.sh("postconf -h recipient_canonical_maps") == (
        "socketmap:unix:srs:reverse, hash:/etc/postfix/recipient_canonical"
    )
    # No postsrsd 1.x tcp: listener is left (10001/10002 are 2711/2712 in /proc/net/tcp).
    listeners = "grep -ciE '^ *[0-9]+: [0-9A-F]+:271[12] [0-9A-F:]+ 0A ' /proc/net/tcp /proc/net/tcp6 || true"
    assert fixture.sh(listeners) == "/proc/net/tcp:0\n/proc/net/tcp6:0"

    forward = fixture.lookup("alice@external.test", "sender_canonical_maps")
    assert re.fullmatch(r"SRS0=[^=]{4}=[^=]{2}=external\.test=alice@relay\.example\.test", forward), forward
    assert fixture.lookup(forward, "recipient_canonical_maps") == "alice@external.test"
    for address in ("bob@own.example.test", "bob@fedi.own.example.test", "carol@relay.example.test"):
        assert fixture.lookup(address, "sender_canonical_maps") == ""
    # The SRS table answers NOTFOUND for the rest, so the rewrite map behind it still applies.
    assert fixture.lookup("@alias.example.test", "recipient_canonical_maps") == "@own.example.test"
    forged = "SRS0=AAAA" + forward[len("SRS0=AAAA") :]
    assert forged != forward
    assert fixture.lookup(forged, "recipient_canonical_maps") == ""

    # Through sendmail and the chrooted cleanup daemon (network-less, so it stays queued).
    sent = fixture.queued("alice@external.test", "someone@remote.example.net")
    assert sent["sender"] == forward
    bounce = fixture.queued("", forward)
    assert [entry["address"] for entry in bounce["recipients"]] == ["alice@external.test"]
    own = fixture.queued("bob@own.example.test", "someone@remote.example.net")
    assert own["sender"] == "bob@own.example.test"

    pids = fixture.pids()
    again = fixture.deploy()
    assert managed(again) == []
    assert fixture.pids() == pids
    assert fixture.lookup("alice@external.test", "sender_canonical_maps") == forward


def test_drifted_postsrsd_conf_is_restored_with_a_restart(fixture: Fixture) -> None:
    fixture.deploy()
    before = fixture.pids()
    fixture.sh("sed -i 's/^hash-minimum = 4/hash-minimum = 2/' /etc/postsrsd.conf")
    ops = fixture.deploy()
    changed = [name.split(" | ", 1)[1] for name in managed(ops)]
    assert "Install relay configuration" in changed
    assert "Restart postsrsd.service" in changed
    after = fixture.pids()
    assert after["postsrsd"] != before["postsrsd"]
    assert after["postfix"] == before["postfix"]
    assert fixture.sh("grep -c '^hash-minimum = 4$' /etc/postsrsd.conf") == "1"
