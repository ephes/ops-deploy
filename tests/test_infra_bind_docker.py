"""``bind`` against a real named, named-checkconf and named-checkzone in an owned Docker fixture.

Skipped unless ``BIND_DOCKER_CONTAINER`` names the full ID of a running
fixture container (see ``docs/bind.md``, "Tests"). The container has no
network; named answers on its loopback. It checks what the fake connector
cannot: a first run validates, installs and reloads, a converged run changes
nothing and does not reload, an RFC 2136 update (with ``rndc sync`` writing
the zone file) leaves the dynamic zone, its journal and its serial untouched
by later runs, a configuration named-checkconf rejects is rolled back without
a reload, an unbumped serial and a lone journal are refused, a secondary
validates, and (with ``OPS_LIBRARY_PATH``) the role and this deploy take turns
without a change or a reload.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.operations import run_ops
from pyinfra.connectors.docker import DockerConnector

from ops_deploy.infra.bind import BindConfig, deploy_bind, render_keys, render_local, render_options
from ops_deploy.testing.harness import OpResult, collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("BIND_DOCKER_CONTAINER"), reason="no explicitly owned BIND Docker fixture"
)

NAME = "/ops-deploy-bind-20261021"
RUN_LABEL = "bind-20261021"
P = "BIND authoritative | "
INSTALL = P + "Install the BIND configuration (validated, restored on failure)"
RELOAD = P + "Reload named"
SECRETS = {"xfer": SecretStr("Zml4dHVyZS14ZmVyLWtleS0wMQ=="), "acme": SecretStr("Zml4dHVyZS1hY21lLWtleS0wMg==")}
DYNAMIC = "/var/lib/bind/db.home.example.test"
STATIC = "/etc/bind/db.example.test"
MANAGED = (
    "/etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local /etc/bind/named.conf.keys "
    f"{STATIC} /etc/bind/db.192.0.2"
)
ZONE = """$TTL 300
@ IN SOA ns1.example.test. hostmaster.example.test. ( {serial} 3600 600 604800 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.{last}
"""
SEED = """$ORIGIN home.example.test.
$TTL 300
@ IN SOA ns1.example.test. hostmaster.example.test. ( 2026102101 3600 600 604800 60 )
@ IN NS ns1.example.test.
@ IN A 192.0.2.10
"""
REVERSE = """$TTL 300
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 604800 60 )
@ IN NS ns1.example.test.
1 IN PTR ns1.example.test.
"""
TRANSFER_ACL = ("!{ !{ 192.0.2.2; }; any; }", 'key "xfer"')
NOTIFY = 'also-notify { 192.0.2.2 key "xfer"; };'


def primary(zones_dir: Path, **changes: Any) -> BindConfig:
    base: dict[str, Any] = {
        "zone_files_dir": str(zones_dir),
        "verify_delay": 1,
        "tsig_keys": [{"name": "xfer"}, {"name": "acme"}],
        "zones": [
            {
                "name": "example.test",
                "file": "db.example.test",
                "type": "master",
                "allow_transfer": TRANSFER_ACL,
                "extra_config": (NOTIFY,),
            },
            {
                "name": "home.example.test",
                "file": "db.home.example.test",
                "type": "master",
                "dynamic": True,
                "update_policy": ('grant "acme" name _acme-challenge.home.example.test. TXT',),
                "allow_transfer": TRANSFER_ACL,
                "extra_config": (NOTIFY,),
            },
            {"name": "2.0.192.in-addr.arpa", "file": "db.192.0.2", "type": "master"},
        ],
    }
    return BindConfig.model_validate({**base, **changes})


class Fixture:
    def __init__(self) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.identifier = os.environ["BIND_DOCKER_CONTAINER"]
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        info = json.loads(self.docker("container", "inspect", self.identifier).stdout)[0]
        # Only the owned, isolated fixture: no network, mounts, ports or devices.
        assert info["Name"] == NAME
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "bind-systemd"
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
        assert self.sh("named -v").startswith("BIND 9.")

    def docker(self, *args: str, check: bool = True, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, *args], input=stdin, capture_output=True, text=True, check=check, timeout=600
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
        """The package's own configuration, no zone data, named running on it."""

        self.sh(
            "rm -rf /etc/bind && cp -a /opt/bind-pristine /etc/bind && chmod 2755 /etc/bind "
            "&& chown root:bind /var/lib/bind /var/cache/bind && chmod 0775 /var/lib/bind /var/cache/bind "
            "&& rm -rf /var/lib/bind/* /var/cache/bind/db.* /root/moved "
            "&& systemctl restart named && systemctl is-active --quiet named"
        )

    def _state(self) -> tuple[State, str]:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        connect_all(state)
        assert state.activated_hosts
        return state, name

    def deploy(self, cfg: BindConfig, secrets: dict[str, SecretStr] | None = None) -> list[OpResult]:
        state, name = self._state()
        try:
            add_deploy(state, deploy_bind, cfg, SECRETS if secrets is None else secrets)
            run_ops(state)
            ops = collect_ops(state, name)
        finally:
            disconnect_all(state)
        assert all(op.succeeded for op in ops), ops
        return ops

    def read(self, path: str) -> str:
        return self.docker("exec", self.identifier, "cat", path).stdout

    def configured(self) -> str:
        """named's "last configured" time from rndc: it changes on every reload."""

        status = self.sh("rndc status")
        match = re.search(r"last configured: (.+)", status)
        assert match, status
        return match.group(1)

    def files(self, paths: str = MANAGED) -> str:
        return self.sh(f"stat -c '%n %U:%G %a %i %Y %s' {paths} && sha256sum {paths}")

    def soa(self, zone: str) -> str:
        return self.sh(f"dig @127.0.0.1 {zone} SOA +short +norecurse")

    def flags(self, zone: str) -> str:
        return self.sh(f"dig @127.0.0.1 {zone} SOA +norecurse | grep -E '^;; (flags|->>HEADER)'")

    def nsupdate(self, token: str) -> None:
        secret = SECRETS["acme"].get_secret_value()
        script = (
            "server 127.0.0.1\nzone home.example.test\n"
            f'update add _acme-challenge.home.example.test. 60 TXT "{token}"\nsend\n'
        )
        self.sh(f"nsupdate -y hmac-sha256:acme:{secret}", stdin=script)

    def ansible(self, cfg: BindConfig, zones_dir: Path) -> str:
        """The role from ``OPS_LIBRARY_PATH`` with Ansible inside the container, on the same inputs."""

        role = Path(os.environ["OPS_LIBRARY_PATH"], "roles", "bind_authoritative_deploy")
        assert role.is_dir()
        base = "/opt/bind-role"
        self.sh(f"rm -rf {base} && mkdir -p {base}/roles {base}/files")
        self.docker("cp", str(role), f"{self.identifier}:{base}/roles/bind_authoritative_deploy")
        self.docker("cp", f"{zones_dir}/.", f"{self.identifier}:{base}/files/bind")
        zones = [
            {key: list(value) if isinstance(value, tuple) else value for key, value in zone.items()}
            for zone in cfg.model_dump(exclude_none=True)["zones"]
        ]
        variables = {
            # Installed in the image; without a network the role's apt refresh cannot run.
            "bind_packages": [],
            "bind_zone_files_dir": f"{base}/files/bind",
            "bind_zones": zones,
            "bind_tsig_keys": [
                {"name": key.name, "algorithm": key.algorithm, "secret": SECRETS[key.name].get_secret_value()}
                for key in cfg.tsig_keys
            ],
            "bind_verify_delay": 1,
        }
        self.sh(f"cat > {base}/vars.json", stdin=json.dumps(variables))
        play = "- hosts: localhost\n  roles:\n    - role: bind_authoritative_deploy\n"
        self.sh(f"cat > {base}/play.yml", stdin=play)
        result = self.docker(
            "exec",
            "-i",
            self.identifier,
            "sh",
            "-c",
            f"cd {base} && ANSIBLE_ROLES_PATH=roles ansible-playbook -c local -i localhost, play.yml -e @vars.json",
            check=False,
        )
        assert result.returncode == 0, result.stdout[-4000:]
        return result.stdout


def mutating(ops: list[OpResult]) -> list[str]:
    return [op.name for op in ops if op.changed and not op.read_only]


@pytest.fixture
def zones_dir(tmp_path: Path) -> Path:
    path = tmp_path / "zones"
    path.mkdir()
    (path / "db.example.test").write_text(ZONE.format(serial=2026102101, last=80))
    (path / "db.home.example.test").write_text(SEED)
    (path / "db.192.0.2").write_text(REVERSE)
    return path


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fixture:
    host = Fixture()
    host.guard_connector(tmp_path, monkeypatch)
    host.reset()
    return host


def test_first_run_validates_installs_and_reloads_then_nothing_changes(fixture: Fixture, zones_dir: Path) -> None:
    cfg = primary(zones_dir)

    first = fixture.deploy(cfg)

    assert mutating(first) == [
        P + "Ensure /etc/bind",
        P + "Clear special mode bits on /etc/bind",
        P + "Ensure /var/lib/bind",
        INSTALL,
        RELOAD,
    ]
    assert fixture.sh("stat -c '%n %U:%G %a' /etc/bind /var/lib/bind " + MANAGED + f" {DYNAMIC}").splitlines() == [
        "/etc/bind root:bind 755",
        "/var/lib/bind bind:bind 775",
        "/etc/bind/named.conf root:bind 644",
        "/etc/bind/named.conf.options root:bind 644",
        "/etc/bind/named.conf.local root:bind 644",
        "/etc/bind/named.conf.keys root:bind 640",
        f"{STATIC} root:bind 644",
        "/etc/bind/db.192.0.2 root:bind 644",
        f"{DYNAMIC} bind:bind 644",
    ]
    assert fixture.read("/etc/bind/named.conf.options") == render_options(cfg)
    assert fixture.read("/etc/bind/named.conf.local") == render_local(cfg)
    assert fixture.read("/etc/bind/named.conf.keys") == render_keys(cfg, SECRETS).reveal().decode()
    assert fixture.sh("cat /etc/bind/named.conf").endswith('include "/etc/bind/named.conf.default-zones";')
    for zone in ("example.test", "home.example.test", "2.0.192.in-addr.arpa"):
        assert " aa" in fixture.flags(zone), zone
        assert "status: NOERROR" in fixture.flags(zone), zone
    assert not fixture.sh("ls -A /etc/bind | grep ops-deploy-bind || true")

    configured = fixture.configured()
    snapshot = fixture.files(f"{MANAGED} {DYNAMIC}")
    second = fixture.deploy(cfg)
    assert mutating(second) == []
    assert fixture.files(f"{MANAGED} {DYNAMIC}") == snapshot
    assert fixture.configured() == configured


def test_dynamic_updates_and_their_journal_survive_every_later_run(fixture: Fixture, zones_dir: Path) -> None:
    cfg = primary(zones_dir)
    fixture.deploy(cfg)
    fixture.nsupdate("token-1")
    # named writes the zone file back, as it does every 15 minutes; the journal stays.
    fixture.sh("rndc sync home.example.test")
    assert fixture.sh(f"test -s {DYNAMIC}.jnl && echo yes") == "yes"
    serial = fixture.soa("home.example.test").split()[2]
    assert int(serial) > 2026102101
    assert fixture.sh(f"grep -c _acme-challenge {DYNAMIC}") == "1"
    dynamic = fixture.files(f"{DYNAMIC} {DYNAMIC}.jnl")
    configured = fixture.configured()

    # A converged run, also with a changed seed on the controller: nothing to do.
    (zones_dir / "db.home.example.test").write_text(SEED.replace("192.0.2.10", "192.0.2.99"))
    assert mutating(fixture.deploy(cfg)) == []
    assert fixture.files(f"{DYNAMIC} {DYNAMIC}.jnl") == dynamic
    assert fixture.configured() == configured

    # A static change reloads named; the dynamic zone keeps its records, journal and serial.
    (zones_dir / "db.example.test").write_text(ZONE.format(serial=2026102102, last=81))
    assert mutating(fixture.deploy(cfg)) == [INSTALL, RELOAD]
    assert fixture.configured() != configured
    assert fixture.soa("example.test").split()[2] == "2026102102"
    assert fixture.files(f"{DYNAMIC} {DYNAMIC}.jnl") == dynamic
    assert fixture.soa("home.example.test").split()[2] == serial
    assert fixture.sh("dig @127.0.0.1 _acme-challenge.home.example.test TXT +short") == '"token-1"'

    # Further updates keep working after the reload.
    fixture.nsupdate("token-2")
    assert int(fixture.soa("home.example.test").split()[2]) > int(serial)


def test_a_configuration_named_rejects_is_rolled_back_without_a_reload(fixture: Fixture, zones_dir: Path) -> None:
    cfg = primary(zones_dir)
    fixture.deploy(cfg)
    snapshot = fixture.files()
    configured = fixture.configured()

    broken = primary(zones_dir, extra_options=("not-a-bind-option yes;",))
    with pytest.raises((AssertionError, PyinfraError)):
        fixture.deploy(broken)

    assert fixture.files() == snapshot
    assert fixture.configured() == configured
    assert not fixture.sh("ls -A /etc/bind /var/lib/bind | grep ops-deploy-bind || true")
    assert " aa" in fixture.flags("example.test")
    assert mutating(fixture.deploy(cfg)) == []


def test_an_unbumped_serial_is_refused_and_nothing_changes(fixture: Fixture, zones_dir: Path) -> None:
    cfg = primary(zones_dir)
    fixture.deploy(cfg)
    snapshot = fixture.files()
    configured = fixture.configured()
    (zones_dir / "db.example.test").write_text(ZONE.format(serial=2026102101, last=82))

    with pytest.raises((AssertionError, PyinfraError)):
        fixture.deploy(cfg)

    assert fixture.files() == snapshot
    assert fixture.configured() == configured


def test_a_journal_without_its_zone_file_is_refused_while_planning(fixture: Fixture, zones_dir: Path) -> None:
    cfg = primary(zones_dir)
    fixture.deploy(cfg)
    fixture.nsupdate("token-3")
    fixture.sh(f"mkdir -p /root/moved && mv {DYNAMIC} /root/moved/")
    snapshot = fixture.files()

    with pytest.raises(PyinfraError, match="refusing to seed the dynamic zone"):
        fixture.deploy(cfg)

    assert fixture.files() == snapshot
    assert fixture.sh(f"test -e {DYNAMIC} || echo absent") == "absent"
    fixture.sh(f"mv /root/moved/db.home.example.test {DYNAMIC}")


def test_a_secondary_validates_and_converges(fixture: Fixture, zones_dir: Path) -> None:
    cfg = BindConfig(
        zone_files_dir=str(zones_dir),
        recursion=False,
        verify_enabled=False,
        tsig_keys=[{"name": "xfer"}],
        zones=[
            {
                "name": "example.test",
                "file": "db.example.test",
                "type": "secondary",
                "primaries": ('192.0.2.1 key "xfer"',),
            },
            {
                "name": "home.example.test",
                "file": "db.home.example.test",
                "type": "secondary",
                "primaries": "192.0.2.1",
            },
        ],
    )
    secrets = {"xfer": SECRETS["xfer"]}

    first = fixture.deploy(cfg, secrets)

    assert INSTALL in mutating(first)
    assert RELOAD in mutating(first)
    assert P + "Ensure /var/cache/bind" in mutating(first)
    assert fixture.sh("stat -c '%U:%G %a' /var/cache/bind") == "bind:bind 775"
    assert "allow-recursion { none; };" in fixture.sh("cat /etc/bind/named.conf.options")
    assert fixture.sh("named-checkconf /etc/bind/named.conf && echo ok") == "ok"
    assert mutating(fixture.deploy(cfg, secrets)) == []


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_role_and_deploy_take_turns_without_a_change(fixture: Fixture, zones_dir: Path) -> None:
    cfg = primary(zones_dir)
    recap = fixture.ansible(cfg, zones_dir)
    assert re.search(r"localhost\s+: ok=\d+\s+changed=[1-9]\d*\s+unreachable=0\s+failed=0", recap), recap
    fixture.nsupdate("token-4")
    configured = fixture.configured()
    snapshot = fixture.files(f"{MANAGED} {DYNAMIC} {DYNAMIC}.jnl")

    # pyinfra over the role: nothing to do, no reload.
    assert mutating(fixture.deploy(cfg)) == []
    assert fixture.files(f"{MANAGED} {DYNAMIC} {DYNAMIC}.jnl") == snapshot
    assert fixture.configured() == configured

    # The role over pyinfra: nothing changed either.
    recap = fixture.ansible(cfg, zones_dir)
    assert re.search(r"localhost\s+: ok=\d+\s+changed=0\s+unreachable=0\s+failed=0", recap), recap
    assert fixture.files(f"{MANAGED} {DYNAMIC} {DYNAMIC}.jnl") == snapshot
    assert fixture.configured() == configured
