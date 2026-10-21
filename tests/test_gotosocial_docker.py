"""``gotosocial`` against a real systemd and GoToSocial in an owned Docker fixture.

Skipped unless ``GOTOSOCIAL_DOCKER_CONTAINER`` names the full ID of a running
fixture container (see ``docs/services/gotosocial.md``, "Tests"). The fixture
has no network: the pinned release archive is baked into the image under
``/srv/gts-release`` and served on the container's loopback, and the deploy
fetches it from there (``download_base_url``), checksum-verified as always.

It checks what the fake connector cannot: the release unpacks, GoToSocial
starts behind its hardened unit and answers ``/readyz`` and WebFinger, a
converged run restarts nothing, drift restarts once, a changed domain layout
is refused before anything changes, and (with ``OPS_LIBRARY_PATH``) the role
and this deploy take turns on one instance without a restart or a change.
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

from ops_deploy.services.gotosocial import GotosocialConfig, deploy_gotosocial, render_config
from ops_deploy.testing.harness import OpResult, collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("GOTOSOCIAL_DOCKER_CONTAINER"), reason="no explicitly owned GoToSocial Docker fixture"
)

NAME = "/ops-deploy-gotosocial-20261021"
RUN_LABEL = "gotosocial-20261021"
SERVER = "http://127.0.0.1:8765"
CFG = GotosocialConfig(
    host="social.example.test",
    account_domain="example.test",
    download_base_url=SERVER,
    traefik_cert_resolver="letsencrypt",
)
CONFIG = "/etc/gotosocial/config.yaml"
MARKER = "/var/lib/gotosocial/.ops-domain-layout"


class Fixture:
    def __init__(self) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.identifier = os.environ["GOTOSOCIAL_DOCKER_CONTAINER"]
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        info = json.loads(self.docker("container", "inspect", self.identifier).stdout)[0]
        # Only the owned, isolated fixture: no network, mounts, ports or devices.
        assert info["Name"] == NAME
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "gotosocial-systemd"
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

    def docker(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.binary, *args], capture_output=True, text=True, check=check, timeout=600)

    def sh(self, command: str) -> str:
        return self.docker("exec", "-i", self.identifier, "sh", "-c", command).stdout.strip()

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

    def serve_release(self) -> None:
        """The baked-in release archive on loopback (a transient unit, started once)."""

        self.sh(
            "systemctl is-active --quiet gts-release-http || systemd-run --unit gts-release-http "
            "python3 -m http.server 8765 --bind 127.0.0.1 --directory /srv/gts-release >/dev/null"
        )
        self.sh(f"for i in $(seq 1 50); do curl -fsS -o /dev/null {SERVER}/ && exit 0; sleep 0.2; done; exit 1")

    def reset(self) -> None:
        """No GoToSocial at all: unit, user, release tree, config, data, wrapper and route removed."""

        self.sh(
            "systemctl disable --now gotosocial.service >/dev/null 2>&1 || true; "
            "systemctl reset-failed gotosocial.service >/dev/null 2>&1 || true; "
            "rm -f /etc/systemd/system/gotosocial.service /usr/local/sbin/gotosocial-admin "
            "/etc/traefik/dynamic/gotosocial.yml; systemctl daemon-reload; "
            "rm -rf /opt/gotosocial /etc/gotosocial /var/lib/gotosocial; "
            "userdel gotosocial >/dev/null 2>&1 || true; groupdel gotosocial >/dev/null 2>&1 || true"
        )

    def deploy(self, cfg: GotosocialConfig) -> list[OpResult]:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        try:
            connect_all(state)
            assert state.activated_hosts
            add_deploy(state, deploy_gotosocial, cfg)
            run_ops(state)
            ops = collect_ops(state, name)
        finally:
            disconnect_all(state)
        assert all(op.succeeded for op in ops), ops
        return ops

    def service(self) -> tuple[str, str]:
        """(InvocationID, MainPID): both change on every (re)start."""

        invocation = self.sh("systemctl show -p InvocationID --value gotosocial.service")
        pid = self.sh("systemctl show -p MainPID --value gotosocial.service")
        assert invocation
        assert pid not in ("", "0")
        return invocation, pid

    def files(self) -> str:
        """Owner, mode, inode, mtime and content of every file the deploy writes."""

        paths = f"{CONFIG} /etc/systemd/system/gotosocial.service /usr/local/sbin/gotosocial-admin {MARKER} "
        paths += "/etc/traefik/dynamic/gotosocial.yml"
        return self.sh(f"stat -c '%n %U:%G %a %i %Y' {paths} && cat {paths} && readlink /opt/gotosocial/current")

    def ansible(self, **extra: str) -> str:
        """The role from ``OPS_LIBRARY_PATH`` with Ansible inside the container, on the same inputs."""

        role = Path(os.environ["OPS_LIBRARY_PATH"], "roles", "gotosocial_deploy")
        assert role.is_dir()
        base = "/opt/gotosocial-role"
        self.sh(f"rm -rf {base} && mkdir -p {base}/roles")
        self.docker("cp", str(role), f"{self.identifier}:{base}/roles/gotosocial_deploy")
        variables = {
            "gotosocial_host": CFG.host,
            "gotosocial_account_domain": CFG.account_domain,
            "gotosocial_download_base_url": SERVER,
            "gotosocial_traefik_cert_resolver": CFG.traefik_cert_resolver,
            **extra,
        }
        play = "- hosts: localhost\n  roles:\n    - role: gotosocial_deploy\n      vars:\n"
        play += "".join(f"        {key}: {json.dumps(value)}\n" for key, value in variables.items())
        self.sh(f"printf %s {shlex.quote(play)} > {base}/play.yml")
        # The image's apt lists are current; without a network the role's hour-old refresh must not run.
        self.sh("mkdir -p /var/lib/apt/periodic && touch /var/lib/apt/periodic/update-success-stamp")
        result = self.docker(
            "exec",
            "-i",
            self.identifier,
            "sh",
            "-c",
            f"cd {base} && ANSIBLE_ROLES_PATH=roles ansible-playbook -c local -i localhost, play.yml",
            check=False,
        )
        assert result.returncode == 0, result.stdout[-4000:]
        return result.stdout


def mutating(ops: list[OpResult]) -> list[str]:
    return [op.name for op in ops if op.changed and not op.read_only]


def short(names: list[str]) -> list[str]:
    return [name.removeprefix("Deploy GoToSocial | ") for name in names]


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fixture:
    host = Fixture()
    host.guard_connector(tmp_path, monkeypatch)
    host.serve_release()
    host.reset()
    return host


def test_fresh_install_runs_and_a_second_run_changes_nothing(fixture: Fixture) -> None:
    first = fixture.deploy(CFG)

    assert "Install GoToSocial 0.22.2" in short(mutating(first))
    assert "Start gotosocial.service" in short(mutating(first))
    assert "Restart gotosocial.service" not in short(mutating(first))
    assert fixture.sh("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:10070/readyz") == "200"
    assert fixture.sh(f"cat {MARKER}") == "social.example.test example.test"
    assert fixture.sh("readlink /opt/gotosocial/current") == "/opt/gotosocial/releases/0.22.2"
    modes = fixture.sh(
        f"stat -c '%n %U:%G %a' /opt/gotosocial/releases/0.22.2 /opt/gotosocial/releases/0.22.2/gotosocial "
        f"/etc/gotosocial {CONFIG} /var/lib/gotosocial /var/lib/gotosocial/storage /var/lib/gotosocial/.cache "
        f"/usr/local/sbin/gotosocial-admin {MARKER} /etc/traefik/dynamic/gotosocial.yml"
    )
    assert modes.splitlines() == [
        "/opt/gotosocial/releases/0.22.2 root:root 755",
        "/opt/gotosocial/releases/0.22.2/gotosocial root:root 755",
        "/etc/gotosocial root:gotosocial 750",
        f"{CONFIG} root:gotosocial 640",
        "/var/lib/gotosocial gotosocial:gotosocial 700",
        "/var/lib/gotosocial/storage gotosocial:gotosocial 700",
        "/var/lib/gotosocial/.cache gotosocial:gotosocial 700",
        "/usr/local/sbin/gotosocial-admin root:root 750",
        f"{MARKER} root:root 644",
        "/etc/traefik/dynamic/gotosocial.yml root:root 644",
    ]
    assert fixture.sh("getent passwd gotosocial | cut -d: -f6,7") == "/var/lib/gotosocial:/usr/sbin/nologin"
    # Only loopback listens.
    listeners = fixture.sh("ss -ltnH | awk '{print $4}' | grep -E ':10070$'").splitlines()
    assert listeners
    assert all(re.fullmatch(r"(127\.0\.0\.1|\[::1\]):10070", item) for item in listeners)
    # No staging leftovers next to the release.
    assert fixture.sh("ls -A /opt/gotosocial/releases") == "0.22.2"

    # The admin wrapper creates an account the account domain resolves.
    fixture.sh(
        "gotosocial-admin account create --username docker --email docker@example.test "
        "--password 'Docker-Fixture-Only-0001!' >/dev/null 2>&1"
    )
    webfinger = fixture.sh(
        "curl -s -H 'Host: social.example.test' -H 'X-Forwarded-Proto: https' "
        "'http://127.0.0.1:10070/.well-known/webfinger?resource=acct:docker@example.test'"
    )
    assert json.loads(webfinger)["subject"] == "acct:docker@example.test"

    running = fixture.service()
    snapshot = fixture.files()
    second = fixture.deploy(CFG)
    assert mutating(second) == []
    assert short([op.name for op in second if op.changed]) == ["Wait for GoToSocial readiness"]
    assert fixture.service() == running
    assert fixture.files() == snapshot


def test_changed_layout_is_refused_and_nothing_changes(fixture: Fixture) -> None:
    fixture.deploy(CFG)
    running = fixture.service()
    snapshot = fixture.files()

    moved = CFG.model_copy(update={"account_domain": "social.example.test"})
    with pytest.raises(PyinfraError, match="cannot change its domain layout"):
        fixture.deploy(moved)
    assert fixture.service() == running
    assert fixture.files() == snapshot


def test_drift_and_a_lost_restart_restart_once(fixture: Fixture) -> None:
    fixture.deploy(CFG)
    running = fixture.service()

    fixture.sh(f"printf '# drift\\n' >> {CONFIG}")
    assert short(mutating(fixture.deploy(CFG))) == [f"Write {CONFIG}", "Restart gotosocial.service"]
    restarted = fixture.service()
    assert restarted != running
    assert fixture.sh(f"cat {CONFIG}") + "\n" == render_config(CFG).reveal().decode()

    # A run that wrote the file and died before restarting: the file is newer than the
    # process, here within the same second as its start.
    fixture.sh(f"touch {CONFIG}")
    assert short(mutating(fixture.deploy(CFG))) == ["Restart gotosocial.service"]
    made_up = fixture.service()
    assert made_up != restarted
    assert mutating(fixture.deploy(CFG)) == []
    assert fixture.service() == made_up


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_role_and_deploy_take_turns_without_a_change(fixture: Fixture) -> None:
    recap = fixture.ansible()
    assert re.search(r"localhost\s+: ok=\d+\s+changed=[1-9]\d*\s+unreachable=0\s+failed=0", recap), recap
    by_role = fixture.service()
    snapshot = fixture.files()

    # pyinfra over the role: nothing to do, the same process keeps running.
    assert mutating(fixture.deploy(CFG)) == []
    assert fixture.service() == by_role
    assert fixture.files() == snapshot

    # The role over pyinfra: no restart and the same files.
    fixture.ansible()
    assert fixture.service() == by_role
    assert fixture.files() == snapshot

    # The role refuses the changed layout the deploy recorded and kept.
    with pytest.raises(AssertionError):
        fixture.ansible(gotosocial_account_domain="social.example.test")
    assert fixture.service() == by_role
