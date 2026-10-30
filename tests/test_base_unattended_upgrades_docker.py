"""``unattended_upgrades`` against real apt, unattended-upgrades and needrestart in owned Docker containers.

Skipped unless ``UNATTENDED_UPGRADES_DOCKER_CONTAINERS`` holds the full IDs
(space separated) of running fixture containers, one per supported release
(``docs/base.md``, "unattended_upgrades", describes them). Each runs systemd as
PID 1 without network, with both packages installed. The test checks what the
fake connector cannot: apt really reads the drop-in (``#clear`` replaces the
packaged origins), unattended-upgrade resolves the security-only origins for
the release's codename (on Debian also with point releases and
``<codename>-updates``), needrestart evaluates its drop-in, the packaged
``20auto-upgrades`` and ``50unattended-upgrades`` are left byte for byte, a
converged run changes nothing, and the read-only check fails when another
drop-in adds an origin. The Docker CLI is wrapped so that pyinfra can only
inspect, exec in and copy into the container.
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

from ops_deploy.base import UnattendedUpgradesConfig, deploy_unattended_upgrades
from ops_deploy.base.unattended_upgrades import APT_DROPIN, NEEDRESTART_DROPIN, render_apt_dropin
from ops_deploy.testing.harness import DeployRun, collect_ops

CONTAINERS = os.environ.get("UNATTENDED_UPGRADES_DOCKER_CONTAINERS", "").split()
pytestmark = pytest.mark.skipif(not CONTAINERS, reason="no owned unattended-upgrades Docker containers")

WRITE_APT = f"unattended-upgrades | Write {APT_DROPIN}"
WRITE_NR = f"unattended-upgrades | Write {NEEDRESTART_DROPIN}"
CHECK = "unattended-upgrades | Check the effective unattended-upgrades policy"
PACKAGED = ("/etc/apt/apt.conf.d/20auto-upgrades", "/etc/apt/apt.conf.d/50unattended-upgrades")
FOREIGN = "/etc/apt/apt.conf.d/99zz-ops-deploy-test-origin"


class Container:
    def __init__(self, identifier: str) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        assert re.fullmatch(r"[0-9a-f]{64}", identifier)
        self.identifier = identifier
        info = json.loads(self.docker("container", "inspect", identifier).stdout)[0]
        # Only the owned, isolated fixture: no network, mounts, ports or devices.
        assert info["Name"].startswith("/ops-deploy-uu-")
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "unattended-upgrades"
        assert info["HostConfig"]["NetworkMode"] == "none"
        assert info["HostConfig"]["Privileged"] is False
        assert not info["Mounts"]
        assert not info["HostConfig"]["PortBindings"]
        assert not info["HostConfig"]["Devices"]
        assert self.out("cat /proc/1/comm") == "systemd"
        self.distro, self.codename = self.out('. /etc/os-release && echo "$ID $VERSION_CODENAME"').split()

    def docker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.binary, *args], capture_output=True, text=True, check=True, timeout=120)

    def sh(self, command: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, "exec", self.identifier, "sh", "-c", command],
            capture_output=True,
            text=True,
            check=check,
            timeout=300,
        )

    def out(self, command: str) -> str:
        return self.sh(command).stdout.strip()

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

    def deploy(self, cfg: UnattendedUpgradesConfig) -> DeployRun:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        run = DeployRun()
        try:
            connect_all(state)
            assert state.activated_hosts
            add_deploy(state, deploy_unattended_upgrades, cfg)
            run_ops(state)
        except PyinfraError as exc:
            run.error = exc
        finally:
            run.ops = collect_ops(state, name)
            disconnect_all(state)
        return run

    def snapshot(self, *paths: str) -> str:
        """Owner, mode, inode, mtime and content of each path."""

        return self.out("; ".join(f"stat -c '%U:%G %a %i %Y' {p} && cat {p}" for p in paths))

    def dry_run(self) -> str:
        return self.sh("unattended-upgrade --dry-run --debug 2>&1", check=False).stdout


def mutating(run: DeployRun) -> list[str]:
    return [op.name for op in run.ops if op.changed and not op.read_only]


@pytest.fixture(params=CONTAINERS)
def container(request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Container:
    box = Container(request.param)
    box.guard_connector(tmp_path, monkeypatch)
    box.sh(f"rm -f {APT_DROPIN} {NEEDRESTART_DROPIN} {FOREIGN}")
    return box


def test_security_only_policy_converges_and_leaves_packaged_files_alone(container: Container) -> None:
    packaged = container.snapshot(*PACKAGED)
    before = container.dry_run()
    # The packaged default on Debian also takes the point-release archive.
    if container.distro == "debian":
        assert f"origin=Debian,codename={container.codename},label=Debian," in before

    cfg = UnattendedUpgradesConfig(
        package_blacklist=("^linux-image-",), needrestart_skip_services=("ops-deploy-skip-test.service",)
    )
    first = container.deploy(cfg)
    assert first.succeeded, first.error
    assert mutating(first) == [WRITE_APT, WRITE_NR]
    assert container.out(f"cat {APT_DROPIN}") + "\n" == render_apt_dropin(cfg, container.distro)
    assert container.out(f"stat -c '%U:%G %a' {APT_DROPIN} {NEEDRESTART_DROPIN}") == "root:root 644\nroot:root 644"
    assert container.snapshot(*PACKAGED) == packaged

    after = container.dry_run()
    allowed = re.search(r"^Allowed origins are: (.*)$", after, re.MULTILINE)
    assert allowed is not None, after
    if container.distro == "debian":
        assert allowed.group(1) == f"origin=Debian,codename={container.codename}-security,label=Debian-Security"
    else:
        codename = container.codename
        assert allowed.group(1) == (
            f"origin=Ubuntu,archive={codename}, origin=Ubuntu,archive={codename}-security, "
            f"origin=UbuntuESMApps,archive={codename}-apps-security, "
            f"origin=UbuntuESM,archive={codename}-infra-security"
        )
    assert re.search(r"^Initial blacklist: \^linux-image-$", after, re.MULTILINE), after
    # needrestart evaluates the drop-in after its own configuration.
    effective = container.out(
        "perl -e 'our %nrconf; do q(/etc/needrestart/needrestart.conf); "
        "print $nrconf{restart}, q( ), scalar grep({ /ops-deploy-skip-test/ } keys %{$nrconf{override_rc}}), qq(\\n)'"
    )
    assert effective == "a 1"

    # Converged: nothing is written, the files keep inode and mtime.
    files = container.snapshot(APT_DROPIN, NEEDRESTART_DROPIN)
    second = container.deploy(cfg)
    assert second.succeeded, second.error
    assert mutating(second) == []
    assert [op.name for op in second.ops if op.changed] == [CHECK]
    assert container.snapshot(APT_DROPIN, NEEDRESTART_DROPIN) == files


def test_debian_point_releases_and_stable_updates_resolve_for_the_codename(container: Container) -> None:
    if container.distro != "debian":
        pytest.skip("Debian origins only")
    cfg = UnattendedUpgradesConfig(debian_point_releases=True, debian_stable_updates=True)
    run = container.deploy(cfg)
    assert run.succeeded, run.error

    allowed = re.search(r"^Allowed origins are: (.*)$", container.dry_run(), re.MULTILINE)
    assert allowed is not None
    codename = container.codename
    assert allowed.group(1) == (
        f"origin=Debian,codename={codename}-security,label=Debian-Security, "
        f"origin=Debian,codename={codename},label=Debian, "
        f"origin=Debian,codename={codename}-updates,label=Debian"
    )
    second = container.deploy(cfg)
    assert second.succeeded, second.error
    assert mutating(second) == []
    assert container.deploy(UnattendedUpgradesConfig()).succeeded


@pytest.mark.parametrize(
    "statement",
    [
        'Unattended-Upgrade::Origins-Pattern { "origin=Example"; };',
        # A named entry: unattended-upgrade reads it like an anonymous one.
        'Unattended-Upgrade::Origins-Pattern::extra "origin=Example";',
        'Unattended-Upgrade::Allowed-Origins::extra "Example:stable";',
        'Unattended-Upgrade::Automatic-Reboot "true";',
    ],
)
def test_a_setting_changed_by_another_drop_in_fails_the_check(container: Container, statement: str) -> None:
    cfg = UnattendedUpgradesConfig()
    assert container.deploy(cfg).succeeded
    container.sh(f"printf '%s\\n' {shlex.quote(statement)} > {FOREIGN}")
    try:
        run = container.deploy(cfg)
        assert not run.succeeded
        assert mutating(run) == []
        assert not run.op(CHECK).succeeded
    finally:
        container.sh(f"rm -f {FOREIGN}")
    assert container.deploy(cfg).succeeded


def test_unmanaged_needrestart_removes_only_its_drop_in(container: Container) -> None:
    assert container.deploy(UnattendedUpgradesConfig()).succeeded

    run = container.deploy(UnattendedUpgradesConfig(needrestart="unmanaged"))

    assert run.succeeded, run.error
    assert mutating(run) == [f"unattended-upgrades | Remove {NEEDRESTART_DROPIN}"]
    assert container.sh(f"test -e {NEEDRESTART_DROPIN}", check=False).returncode == 1
    assert container.out("dpkg-query -W -f='${Status}' needrestart") == "install ok installed"
