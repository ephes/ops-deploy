"""Operations API backup, restore and remove against a real systemd host in an owned Docker container.

Skipped unless ``DAYBOOK_OPERATIONS_API_LIFECYCLE_DOCKER_IMAGE`` names an image
built from ``tests/integration/daybook_operations_api_lifecycle/Dockerfile``
(Debian 12, systemd as PID 1). Each test starts its own container, named
``ops-deploy-daybook-ops-lifecycle-<random>`` and labelled
``ops-deploy.fixture=daybook-operations-api-lifecycle``, without network, and
removes it at the end. The Docker CLI is wrapped so that pyinfra can only
inspect, exec into and copy into that container.

Daybook's lifecycle tool is private; ``fake_lifecycle.py`` stands in for it
with the same command line and the same unit and ownership checks, so this
exercises the deploys' side: the account the tool runs as, the order of the
unit changes, what removal leaves behind and that repeats change nothing.
"""

from __future__ import annotations

import os
import re
import secrets
import shlex
import shutil
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.operations import run_ops
from pyinfra.connectors.docker import DockerConnector

from ops_deploy.services.daybook_operations_api import (
    OperationsApiBackupConfig,
    OperationsApiRemoveConfig,
    OperationsApiRestoreConfig,
    deploy_daybook_operations_api_backup,
    deploy_daybook_operations_api_remove,
    deploy_daybook_operations_api_restore,
)
from ops_deploy.testing.harness import DeployRun, collect_ops

IMAGE = os.environ.get("DAYBOOK_OPERATIONS_API_LIFECYCLE_DOCKER_IMAGE", "")
pytestmark = pytest.mark.skipif(not IMAGE, reason="DAYBOOK_OPERATIONS_API_LIFECYCLE_DOCKER_IMAGE not set")

FIXTURE = Path(__file__).parent / "integration" / "daybook_operations_api_lifecycle"
USER = "daybook-operations"
ROOT = "/opt/backups/daybook_operations"
UNITS = ("daybook-operations", "daybook-operations-reconcile")
ROUTE = "/etc/traefik/dynamic/daybook-operations.yml"
SETUP = f"""set -eu
groupadd --system {USER}
useradd --system --gid {USER} --home-dir /home/{USER} --create-home --shell /usr/sbin/nologin {USER}
install -d -o {USER} -g {USER} -m 0750 /home/{USER}/site/services/operations_api /etc/daybook-operations
install -d -m 0755 /home/{USER}/venv/bin /etc/traefik/dynamic /opt/backups
ln -s /usr/bin/python3 /home/{USER}/venv/bin/python
install -o {USER} -g {USER} -m 0644 /fixture/fake_lifecycle.py /home/{USER}/site/services/operations_api/lifecycle.py
printf '%s' '{{"backup_root": "{ROOT}", "profiles": "/etc/daybook-operations/profiles.json"}}' \
  > /etc/daybook-operations/lifecycle.json
echo '[]' > /etc/daybook-operations/profiles.json
chown {USER}:{USER} /etc/daybook-operations/lifecycle.json /etc/daybook-operations/profiles.json
chmod 0600 /etc/daybook-operations/lifecycle.json /etc/daybook-operations/profiles.json
for unit in {" ".join(UNITS)}; do
  printf '[Unit]\\nDescription=%s\\n[Service]\\nUser={USER}\\nExecStart=/bin/sleep infinity\\n' "$unit" \
    > /etc/systemd/system/$unit.service
  printf '[Install]\\nWantedBy=multi-user.target\\n' >> /etc/systemd/system/$unit.service
done
echo 'http: {{}}' > {ROUTE}
systemctl daemon-reload
systemctl enable --now {" ".join(UNITS)}
"""


class Box:
    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.name = f"ops-deploy-daybook-ops-lifecycle-{secrets.token_hex(4)}"
        self.identifier = self.docker(
            "run", "-d", "--name", self.name, "--label", "ops-deploy.fixture=daybook-operations-api-lifecycle",
            "--network", "none", "--cgroupns", "private", "--cap-add", "SYS_ADMIN",
            "--security-opt", "apparmor=unconfined", "--tmpfs", "/run", "--tmpfs", "/run/lock",
            "--tmpfs", "/opt/backups",
            "-v", f"{FIXTURE}:/fixture:ro", IMAGE,
        ).stdout.strip()  # fmt: skip
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        for _ in range(60):
            if self.sh("systemctl is-system-running", check=False).stdout.strip() in {"running", "degraded"}:
                break
            time.sleep(1)
        else:
            raise AssertionError("systemd did not start in the fixture")
        self.sh(SETUP)
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

    def sh(self, command: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, "exec", self.identifier, "bash", "-c", command],
            capture_output=True,
            text=True,
            check=check,
            timeout=300,
        )

    def out(self, command: str) -> str:
        return self.sh(command).stdout.strip()

    def remove(self) -> None:
        subprocess.run([self.binary, "rm", "-f", self.identifier], capture_output=True, check=False, timeout=120)

    def deploy(self, function: Callable[..., Any], cfg: Any) -> DeployRun:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        run = DeployRun()
        try:
            connect_all(state)
            assert state.activated_hosts
            add_deploy(state, function, cfg)
            run_ops(state)
        except PyinfraError as exc:
            run.error = exc
        finally:
            run.ops = collect_ops(state, name)
            disconnect_all(state)
        return run

    def unit(self, unit: str) -> tuple[str, str]:
        active = self.sh(f"systemctl is-active {unit}", check=False).stdout.strip()
        enabled = self.sh(f"systemctl is-enabled {unit}", check=False).stdout.strip()
        return active, enabled

    def archives(self) -> list[str]:
        return self.out(f"find {ROOT} -maxdepth 1 -name '*.tar' ! -name 'before-restore-*' | sort").split()


@pytest.fixture
def box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Box]:
    fixture = Box(tmp_path, monkeypatch)
    try:
        yield fixture
    finally:
        fixture.remove()


def test_backup_restore_remove_on_a_systemd_host(box: Box) -> None:
    for _ in range(2):
        run = box.deploy(deploy_daybook_operations_api_backup, OperationsApiBackupConfig(required_mount="/opt/backups"))
        assert run.succeeded, run.error
    archives = box.archives()
    assert len(archives) == 2
    assert box.out(f"stat -c '%U:%G %a' {ROOT}") == f"{USER}:{USER} 700"
    for archive in archives:
        assert box.out(f"stat -c '%U %a' {archive}") == f"{USER} 600"
    assert all(box.unit(unit) == ("active", "enabled") for unit in UNITS)

    archive = archives[0]
    box.sh("""echo '["changed"]' > /etc/daybook-operations/profiles.json""")
    refused = box.deploy(deploy_daybook_operations_api_restore, OperationsApiRestoreConfig(archive=archive))
    assert not refused.succeeded
    validate = OperationsApiRestoreConfig(archive=archive, confirmed=True, clients_quiesced=True, validate_only=True)
    run = box.deploy(deploy_daybook_operations_api_restore, validate)
    assert run.succeeded, run.error
    assert all(box.unit(unit) == ("active", "enabled") for unit in UNITS)

    restore = OperationsApiRestoreConfig(archive=archive, confirmed=True, clients_quiesced=True)
    for _ in range(2):
        run = box.deploy(deploy_daybook_operations_api_restore, restore)
        assert run.succeeded, run.error
        assert box.out("cat /etc/daybook-operations/profiles.json") == "[]"
        assert all(box.unit(unit) == ("inactive", "disabled") for unit in UNITS)
    # The repeat finds both units stopped and disabled and changes no unit.
    assert not [name for name in run.changed_ops if "before the unprivileged restore" in name]
    calls = box.out(f"cat {ROOT}/calls.log").splitlines()
    assert {line.split()[0] for line in calls} == {USER}
    actions = [line.split()[1] for line in calls]
    assert actions == ["backup", "backup", "validate", "validate", "restore", "validate", "restore"]

    remove = OperationsApiRemoveConfig(confirmed=True, clients_quiesced=True)
    box.sh(f"systemctl enable --now {' '.join(UNITS)}")
    run = box.deploy(deploy_daybook_operations_api_remove, remove)
    assert run.succeeded, run.error
    for unit in UNITS:
        assert box.sh(f"test -e /etc/systemd/system/{unit}.service", check=False).returncode == 1
        assert box.unit(unit)[0] in {"inactive", "unknown"}
    assert box.sh(f"test -e {ROUTE}", check=False).returncode == 1
    for kept in (f"/home/{USER}/site", "/etc/daybook-operations/lifecycle.json", *archives):
        assert box.sh(f"test -e {kept}").returncode == 0
    assert box.out(f"id -un {USER}") == USER

    again = box.deploy(deploy_daybook_operations_api_remove, remove)
    assert again.succeeded, again.error
    assert again.changed_ops == []
