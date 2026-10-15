"""Deploy recorder to the smoke target twice: real build and end state, then a converged rerun.

Needs a recorder checkout (the podcast repo's ``apps/recorder``), Go and npm:
``RECORDER_SOURCE``, else ``$PROJECTS_ROOT/podcast/apps/recorder``. Its
committed ``HEAD`` is exported, so local builds and uncommitted files never
reach the VM. The binary is built for the VM's architecture.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.recorder import RecorderConfig, deploy_recorder
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "recorder.example.invalid"
DATA = "/var/lib/recorder"


def recorder_checkout() -> Path | None:
    configured = os.environ.get("RECORDER_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "podcast" / "apps" / "recorder" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: RecorderConfig
    secrets: SecretValues
    first: SshRun
    second: SshRun
    upgrade: SshRun
    pids: tuple[str, str]


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = recorder_checkout()
    if checkout is None or not (checkout / "cmd" / "recorderd").exists():
        pytest.skip("no recorder checkout (set RECORDER_SOURCE or PROJECTS_ROOT)")
    if not (shutil.which("go") and shutil.which("npm")):
        pytest.skip("recorder smoke needs go and npm on the controller")
    source = tmp_path_factory.mktemp("recorder")
    archive = subprocess.run(
        ["git", "-C", str(checkout), "archive", "HEAD", "."], check=True, capture_output=True
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive, check=True)
    arch = smoke_host.out("dpkg --print-architecture")
    ref = SecretRef("secrets/smoke/recorder.yml")
    cfg = RecorderConfig(
        source_path=source,
        artifact_path=tmp_path_factory.mktemp("build") / "recorderd",
        goarch="arm64" if arch == "arm64" else "amd64",
        secrets=ref,
        public_url=f"https://{HOST}",
        traefik_host=HOST,
    )
    values = SecretValues(
        ref,
        {
            "session_secret": f"smoke-session-{secrets.token_hex(24)}",
            "admin_emails": "admin@example.invalid",
        },
    )
    # Start from nothing (the coexistence smoke may have left recorder deployed).
    smoke_host.run(
        "systemctl disable --now recorder 2>/dev/null; rm -rf /etc/systemd/system/recorder.service "
        f"/opt/recorder /etc/recorder {DATA} /etc/traefik/dynamic/recorder.yml; "
        "userdel recorder 2>/dev/null; groupdel recorder 2>/dev/null; systemctl daemon-reload; true"
    )
    runs = []
    pids: list[str] = []
    for label in ("first", "second", "upgrade"):
        if label == "upgrade":
            # A file in web/dist is embedded (``all:dist``): a new binary
            # replaces the one recorder is running from.
            (source / "web" / "dist").mkdir(parents=True, exist_ok=True)
            (source / "web" / "dist" / "smoke-upgrade.txt").write_text("upgrade\n")
            pids.append(smoke_host.out("systemctl show -p MainPID --value recorder"))
        run = run_deploy_ssh(deploy_recorder, cfg, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"recorder {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    pids.append(smoke_host.out("systemctl show -p MainPID --value recorder"))
    first, second, upgrade = runs
    return Deployed(cfg, values, first, second, upgrade, pids=(pids[0], pids[1]))


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert "Deploy recorder | Install recorder binary" in deployed.first.changed_ops
    # The binary is rebuilt on every run; an unchanged source builds the same bytes.
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_new_binary_replaces_the_running_one(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert sorted(deployed.upgrade.mutating_changed_ops) == [
        "Deploy recorder | Install recorder binary",
        "Deploy recorder | Restart recorder.service",
    ]
    before, after = deployed.pids
    assert before != after
    assert smoke_host.out("curl -fsS http://127.0.0.1:10015/smoke-upgrade.txt") == "upgrade"
    assert smoke_host.out("ls /opt/recorder") == "recorderd"


def test_service_runs_and_is_healthy(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active recorder") == "active"
    assert smoke_host.out("systemctl is-enabled recorder") == "enabled"
    assert '"status":"ok"' in smoke_host.out("curl -fsS http://127.0.0.1:10015/health").replace(" ", "")


def test_traefik_serves_the_app(smoke_host: SmokeHost, deployed: Deployed) -> None:
    curl = f"curl -ks --resolve {HOST}:443:127.0.0.1 https://{HOST}"
    body = ""
    for _ in range(15):
        body = smoke_host.run(f"{curl}/", check=False).stdout
        if "<recorder-app" in body:
            break
        smoke_host.run("sleep 1")
    assert "<recorder-app" in body
    assert '"accounts":true' in smoke_host.out(f"{curl}/api/auth/config").replace(" ", "")


def test_files_have_the_roles_owners_and_modes(smoke_host: SmokeHost, deployed: Deployed) -> None:
    listing = smoke_host.out(
        f"stat -c '%a %U %G %n' /opt/recorder /opt/recorder/recorderd /etc/recorder /etc/recorder/recorder.env {DATA}"
    ).splitlines()
    assert listing == [
        "755 root root /opt/recorder",
        "755 root root /opt/recorder/recorderd",
        "750 root recorder /etc/recorder",
        "640 root recorder /etc/recorder/recorder.env",
        f"750 recorder recorder {DATA}",
    ]
    assert smoke_host.out("getent passwd recorder | cut -d: -f6,7") == f"{DATA}:/usr/sbin/nologin"
    assert smoke_host.out(f"test -s {DATA}/recorder.db && echo db") == "db"


def test_no_secret_on_disk_outside_the_env_file(smoke_host: SmokeHost, deployed: Deployed) -> None:
    value = deployed.secrets["session_secret"]
    found = smoke_host.run(
        "grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root /etc /opt/recorder --exclude=recorder.env || true",
        input=f"{value}\n",
    )
    assert found.stdout.strip() == ""
