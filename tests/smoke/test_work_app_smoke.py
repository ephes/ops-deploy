"""Deploy work_app to the smoke target: real end state, converged rerun, port guard.

Needs a work-ledger checkout: ``WORK_LEDGER_SOURCE``, else ``$PROJECTS_ROOT/work-ledger``.
Its committed ``HEAD`` is exported, so local databases and uncommitted files
never reach the VM. The Echoport/Nyxmon wiring is off here (neither runs on the
VM); the fake-connector tests cover it.
"""

from __future__ import annotations

import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.work_app import WorkAppConfig, deploy_work_app
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "work.example.invalid"
HOME = "/home/work"
SITE = f"{HOME}/site"


def work_ledger_checkout() -> Path | None:
    configured = os.environ.get("WORK_LEDGER_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "work-ledger" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: WorkAppConfig
    secrets: SecretValues
    first: SshRun
    second: SshRun
    fresh_clone: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = work_ledger_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no work-ledger checkout (set WORK_LEDGER_SOURCE or PROJECTS_ROOT)")
    if smoke_host.out(f"test -e {SITE} && echo present || true") == "present":
        pytest.skip(f"{SITE} already exists on the smoke target; the first-run checks need a host without it")
    source = tmp_path_factory.mktemp("work-ledger")
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive.stdout, check=True)
    ref = SecretRef("secrets/smoke/work_app.yml")
    cfg = WorkAppConfig(
        source_path=source,
        secrets=ref,
        traefik_host=HOST,
        django_allowed_hosts=("127.0.0.1", "localhost", HOST),
        django_csrf_trusted_origins=(f"https://{HOST}",),
    )
    values = SecretValues(
        ref,
        {
            "django_secret_key": f"smoke-key-{secrets.token_hex(32)}",
            "basic_auth_password": f"smoke-pw-{secrets.token_hex(12)}",
        },
    )

    def deploy(label: str, config: WorkAppConfig) -> SshRun:
        run = run_deploy_ssh(deploy_work_app, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"work_app {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        return run

    fresh = tmp_path_factory.mktemp("work-ledger-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=archive.stdout, check=True)
    return Deployed(
        cfg,
        values,
        deploy("first", cfg),
        deploy("second", cfg),
        deploy("fresh clone", cfg.model_copy(update={"source_path": fresh})),
    )


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Write .env") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_fresh_clone_of_unchanged_code_is_a_noop(deployed: Deployed) -> None:
    assert deployed.fresh_clone.mutating_changed_ops == []


def test_service_runs_and_answers(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active work-app") == "active"
    assert smoke_host.out("systemctl is-enabled work-app") == "enabled"
    assert smoke_host.out("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:10011/accounts/login/") == "200"
    assert smoke_host.out("curl -s http://127.0.0.1:10011/healthz") != ""


def test_state_files_are_private_and_owned(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/.env") == "600 work work"
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/db.sqlite3") == "600 work work"
    for path in (HOME, SITE, f"{SITE}/staticfiles"):
        assert smoke_host.out(f"stat -c '%a %U %G' {path}") == "750 work work"
    for name in ("manage.py", "pyproject.toml", "uv.lock"):
        assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/{name}") == "644 work work"
    assert smoke_host.out(f"find {SITE}/staticfiles -type f | head -n 1") != ""


def test_synced_trees_are_owned_by_the_service_user(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out(f"find {SITE}/src {SITE}/ledger ! -user work -print -quit") == ""


def test_traefik_serves_internal_clients_and_guards_the_rest(smoke_host: SmokeHost, deployed: Deployed) -> None:
    route = smoke_host.out("cat /etc/traefik/dynamic/work-app.yml")
    assert "work-app-ext:" in route
    assert '- "admin:$2y$05$' in route
    assert deployed.secrets["basic_auth_password"] not in route


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        found = smoke_host.run(
            f"grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root {HOME} --exclude=.env --exclude='db.sqlite3*' "
            "|| true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key


def test_port_preflight_refuses_another_listener(smoke_host: SmokeHost, deployed: Deployed) -> None:
    smoke_host.run("systemctl stop work-app")
    squatter = "systemd-run --unit=work-app-port-squatter python3 -m http.server 10011 --bind 127.0.0.1"
    smoke_host.run(f"{squatter} && sleep 1")
    try:
        run = run_deploy_ssh(
            deploy_work_app,
            deployed.cfg,
            deployed.secrets,
            host_name=smoke_host.name,
            host_data=smoke_host.host_data,
        )
        assert not run.succeeded
        failed = [op.name for op in run.ops if not op.succeeded]
        assert failed
        assert failed[0] == "Deploy work_app | Port preflight tcp/10011"
        assert run.mutating_changed_ops == []
    finally:
        smoke_host.run("systemctl stop work-app-port-squatter; systemctl start work-app", check=False)
    assert smoke_host.out("systemctl is-active work-app") == "active"


def test_files_newer_than_the_service_restart_it(smoke_host: SmokeHost, deployed: Deployed) -> None:
    before = smoke_host.out("systemctl show -p MainPID --value work-app")
    # Content unchanged, so only the "written after the service started" probe can see it.
    smoke_host.run(f"sleep 4; touch {SITE}/manage.py")
    run = run_deploy_ssh(
        deploy_work_app, deployed.cfg, deployed.secrets, host_name=smoke_host.name, host_data=smoke_host.host_data
    )
    assert run.succeeded
    assert any(name.endswith("| Service started before the deployed files") for name in run.mutating_changed_ops)
    assert smoke_host.out("systemctl show -p MainPID --value work-app") != before
    again = run_deploy_ssh(
        deploy_work_app, deployed.cfg, deployed.secrets, host_name=smoke_host.name, host_data=smoke_host.host_data
    )
    assert again.mutating_changed_ops == []
