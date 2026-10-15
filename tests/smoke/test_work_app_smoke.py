"""Deploy work_app to the smoke target: real end state, converged rerun, port guard.

Needs a work-ledger checkout: ``WORK_LEDGER_SOURCE``, else ``$PROJECTS_ROOT/work-ledger``.
Its committed ``HEAD`` is exported, so local databases and uncommitted files
never reach the VM. The Echoport/Nyxmon wiring is off here (neither runs on the
VM); the fake-connector tests cover it.
"""

from __future__ import annotations

import os
import secrets
import shlex
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.work_app import (
    WorkAppBackupConfig,
    WorkAppConfig,
    WorkAppRemoveConfig,
    WorkAppRestoreConfig,
    deploy_work_app,
    deploy_work_app_backup,
    deploy_work_app_remove,
    deploy_work_app_restore,
)
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


# -- backup, restore, remove (last: the removal deletes everything) -----------------


def _django(smoke_host: SmokeHost, script: str) -> str:
    shell = f"set -a; . ./.env; set +a; exec .venv/bin/python manage.py shell -c {shlex.quote(script)}"
    out = smoke_host.out(f"cd {SITE} && runuser -u work -- sh -c {shlex.quote(shell)}")
    return out.splitlines()[-1] if out else ""


USERS = (
    "from django.contrib.auth import get_user_model; "
    "print(sorted(get_user_model().objects.values_list('username', flat=True)))"
)


def test_backup_restore_and_remove(smoke_host: SmokeHost, deployed: Deployed, tmp_path: Path) -> None:
    def run(deploy: Callable[..., Any], cfg: object) -> SshRun:
        result = run_deploy_ssh(deploy, cfg, host_name=smoke_host.name, host_data=smoke_host.host_data)
        assert result.succeeded, (result.error, [op for op in result.ops if not op.succeeded])
        return result

    # The roles need the sqlite3 CLI on the host (macmini has it); the VM does not.
    smoke_host.run(
        "command -v sqlite3 >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive "
        "apt-get install -y -qq sqlite3; }"
    )
    _django(
        smoke_host,
        "from django.contrib.auth import get_user_model; get_user_model().objects.create_user('smoke-marker')",
    )
    local = tmp_path / "backups"
    backup_cfg = WorkAppBackupConfig(local_dir=local, ops_library_version="smoke")
    run(deploy_work_app_backup, backup_cfg)
    (archive,) = local.glob("manual-*.tar.gz")
    assert archive.stat().st_size > 0
    listing = smoke_host.out(f"tar -tzf /opt/backups/work_app/{archive.name}")
    for member in ("metadata.yml", "manifest.sha256", "database/db.sqlite3", "env/.env", "configs/work-app.service"):
        assert f"{archive.name.removesuffix('.tar.gz')}/{member}" in listing
    assert smoke_host.out(f"stat -c '%a %U' /opt/backups/work_app/{archive.name}") == "600 root"

    # The data changes after the backup; the restore must bring the backed-up state back.
    _django(
        smoke_host,
        "from django.contrib.auth import get_user_model; get_user_model().objects.all().delete()",
    )
    assert _django(smoke_host, USERS) == "[]"
    restore = run(deploy_work_app_restore, WorkAppRestoreConfig(ops_library_version="smoke"))
    assert any(name.endswith("| Restart work-app") for name in restore.changed_ops)
    assert _django(smoke_host, USERS) == "['smoke-marker']"
    assert smoke_host.out("systemctl is-active work-app") == "active"
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/db.sqlite3") == "600 work work"
    assert smoke_host.out("ls -d /home/work/site.pre-restore-* 2>/dev/null || true") == ""
    assert smoke_host.out("ls -d /tmp/work-app-restore 2>/dev/null || true") == ""
    # A deploy over the restored state has nothing to do.
    again = run_deploy_ssh(
        deploy_work_app, deployed.cfg, deployed.secrets, host_name=smoke_host.name, host_data=smoke_host.host_data
    )
    assert again.succeeded
    assert again.mutating_changed_ops == []

    removal = WorkAppRemoveConfig(confirm=True, auto_confirm=True)
    run(deploy_work_app_remove, removal)
    assert smoke_host.out("systemctl is-active work-app || true") in {"inactive", "unknown"}
    assert (
        smoke_host.out("ls /etc/systemd/system/work-app.service /etc/traefik/dynamic/work-app.yml 2>&1 | wc -l") == "2"
    )
    assert smoke_host.out("id work 2>&1 | grep -c 'no such user' || true") == "1"
    assert smoke_host.out("test -e /home/work && echo present || echo gone") == "gone"
    second = run(deploy_work_app_remove, removal)
    assert second.mutating_changed_ops == []
