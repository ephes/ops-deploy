"""Deploy heis to the smoke target: real end state, converged rerun, kept data.

Needs a heis checkout: ``HEIS_SOURCE``, else ``$PROJECTS_ROOT/heis``. Its
committed ``HEAD`` is exported, so local databases and uncommitted files never
reach the VM.
"""

from __future__ import annotations

import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.heis import HeisConfig, deploy_heis
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

FQDN = "heis.example.invalid"
HOME = "/home/heis"
SITE = f"{HOME}/site"
ADMIN_QUERY = (
    "import sqlite3; db = sqlite3.connect('file:{db}?mode=ro', uri=True); "
    "print(db.execute('select is_staff, is_superuser, is_active from auth_user').fetchall())"
)


def heis_checkout() -> Path | None:
    configured = os.environ.get("HEIS_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "heis" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: HeisConfig
    secrets: SecretValues
    first: SshRun
    second: SshRun
    fresh_clone: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = heis_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no heis checkout (set HEIS_SOURCE or PROJECTS_ROOT)")
    # Start from nothing: heis has no remove deploy and a coexistence smoke may have run before.
    smoke_host.run(
        "systemctl disable --now heis 2>/dev/null; "
        "rm -f /etc/systemd/system/heis.service /etc/traefik/dynamic/heis*.yml; "
        "systemctl daemon-reload; userdel -r heis 2>/dev/null; rm -rf /home/heis; true"
    )
    source = tmp_path_factory.mktemp("heis")
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive.stdout, check=True)
    fresh = tmp_path_factory.mktemp("heis-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=archive.stdout, check=True)
    ref = SecretRef("secrets/smoke/heis.yml")
    cfg = HeisConfig(
        source_path=source, secrets=ref, fqdn=FQDN, traefik_host_rule=f"Host(`{FQDN}`) || Host(`www.{FQDN}`)"
    )
    values = SecretValues(
        ref,
        {
            "django_secret_key": f"smoke-key-{secrets.token_hex(24)}",
            "django_admin_url": f"smoke-admin-{secrets.token_hex(6)}/",
            "admin_username": "smoke-admin",
            "admin_email": "smoke-admin@example.invalid",
            "admin_password": f"smoke-pw-{secrets.token_hex(12)}",
        },
    )
    runs = []
    for label, config in (
        ("first", cfg),
        ("second", cfg),
        ("fresh clone", cfg.model_copy(update={"source_path": fresh})),
    ):
        run = run_deploy_ssh(deploy_heis, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"heis {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    return Deployed(cfg, values, *runs)


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Write .env") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_fresh_clone_of_unchanged_code_is_a_noop(deployed: Deployed) -> None:
    assert deployed.fresh_clone.mutating_changed_ops == []


def test_service_runs_and_answers(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active heis") == "active"
    assert smoke_host.out("systemctl is-enabled heis") == "enabled"
    code = smoke_host.out(f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: {FQDN}' http://127.0.0.1:10020/")
    assert code == "301"
    forwarded = f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: {FQDN}' -H 'X-Forwarded-Proto: https'"
    assert smoke_host.out(f"{forwarded} http://127.0.0.1:10020/") == "200"


def test_files_have_the_roles_owners_and_modes(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/.env") == "600 heis heis"
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/gunicorn.sh") == "755 heis heis"
    assert smoke_host.out(f"stat -c '%a %U %G' {HOME}/.ops-deploy-admin") == "600 root root"
    assert smoke_host.out(f"stat -c '%a %U %G' {HOME}/.config/fish/config.fish") == "644 heis heis"
    assert smoke_host.out(f"readlink {SITE}/venv") == f"{SITE}/.venv"
    assert smoke_host.out("getent passwd heis | cut -d: -f6,7") == f"{HOME}:/usr/bin/fish"
    assert smoke_host.out('test -z "$(find /home/heis/site ! -user heis -print -quit)" && echo ok') == "ok"


def test_admin_user_exists(smoke_host: SmokeHost, deployed: Deployed) -> None:
    query = ADMIN_QUERY.format(db=f"{SITE}/db.sqlite3")
    assert smoke_host.out(f'python3 -c "{query}"') == "[(1, 1, 1)]"


def test_content_reconcilers_ran(smoke_host: SmokeHost, deployed: Deployed) -> None:
    query = (
        f"import sqlite3; db = sqlite3.connect('file:{SITE}/db.sqlite3?mode=ro', uri=True); "
        "print(db.execute('select count(*) from wagtailcore_page where depth = 2').fetchone()[0])"
    )
    assert int(smoke_host.out(f'python3 -c "{query}"')) >= 1


def test_route_is_written_where_the_role_writes_it(smoke_host: SmokeHost, deployed: Deployed) -> None:
    route = smoke_host.out("cat /etc/traefik/dynamic/heis.traefik.yml")
    assert f"{FQDN}-secure-router:" in route
    assert smoke_host.out("test -e /etc/traefik/dynamic/heis.yml && echo wrong || echo ok") == "ok"


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    roots = f"/tmp /var/tmp /dev/shm /root {HOME}"
    for key, value in deployed.secrets.items():
        found = smoke_host.run(
            f"grep -rlF --no-messages -f - {roots} --exclude=.env --exclude='db.sqlite3*' --exclude=.ops-deploy-admin "
            "|| true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
