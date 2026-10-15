"""Deploy echoport to the smoke target: real end state, a converged rerun, a code change.

Needs an echoport checkout: ``ECHOPORT_SOURCE``, else ``$PROJECTS_ROOT/echoport``.
Its committed ``HEAD`` is exported, so local databases and uncommitted files
never reach the VM. No MinIO and no Nyxmon: the cleanup job and the Nyxmon
check are off here; ops-control's ``just smoke-echoport-coexistence`` covers
them against fixtures.
"""

from __future__ import annotations

import os
import secrets
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.echoport import EchoportConfig, deploy_echoport
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "echoport.example.invalid"
SITE = "/home/echoport/site"
MARKER = "smoke-marker"


def echoport_checkout() -> Path | None:
    configured = os.environ.get("ECHOPORT_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "echoport" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: EchoportConfig
    secrets: SecretValues
    first: SshRun
    second: SshRun
    fresh_clone: SshRun
    code_change: SshRun
    pids: tuple[str, str]


def manage(smoke_host: SmokeHost, script: str, input: str | None = None) -> str:
    shell = f"exec {SITE}/.venv/bin/python manage.py shell -c {shlex.quote(script)}"
    result = smoke_host.run(
        f"cd {SITE} && runuser -u echoport -- env DJANGO_SETTINGS_MODULE=config.settings.production sh -c "
        f"{shlex.quote(shell)}",
        input=input,
    )
    return result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = echoport_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no echoport checkout (set ECHOPORT_SOURCE or PROJECTS_ROOT)")
    source = tmp_path_factory.mktemp("echoport")
    exported = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(source)], input=exported.stdout, check=True)
    ref = SecretRef("secrets/smoke/echoport.yml")
    cfg = EchoportConfig(
        source_path=source,
        secrets=ref,
        traefik_host=HOST,
        django_allowed_hosts=("127.0.0.1", HOST),
        cleanup_enabled=False,
        staging_db_refresh_enabled=True,
        staging_db_refresh_targets=("homepage-production-db",),
    )
    values = SecretValues(
        ref,
        {
            "django_secret_key": f'smoke-key-{secrets.token_hex(24)}$`"x',
            "fastdeploy_base_url": "https://deploy.example.invalid",
            "fastdeploy_service_token": f"smoke-token-{secrets.token_hex(16)}",
            "admin_username": "smoke-admin",
            "admin_password": f"smoke-pw-{secrets.token_hex(12)}",
            "admin_email": "admin@example.invalid",
            "basic_auth_password": f"smoke-basic-{secrets.token_hex(12)}",
        },
    )
    # The same commit exported again with fresh mtimes (``tar -m``), as a new clone has.
    fresh = tmp_path_factory.mktemp("echoport-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=exported.stdout, check=True)
    changed = tmp_path_factory.mktemp("echoport-changed")
    subprocess.run(["tar", "-x", "-C", str(changed)], input=exported.stdout, check=True)
    (changed / "src/django/smoke_marker.py").write_text("# a code change\n")

    runs = []
    pids = ["", ""]
    for label, config in (
        ("first", cfg),
        ("second", cfg),
        ("fresh clone", cfg.model_copy(update={"source_path": fresh})),
        ("code change", cfg.model_copy(update={"source_path": changed})),
    ):
        if label == "second":
            manage(smoke_host, f"from django.contrib.auth.models import User; User.objects.create_user({MARKER!r})")
            pids[0] = smoke_host.out("systemctl show -p MainPID --value echoport")
        if label == "code change":
            pids[1] = smoke_host.out("systemctl show -p MainPID --value echoport")
        run = run_deploy_ssh(deploy_echoport, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"echoport {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    first, second, fresh_clone, code_change = runs
    return Deployed(cfg, values, first, second, fresh_clone, code_change, (pids[0], pids[1]))


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Ensure Echoport admin user") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_fresh_clone_of_unchanged_code_is_a_noop(deployed: Deployed) -> None:
    assert deployed.fresh_clone.mutating_changed_ops == []


def test_code_change_restarts_and_keeps_the_database(smoke_host: SmokeHost, deployed: Deployed) -> None:
    names = {name.removeprefix("Deploy echoport | ") for name in deployed.code_change.mutating_changed_ops}
    assert {"Sync echoport source", "Restart echoport.service"} <= names
    assert smoke_host.out("systemctl show -p MainPID --value echoport") != deployed.pids[1]
    found = manage(
        smoke_host,
        f"from django.contrib.auth.models import User; print(User.objects.filter(username={MARKER!r}).exists())",
    )
    assert found == "True"


def test_unit_runs_and_listens_on_loopback_only(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active echoport") == "active"
    assert smoke_host.out("systemctl is-enabled echoport") == "enabled"
    sockets = smoke_host.out("ss -H -ltn 'sport = :10018'")
    assert sockets
    assert all("127.0.0.1:10018" in line for line in sockets.splitlines())
    assert smoke_host.out("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:10018/api/health/") in {"200", "503"}


def test_env_file_is_private(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/.env") == "600 echoport echoport"


def test_admin_can_log_in(smoke_host: SmokeHost, deployed: Deployed) -> None:
    out = manage(
        smoke_host,
        "import sys; from django.contrib.auth import authenticate; "
        "u = authenticate(username=sys.stdin.readline().strip(), password=sys.stdin.readline().strip()); "
        "print(bool(u and u.is_superuser and u.is_staff))",
        input=f"{deployed.secrets['admin_username']}\n{deployed.secrets['admin_password']}\n",
    )
    assert out == "True"


def test_traefik_route_serves_the_app(smoke_host: SmokeHost, deployed: Deployed) -> None:
    base = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1"
    # Loopback is outside the internal ranges: the public router asks for basic auth.
    assert smoke_host.out(f"{base} https://{HOST}/admin/login/") == "401"
    auth = f"{deployed.secrets['basic_auth_password']}"
    assert smoke_host.run(f"{base} -u admin:{shlex.quote(auth)} https://{HOST}/admin/login/").stdout.strip() == "200"


def test_crontab_has_the_roles_entries_in_ansibles_format(smoke_host: SmokeHost, deployed: Deployed) -> None:
    lines = smoke_host.out("crontab -l -u echoport").splitlines()
    assert lines[0] == "#Ansible: Echoport scheduled backups"
    assert lines[1].startswith(
        "*/5 * * * * cd /home/echoport/site && DJANGO_SETTINGS_MODULE=config.settings.production "
    )
    assert "#Ansible: Echoport staging DB refresh" in lines
    assert "#Ansible: Echoport cleanup old backups" not in lines
    assert smoke_host.out("stat -c '%a %U' /home/echoport/logs/scheduler.log") == "640 echoport"
    assert smoke_host.out(f"stat -c '%a %U' {SITE}/staging-db-refresh.sh") == "750 echoport"


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        if key in ("admin_username", "admin_email", "fastdeploy_base_url"):
            continue
        found = smoke_host.run(
            "grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root /home/echoport "
            "--exclude=.env --exclude='db.sqlite3*' --exclude='*.pyc' --exclude=traefik.yml || true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
