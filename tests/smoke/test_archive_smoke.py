"""Deploy archive to the smoke target twice: real end state, then a converged rerun.

Needs an archive checkout: ``ARCHIVE_SOURCE``, else ``$PROJECTS_ROOT/archive``.
Its committed ``HEAD`` is exported, so local databases and uncommitted files
never reach the VM. Filesystem media storage, no MinIO or Echoport: ops-control's
``just smoke-archive-coexistence`` covers those against fixtures.
"""

from __future__ import annotations

import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.archive import ArchiveConfig, deploy_archive
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "archive.example.invalid"
SITE = "/home/archive/site"


def archive_checkout() -> Path | None:
    configured = os.environ.get("ARCHIVE_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "archive" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: ArchiveConfig
    secrets: SecretValues
    first: SshRun
    second: SshRun
    fresh_clone: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = archive_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no archive checkout (set ARCHIVE_SOURCE or PROJECTS_ROOT)")
    source = tmp_path_factory.mktemp("archive")
    exported = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(source)], input=exported.stdout, check=True)
    ref = SecretRef("secrets/smoke/archive.yml")
    cfg = ArchiveConfig(
        source_path=source,
        secrets=ref,
        traefik_host=HOST,
        django_allowed_hosts=("127.0.0.1", HOST),
        django_csrf_trusted_origins=(f"https://{HOST}",),
    )
    values = SecretValues(
        ref,
        {
            "django_secret_key": f'smoke-key-{secrets.token_hex(24)}$`"x',
            "api_token": f"smoke-api-{secrets.token_hex(16)}",
            "summary_api_key": f"smoke-summary-{secrets.token_hex(16)}",
            "admin_username": "smoke-admin",
            "admin_password": f"smoke-pw-{secrets.token_hex(12)}",
            "admin_email": "admin@example.invalid",
        },
    )
    # The same commit exported again with fresh mtimes (``tar -m``), as a new clone has.
    fresh = tmp_path_factory.mktemp("archive-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=exported.stdout, check=True)
    runs = []
    fresh_cfg = cfg.model_copy(update={"source_path": fresh})
    for label, config in (("first", cfg), ("second", cfg), ("fresh clone", fresh_cfg)):
        run = run_deploy_ssh(deploy_archive, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"archive {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    return Deployed(cfg, values, *runs)


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Ensure archive admin user") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_fresh_clone_of_unchanged_code_is_a_noop(deployed: Deployed) -> None:
    assert deployed.fresh_clone.mutating_changed_ops == []


def test_both_units_run(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for unit in ("archive", "archive-metadata-worker"):
        assert smoke_host.out(f"systemctl is-active {unit}") == "active"
        assert smoke_host.out(f"systemctl is-enabled {unit}") == "enabled"


def test_env_files_are_private(smoke_host: SmokeHost, deployed: Deployed) -> None:
    listing = smoke_host.out(f"stat -c '%a %U %G %n' {SITE}/.env {SITE}/.env.shell")
    for line in listing.splitlines():
        assert line.startswith("600 archive archive "), line


def test_migrations_applied_and_admin_can_log_in(smoke_host: SmokeHost, deployed: Deployed) -> None:
    script = (
        "set -a; . ../../.env.shell; set +a; .venv_python manage.py migrate --check && "
        ".venv_python manage.py shell -c "
        '"import sys; from django.contrib.auth import authenticate; '
        "u = authenticate(username=sys.stdin.readline().strip(), password=sys.stdin.readline().strip()); "
        'print(bool(u and u.is_superuser and u.is_staff))"'
    ).replace(".venv_python", f"{SITE}/.venv/bin/python")
    out = smoke_host.run(
        f"cd {SITE}/src/django && runuser -u archive -- sh -c '{script}'",
        input=f"{deployed.secrets['admin_username']}\n{deployed.secrets['admin_password']}\n",
    )
    assert out.stdout.strip().splitlines()[-1] == "True"


def test_traefik_route_serves_the_app(smoke_host: SmokeHost, deployed: Deployed) -> None:
    curl = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/"
    assert smoke_host.out(curl) == "200"
    assert smoke_host.out("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:10041/") == "200"


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        if key in ("admin_username", "admin_email"):
            continue
        found = smoke_host.run(
            "grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root /home/archive "
            "--exclude=.env --exclude=.env.shell --exclude='db.sqlite3*' || true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
