"""Deploy heis with django_site to the smoke target (staging shape).

heis is deployed from nothing, data is written, and the next runs (the same
tree, a fresh clone) change nothing; a code change restarts once and runs the
content reconcilers before collectstatic; the database, media, cache and admin
account stay as they were, and no marker is left behind. Needs a heis
checkout: ``HEIS_SOURCE``, else ``$PROJECTS_ROOT/heis``. Its committed
``HEAD`` is exported, so local databases and uncommitted files never reach
the VM. The switch from the Ansible role runs in ops-control
(``just smoke-heis-coexistence``).
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
from ops_deploy.services.django_site import DjangoSiteConfig, deploy_django_site
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.django_site_fixtures import heis_site
from tests.smoke.conftest import TIMINGS, SmokeHost

FQDN = "heis.example.invalid"
HOME = "/home/heis"
SITE = f"{HOME}/site"
STATE = "/var/lib/ops-deploy/heis"
USERS = "select username, is_staff, is_superuser, is_active from auth_user order by username"
ENV_DUMP = f"env -i sh -c 'set -a; . {SITE}/.env; set +a; env' | grep -E '^(DJANGO|WAGTAIL)_' | sort"
RECONCILERS = [
    "Deploy heis | Mark content reconciliation pending",
    "Deploy heis | Ensure default Wagtail pages exist",
    "Deploy heis | Seed homepage content",
    "Deploy heis | Seed subpage content and chrome defaults",
    "Deploy heis | Clear content reconciliation marker",
]


def heis_checkout() -> Path | None:
    configured = os.environ.get("HEIS_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "heis" if root else None


@dataclass
class Deployed:
    cfg: DjangoSiteConfig
    secrets: SecretValues
    runs: dict[str, SshRun]
    before: dict[str, str]


def _state(host: SmokeHost) -> dict[str, str]:
    """What later runs must leave alone."""

    return {
        "pid": host.out("systemctl show -p MainPID --value heis"),
        "env": host.out(ENV_DUMP),
        "inode": host.out(f"stat -c %i {SITE}/db.sqlite3"),
        "users": host.out(
            f"python3 -c \"import sqlite3; print(sqlite3.connect('{SITE}/db.sqlite3').execute('{USERS}').fetchall())\""
        ),
        "media": host.out(f"cat {SITE}/media/uploads/smoke.txt"),
        "cache": host.out(f"cat {SITE}/cache/smoke.txt"),
        "markers": host.out(f"ls -1A {STATE} 2>/dev/null | grep -c '^.ops-deploy-' || true"),
        "group": host.out("id -gn heis"),
    }


def _deploy(host: SmokeHost, label: str, fn: Callable[..., Any], cfg: object, values: SecretValues) -> SshRun:
    run = run_deploy_ssh(fn, cfg, values, host_name=host.name, host_data=host.host_data)
    TIMINGS[f"django_site heis: {label}"] = run.seconds
    assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
    return run


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = heis_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no heis checkout (set HEIS_SOURCE or PROJECTS_ROOT)")
    smoke_host.run(
        "systemctl disable --now heis 2>/dev/null; "
        "rm -f /etc/systemd/system/heis.service /etc/traefik/dynamic/heis*.yml; "
        "systemctl daemon-reload; userdel -r heis 2>/dev/null; rm -rf /home/heis; "
        f"rm -rf {STATE}; true"
    )
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    trees = {}
    for name, flags in (("tree", ["-x"]), ("fresh", ["-x", "-m"]), ("v2", ["-x"])):
        trees[name] = Path(tmp_path_factory.mktemp(f"heis-{name}"))
        subprocess.run(["tar", *flags, "-C", str(trees[name])], input=archive.stdout, check=True)
    (trees["v2"] / "docs-smoke-v2.txt").write_text("code change\n")
    ref = SecretRef("secrets/smoke/heis.yml")
    values = SecretValues(
        ref,
        {
            "django_secret_key": f"smoke-key-{secrets.token_hex(24)}",
            "django_admin_url": "smoke-admin-url/",
            "admin_username": "smoke-admin",
            "admin_email": "smoke-admin@example.invalid",
            "admin_password": f"smoke-pw-{secrets.token_hex(12)}",
        },
    )

    def cfg(tree: str) -> DjangoSiteConfig:
        return heis_site(trees[tree], ref, fqdn=FQDN)

    runs = {"first": _deploy(smoke_host, "first", deploy_django_site, cfg("tree"), values)}
    marker = secrets.token_hex(8)
    smoke_host.run(
        f"runuser -u heis -- mkdir -p {SITE}/media/uploads && "
        f"echo {marker} | runuser -u heis -- tee {SITE}/media/uploads/smoke.txt {SITE}/cache/smoke.txt >/dev/null"
    )
    before = _state(smoke_host)
    runs["again"] = _deploy(smoke_host, "again", deploy_django_site, cfg("tree"), values)
    runs["fresh clone"] = _deploy(smoke_host, "fresh clone", deploy_django_site, cfg("fresh"), values)
    runs["code change"] = _deploy(smoke_host, "code change", deploy_django_site, cfg("v2"), values)
    runs["code change again"] = _deploy(smoke_host, "code change again", deploy_django_site, cfg("v2"), values)
    return Deployed(cfg("tree"), values, runs, before)


def test_the_first_run_writes_the_canonical_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert any(name.endswith("| Write .env") for name in deployed.runs["first"].changed_ops)
    assert smoke_host.out(f"head -1 {SITE}/.env") == (
        "# Managed by ops-deploy (django_site). Local changes are overwritten by the next deploy."
    )
    assert smoke_host.out("id -gn heis") == "heis"


@pytest.mark.parametrize("run", ["again", "fresh clone", "code change again"])
def test_later_runs_change_nothing(deployed: Deployed, run: str) -> None:
    assert deployed.runs[run].mutating_changed_ops == []


def test_a_code_change_restarts_once_and_reconciles(deployed: Deployed) -> None:
    ops = deployed.runs["code change"].mutating_changed_ops
    assert ops[0] == "Deploy heis | Mark the heis source change pending"
    assert "Deploy heis | Sync heis source" in ops
    assert ops.count("Deploy heis | Restart heis.service") == 1
    assert ops[-1] == "Deploy heis | Clear the pending markers"
    # Staging shape: the content reconcilers follow the code change, before collectstatic.
    assert [op for op in ops if op in RECONCILERS] == RECONCILERS
    assert ops.index(RECONCILERS[-1]) < ops.index("Deploy heis | Collect static files")


def test_heis_answers_and_keeps_its_data(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active heis") == "active"
    forwarded = f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: {FQDN}' -H 'X-Forwarded-Proto: https'"
    assert smoke_host.out(f"{forwarded} http://127.0.0.1:10020/") == "200"
    now = _state(smoke_host)
    for key in ("env", "inode", "users", "media", "cache", "group"):
        assert now[key] == deployed.before[key], key
    assert now["markers"] == "0"
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/.env") == "600 heis heis"
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/gunicorn.sh") == "755 heis heis"
    # The launcher execs gunicorn: it is the unit's main process.
    pid = smoke_host.out("systemctl show -p MainPID --value heis")
    assert "gunicorn" in smoke_host.out(f"cat /proc/{shlex.quote(pid)}/cmdline | tr '\\0' ' '")


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    roots = f"/tmp /var/tmp /dev/shm /root {HOME} {STATE}"
    for key, value in deployed.secrets.items():
        found = smoke_host.run(
            f"grep -rlF --no-messages -f - {roots} --exclude=.env --exclude='db.sqlite3*' --exclude=.ops-deploy-admin "
            "|| true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
