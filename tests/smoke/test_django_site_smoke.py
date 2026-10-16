"""Switch marina from ``services/marina`` to django_site on the smoke target.

The old module deploys marina twice; data is written; django_site then takes
over. The switch may rewrite only the documented files and restart marina
once; the next runs (the same tree, a fresh clone) change nothing, a code
change restarts once more, and the database, media, cache and admin account
stay as they were. Needs a marina checkout like ``test_marina_smoke.py``.
"""

from __future__ import annotations

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
from ops_deploy.services.marina import MarinaConfig, deploy_marina
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.django_site_fixtures import from_marina
from tests.smoke.conftest import TIMINGS, SmokeHost
from tests.smoke.test_marina_smoke import marina_checkout

FQDN = "marina.example.invalid"
HOME = "/home/marina"
SITE = f"{HOME}/site"
FILES = (
    f"{SITE}/.env",
    f"{SITE}/gunicorn.sh",
    f"{HOME}/.config/fish/config.fish",
    "/etc/systemd/system/marina.service",
    "/etc/traefik/dynamic/marina.traefik.yml",
)
SWITCH = [
    "Deploy marina | Write fish config",
    "Deploy marina | Mark marina for a restart",
    "Deploy marina | Write .env",
    "Deploy marina | Write gunicorn.sh",
    "Deploy marina | Install systemd unit marina.service",
    "Deploy marina | Reload systemd for marina.service",
    "Deploy marina | Restart marina.service",
    "Deploy marina | Write Traefik route marina",
    "Deploy marina | Clear the pending markers",
]
USERS = "select username, is_staff, is_superuser, is_active from auth_user order by username"
ENV_DUMP = f"env -i sh -c 'set -a; . {SITE}/.env; set +a; env' | grep -E '^(DJANGO|WAGTAIL)_' | sort"


@dataclass
class Switch:
    cfg: DjangoSiteConfig
    secrets: SecretValues
    old_runs: list[SshRun]
    runs: dict[str, SshRun]
    before: dict[str, str]
    after_switch: dict[str, str]


def _state(host: SmokeHost) -> dict[str, str]:
    """What must survive the switch, and what may change once."""

    state = {
        "pid": host.out("systemctl show -p MainPID --value marina"),
        "started": host.out("systemctl show -p ActiveEnterTimestampMonotonic --value marina"),
        "env": host.out(ENV_DUMP),
        "inode": host.out(f"stat -c %i {SITE}/db.sqlite3"),
        "users": host.out(
            f"python3 -c \"import sqlite3; print(sqlite3.connect('{SITE}/db.sqlite3').execute('{USERS}').fetchall())\""
        ),
        "media": host.out(f"cat {SITE}/media/uploads/smoke.txt"),
        "cache": host.out(f"cat {SITE}/cache/smoke.txt"),
        "traefik": host.out("systemctl show -p MainPID --value traefik"),
        "markers": host.out(f"ls -1A {HOME} | grep -c '^.ops-deploy-pending\\|^.ops-deploy-restart' || true"),
    }
    for path in FILES:
        state[path] = host.out(f"sha256sum {path} | cut -d' ' -f1")
    return state


def _deploy(host: SmokeHost, label: str, fn: Callable[..., Any], cfg: object, values: SecretValues) -> SshRun:
    run = run_deploy_ssh(fn, cfg, values, host_name=host.name, host_data=host.host_data)
    TIMINGS[f"django_site switch: {label}"] = run.seconds
    assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
    return run


@pytest.fixture(scope="module")
def switch(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Switch:
    checkout = marina_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no marina checkout (set MARINA_SOURCE or PROJECTS_ROOT)")
    smoke_host.run(
        "systemctl disable --now marina 2>/dev/null; "
        "rm -f /etc/systemd/system/marina.service /etc/traefik/dynamic/marina*.yml; "
        "systemctl daemon-reload; userdel -r marina 2>/dev/null; rm -rf /home/marina; true"
    )
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    trees = {}
    for name, flags in (("tree", ["-x"]), ("fresh", ["-x", "-m"]), ("v2", ["-x"])):
        trees[name] = Path(tmp_path_factory.mktemp(f"marina-{name}"))
        subprocess.run(["tar", *flags, "-C", str(trees[name])], input=archive.stdout, check=True)
    (trees["v2"] / "docs-smoke-v2.txt").write_text("code change\n")
    ref = SecretRef("secrets/smoke/marina.yml")
    old = MarinaConfig(
        source_path=trees["tree"], secrets=ref, fqdn=FQDN, traefik_host_rule=f"Host(`{FQDN}`) || Host(`www.{FQDN}`)"
    )
    values = SecretValues(
        ref,
        {
            "django_secret_key": f"smoke-key-{secrets.token_hex(24)}",
            "admin_username": "smoke-admin",
            "admin_email": "smoke-admin@example.invalid",
            "admin_password": f"smoke-pw-{secrets.token_hex(12)}",
        },
    )
    old_runs = [_deploy(smoke_host, f"old module {n}", deploy_marina, old, values) for n in (1, 2)]
    marker = secrets.token_hex(8)
    smoke_host.run(
        f"runuser -u marina -- mkdir -p {SITE}/media/uploads && "
        f"echo {marker} | runuser -u marina -- tee {SITE}/media/uploads/smoke.txt {SITE}/cache/smoke.txt >/dev/null"
    )
    before = _state(smoke_host)
    cfg = from_marina(old)
    runs = {"switch": _deploy(smoke_host, "switch", deploy_django_site, cfg, values)}
    after_switch = _state(smoke_host)
    runs["again"] = _deploy(smoke_host, "again", deploy_django_site, cfg, values)
    fresh = cfg.model_copy(update={"source": cfg.source.model_copy(update={"path": trees["fresh"]})})
    runs["fresh clone"] = _deploy(smoke_host, "fresh clone", deploy_django_site, fresh, values)
    runs["unchanged after fresh"] = _deploy(smoke_host, "unchanged", deploy_django_site, cfg, values)
    v2 = cfg.model_copy(update={"source": cfg.source.model_copy(update={"path": trees["v2"]})})
    runs["code change"] = _deploy(smoke_host, "code change", deploy_django_site, v2, values)
    runs["code change again"] = _deploy(smoke_host, "code change again", deploy_django_site, v2, values)
    return Switch(cfg, values, old_runs, runs, before, after_switch)


def test_the_old_module_was_converged(switch: Switch) -> None:
    assert switch.old_runs[1].mutating_changed_ops == []


def test_the_switch_rewrites_the_documented_files_and_restarts_once(switch: Switch) -> None:
    assert switch.runs["switch"].mutating_changed_ops == SWITCH
    for path in FILES:
        assert switch.after_switch[path] != switch.before[path], path
    assert switch.after_switch["pid"] != switch.before["pid"]
    assert switch.after_switch["traefik"] == switch.before["traefik"]


def test_the_switch_keeps_env_values_and_data(switch: Switch) -> None:
    for key in ("env", "inode", "users", "media", "cache"):
        assert switch.after_switch[key] == switch.before[key], key
    assert "DJANGO_SECRET_KEY=" in switch.before["env"]
    assert switch.after_switch["markers"] == "0"


@pytest.mark.parametrize("run", ["again", "fresh clone", "unchanged after fresh", "code change again"])
def test_later_runs_change_nothing(switch: Switch, run: str) -> None:
    assert switch.runs[run].mutating_changed_ops == []


def test_a_code_change_restarts_once(switch: Switch) -> None:
    ops = switch.runs["code change"].mutating_changed_ops
    assert ops[0] == "Deploy marina | Mark the marina source change pending"
    assert "Deploy marina | Sync marina source" in ops
    assert ops.count("Deploy marina | Restart marina.service") == 1
    assert ops[-1] == "Deploy marina | Clear the pending markers"


def test_marina_answers_and_keeps_its_data(smoke_host: SmokeHost, switch: Switch) -> None:
    assert smoke_host.out("systemctl is-active marina") == "active"
    forwarded = f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: {FQDN}' -H 'X-Forwarded-Proto: https'"
    assert smoke_host.out(f"{forwarded} http://127.0.0.1:10019/") == "200"
    now = _state(smoke_host)
    for key in ("env", "inode", "users", "media", "cache"):
        assert now[key] == switch.before[key], key
    assert now["markers"] == "0"
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/.env") == "600 marina marina"
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/gunicorn.sh") == "755 marina marina"
    # The launcher execs gunicorn: it is the unit's main process.
    pid = smoke_host.out("systemctl show -p MainPID --value marina")
    assert "gunicorn" in smoke_host.out(f"cat /proc/{shlex.quote(pid)}/cmdline | tr '\\0' ' '")


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, switch: Switch) -> None:
    roots = f"/tmp /var/tmp /dev/shm /root {HOME}"
    for key, value in switch.secrets.items():
        found = smoke_host.run(
            f"grep -rlF --no-messages -f - {roots} --exclude=.env --exclude='db.sqlite3*' --exclude=.ops-deploy-admin "
            "|| true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
