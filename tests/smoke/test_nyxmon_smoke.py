"""Deploy nyxmon to the smoke target twice: real end state, then a converged rerun.

Needs a nyxmon checkout: ``NYXMON_SOURCE``, else ``$PROJECTS_ROOT/nyxmon``. Its
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
from ops_deploy.services.nyxmon import NyxmonConfig, deploy_nyxmon
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "nyxmon.example.invalid"
SITE = "/home/nyxmon/site"
OPSGATE = "http://192.0.2.10:8711"
AGENT_DROPIN = "/etc/systemd/system/nyxmon-monitor.service.d/agent-impl.conf"


def nyxmon_checkout() -> Path | None:
    configured = os.environ.get("NYXMON_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "nyxmon" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: NyxmonConfig
    secrets: SecretValues
    first: SshRun
    second: SshRun
    fresh_clone: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = nyxmon_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no nyxmon checkout (set NYXMON_SOURCE or PROJECTS_ROOT)")
    source = tmp_path_factory.mktemp("nyxmon")
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive.stdout, check=True)
    ref = SecretRef("secrets/smoke/nyxmon.yml")
    cfg = NyxmonConfig(
        source_path=source,
        secrets=ref,
        traefik_host=HOST,
        django_allowed_hosts=f"127.0.0.1,{HOST}",
        require_login=True,
        opsgate_submit_base_url=OPSGATE,
    )
    values = SecretValues(
        ref,
        {
            "django_secret_key": f'smoke-key-{secrets.token_hex(24)}$`"x',
            "telegram_bot_token": f"123:smoke-bot-{secrets.token_hex(12)}",
            "telegram_chat_id": "-100123",
            "basic_auth_password": f"smoke-pw-{secrets.token_hex(12)}",
            "opsgate_submit_token": f"smoke-opsgate-{secrets.token_hex(16)}",
        },
    )
    # The same commit exported again with fresh mtimes (``tar -m``), as a new clone has.
    fresh = tmp_path_factory.mktemp("nyxmon-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=archive.stdout, check=True)
    # A Rust agent selection left by the role (nyxmon_agent_impl: rust); impl python removes it.
    smoke_host.run(
        f"install -d -m 0755 {AGENT_DROPIN.rsplit('/', 1)[0]} && "
        f"printf '[Service]\\nExecStart=\\nExecStart=/opt/nyxmon-agent/0.1.0/nyxmon-agent\\n' > {AGENT_DROPIN}"
    )
    runs = []
    fresh_cfg = cfg.model_copy(update={"source_path": fresh})
    for label, config in (("first", cfg), ("second", cfg), ("fresh clone", fresh_cfg)):
        run = run_deploy_ssh(deploy_nyxmon, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"nyxmon {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    return Deployed(cfg, values, *runs)


def test_the_python_agent_runs(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert "Deploy nyxmon | Select the Python agent for nyxmon-monitor" in deployed.first.changed_ops
    assert smoke_host.out(f"test -e {AGENT_DROPIN} && echo present || echo absent") == "absent"
    for run in (deployed.first, deployed.second, deployed.fresh_clone):
        assert run.op("Deploy nyxmon | Check nyxmon-monitor runs the Python agent").succeeded


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Write .env") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_fresh_clone_of_unchanged_code_is_a_noop(deployed: Deployed) -> None:
    assert deployed.fresh_clone.mutating_changed_ops == []


def test_both_units_run(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for unit in ("nyxmon", "nyxmon-monitor"):
        assert smoke_host.out(f"systemctl is-active {unit}") == "active"
        assert smoke_host.out(f"systemctl is-enabled {unit}") == "enabled"
        assert smoke_host.out(f"systemctl show -p UMask --value {unit}") == "0077"


def test_database_and_env_files_are_private(smoke_host: SmokeHost, deployed: Deployed) -> None:
    listing = smoke_host.out(f"stat -c '%a %U %G %n' {SITE}/db.sqlite3* {SITE}/.env {SITE}/.env.shell")
    assert listing
    for line in listing.splitlines():
        assert line.startswith("600 nyxmon nyxmon "), line
    assert smoke_host.out(f"find {SITE} -maxdepth 1 -name '.ops-secret.*'") == ""


def test_migrations_are_applied(smoke_host: SmokeHost, deployed: Deployed) -> None:
    script = "set -a; . ./.env.shell; set +a; exec .venv/bin/python manage.py migrate --check"
    smoke_host.run(f"cd {SITE} && runuser -u nyxmon -- sh -c '{script}'")


def test_traefik_route_requires_auth_from_outside_internal_ranges(smoke_host: SmokeHost, deployed: Deployed) -> None:
    curl = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/"
    assert smoke_host.out(curl) == "401"
    password = deployed.secrets["basic_auth_password"]
    authed = smoke_host.run(f"{curl} --config -", input=f'user = "admin:{password}"\n')
    # NyxBoard requires a Django login: an authenticated proxy request lands on the login redirect.
    assert authed.stdout.strip() == "302"


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        found = smoke_host.run(
            "grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root /home/nyxmon "
            "--exclude=.env --exclude=.env.shell --exclude='db.sqlite3*' || true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
    route = smoke_host.out("cat /etc/traefik/dynamic/nyxmon.yml")
    assert deployed.secrets["basic_auth_password"] not in route
