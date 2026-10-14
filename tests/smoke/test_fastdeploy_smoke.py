"""Deploy fastdeploy to the smoke target: real end state, converged reruns, host state kept.

Needs a FastDeploy checkout: ``FASTDEPLOY_SOURCE``, else ``$PROJECTS_ROOT/fastdeploy``.
Its committed ``HEAD`` is exported, so local databases and uncommitted files
never reach the VM. The VM needs PostgreSQL (``smoke/provision.sh``); the first
deploy installs Node.js from NodeSource like the role.
"""

from __future__ import annotations

import os
import secrets
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

import bcrypt
import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.fastdeploy import FastdeployConfig, deploy_fastdeploy
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "deploy.example.invalid"
SITE = "/home/fastdeploy/site"
# Registered-service state the deploy must leave alone (fastdeploy_register_service writes it).
REGISTERED = f"{SITE}/services/smoke-registered"
RUNNER = "/home/deploy/runners/smoke-registered"
ALWAYS = ["Deploy fastdeploy | Restart fastdeploy.service"]


def fastdeploy_checkout() -> Path | None:
    configured = os.environ.get("FASTDEPLOY_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "fastdeploy" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: FastdeployConfig
    secrets: SecretValues
    password: str
    first: SshRun
    second: SshRun
    fresh_clone: SshRun


def _registered_state(smoke_host: SmokeHost) -> None:
    smoke_host.run(
        f"install -d -o fastdeploy -g fastdeploy {REGISTERED} && "
        f"printf '#!/bin/sh\\necho deployed\\n' > {REGISTERED}/deploy.sh && "
        f'printf \'{{"name": "smoke-registered"}}\\n\' > {REGISTERED}/config.json && '
        f"chown fastdeploy:fastdeploy {REGISTERED}/* && chmod 755 {REGISTERED}/deploy.sh && "
        f"install -d -m 700 -o deploy -g deploy {RUNNER} && echo runner > {RUNNER}/marker"
    )


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = fastdeploy_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no FastDeploy checkout (set FASTDEPLOY_SOURCE or PROJECTS_ROOT)")
    source = tmp_path_factory.mktemp("fastdeploy")
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive.stdout, check=True)
    ref = SecretRef("secrets/smoke/fastdeploy.yml")
    cfg = FastdeployConfig(
        source_path=source,
        secrets=ref,
        api_url=f"https://{HOST}",
        websocket_url=f"wss://{HOST}/deployments/ws",
        traefik_host=HOST,
        legacy_service_tokens_accepted_until="2026-10-31T00:00:00+00:00",
        legacy_token_users=("ops-control",),
    )
    password = f"smoke-login-{secrets.token_hex(8)}"
    values = SecretValues(
        ref,
        {
            "secret_key": f'smoke-key-{secrets.token_hex(24)}$`"x',
            "initial_user_name": "smoke-admin",
            "initial_user_password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "postgres_password": f"smoke-pg-{secrets.token_hex(16)}",
            "basic_auth_password": f"smoke-pw-{secrets.token_hex(12)}",
        },
    )
    # Fresh secrets every session: start from a database without the old users
    # (their hashes would be kept) and without the build stamp (so the first run builds).
    smoke_host.run(
        "systemctl stop fastdeploy 2>/dev/null; "
        "runuser -u postgres -- psql -XAtq -c 'DROP DATABASE IF EXISTS fastdeploy' "
        "-c 'DROP ROLE IF EXISTS fastdeploy'; "
        f"rm -f {SITE}/frontend/dist/.ops-deploy-build; true"
    )
    fresh = tmp_path_factory.mktemp("fastdeploy-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=archive.stdout, check=True)
    fresh_cfg = cfg.model_copy(update={"source_path": fresh})
    runs = []
    for label, config in (("first", cfg), ("second", cfg), ("fresh clone", fresh_cfg)):
        run = run_deploy_ssh(
            deploy_fastdeploy, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data
        )
        TIMINGS[f"fastdeploy {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
        if label == "first":
            _registered_state(smoke_host)
    return Deployed(cfg, values, password, *runs)


def test_reruns_only_restart(deployed: Deployed) -> None:
    assert "Deploy fastdeploy | Build frontend" in deployed.first.changed_ops
    assert deployed.second.mutating_changed_ops == ALWAYS
    assert deployed.fresh_clone.mutating_changed_ops == ALWAYS
    for run in (deployed.second, deployed.fresh_clone):
        assert all(op.succeeded for op in run.ops if op.read_only)


def test_service_runs_and_answers(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active fastdeploy") == "active"
    assert smoke_host.out("systemctl is-enabled fastdeploy") == "enabled"
    assert smoke_host.out(f"test -f {SITE}/frontend/dist/index.html && echo built") == "built"


def test_initial_user_can_log_in(smoke_host: SmokeHost, deployed: Deployed) -> None:
    form = f"username=smoke-admin&password={deployed.password}"
    code = smoke_host.run(
        "curl -s -o /dev/null -w '%{http_code}' --data @- http://127.0.0.1:9999/token", input=form
    ).stdout
    assert code == "200"


def test_database_role_logs_in_with_the_password(smoke_host: SmokeHost, deployed: Deployed) -> None:
    password = deployed.secrets["postgres_password"]
    # psql reads the password from PGPASSWORD set inside the remote shell, never from argv.
    psql = "psql -XAtq -h 127.0.0.1 -U fastdeploy -d fastdeploy -c 'select 1'"
    script = f"PGPASSWORD={shlex.quote(password)} exec {psql}"
    assert smoke_host.run("sh -s", input=script).stdout.strip() == "1"
    owner = "select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'public'"
    assert smoke_host.out(f"runuser -u postgres -- psql -XAtq -d fastdeploy -c {shlex.quote(owner)}") == "fastdeploy"


def test_legacy_token_user_exists(smoke_host: SmokeHost, deployed: Deployed) -> None:
    query = "select count(*) from \"user\" where name in ('smoke-admin', 'ops-control')"
    assert smoke_host.out(f"runuser -u postgres -- psql -XAtq -d fastdeploy -c {shlex.quote(query)}") == "2"


def test_registered_services_and_runners_survive(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out(f"cat {REGISTERED}/deploy.sh") == "#!/bin/sh\necho deployed"
    assert smoke_host.out(f"cat {RUNNER}/marker") == "runner"
    # The sudoers rule lets FastDeploy run a registered deploy.sh as deploy (checked, not run).
    check = f"runuser -u fastdeploy -- sudo -n -l -u deploy {REGISTERED}/deploy.sh --dry"
    assert smoke_host.out(check) == f"{REGISTERED}/deploy.sh --dry"
    assert smoke_host.out("stat -c '%a %U %G' /etc/sudoers.d/fastdeploy") == "440 root root"
    assert smoke_host.out("ls -A /etc/sudoers.d | grep -c '^\\.ops-deploy' || true") == "0"


def test_env_files_are_private(smoke_host: SmokeHost, deployed: Deployed) -> None:
    listing = smoke_host.out(f"stat -c '%a %U %G %n' {SITE}/.env {SITE}/.env.shell")
    for line in listing.splitlines():
        assert line.startswith("600 fastdeploy fastdeploy "), line
    assert smoke_host.out(f"find {SITE} -maxdepth 1 -name '.ops-secret.*'") == ""


def test_traefik_route_requires_auth_from_outside_internal_ranges(smoke_host: SmokeHost, deployed: Deployed) -> None:
    curl = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/users/me"
    assert smoke_host.out(curl) == "401"


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        if key == "initial_user_name":
            continue  # a user name, stored in the database by design
        found = smoke_host.run(
            "grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root /home/fastdeploy /home/deploy "
            "/var/log/postgresql --exclude=.env --exclude=.env.shell || true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
