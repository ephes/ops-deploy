"""Deploy chesslab to the smoke target: database guard, real end state, converged rerun.

Needs a chess (chesslab) checkout: ``CHESSLAB_SOURCE``, else ``$PROJECTS_ROOT/chess``.
Its committed ``HEAD`` is exported, so local databases and uncommitted files
never reach the VM. The Echoport/Nyxmon wiring is off here (neither runs on the
VM); the fake-connector tests cover it.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.chesslab import ChesslabConfig, deploy_chesslab
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "chess.example.invalid"
HOME = "/home/chesslab"
DB = f"{HOME}/data/chess.db"


def chesslab_checkout() -> Path | None:
    configured = os.environ.get("CHESSLAB_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "chess" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: ChesslabConfig
    secrets: SecretValues
    guarded: SshRun
    first: SshRun
    second: SshRun
    fresh_clone: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = chesslab_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no chess checkout (set CHESSLAB_SOURCE or PROJECTS_ROOT)")
    if smoke_host.out(f"test -e {DB} && echo present || true") == "present":
        pytest.skip(f"{DB} already exists on the smoke target; the guard check needs a host without it")
    source = tmp_path_factory.mktemp("chess")
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive.stdout, check=True)
    ref = SecretRef("secrets/smoke/chesslab.yml")
    cfg = ChesslabConfig(
        source_path=source,
        secrets=ref,
        traefik_host=HOST,
        django_allowed_hosts=("127.0.0.1", "localhost", HOST),
        django_csrf_trusted_origins=(f"https://{HOST}",),
    )
    users = [{"username": "smoke-trainer", "password": f"smoke-user-{secrets.token_hex(12)}", "owner": "Smoke_Owner"}]
    values = SecretValues(
        ref,
        {
            "session_secret": f'smoke-key-{secrets.token_hex(24)}$`"x',
            "users": json.dumps(users),
            "basic_auth_password": f"smoke-pw-{secrets.token_hex(12)}",
        },
    )

    def deploy(label: str, config: ChesslabConfig) -> SshRun:
        run = run_deploy_ssh(deploy_chesslab, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"chesslab {label} run"] = run.seconds
        return run

    # Like the role: no database, no deploy (the site is left alone).
    guarded = deploy("guard", cfg)
    assert not guarded.succeeded
    # The database comes from elsewhere in production; here an empty SQLite file.
    smoke_host.run(f"runuser -u chesslab -- touch {DB}")
    fresh = tmp_path_factory.mktemp("chess-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=archive.stdout, check=True)
    runs = []
    for label, config in (
        ("first", cfg),
        ("second", cfg),
        ("fresh clone", cfg.model_copy(update={"source_path": fresh})),
    ):
        run = deploy(label, config)
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    return Deployed(cfg, values, guarded, *runs)


def test_missing_database_stops_the_deploy(deployed: Deployed) -> None:
    assert not any(name.endswith("| Sync chesslab source") for name in deployed.guarded.changed_ops)


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Write .env") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_fresh_clone_of_unchanged_code_is_a_noop(deployed: Deployed) -> None:
    assert deployed.fresh_clone.mutating_changed_ops == []


def test_service_runs_and_is_healthy(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active chesslab") == "active"
    assert smoke_host.out("systemctl is-enabled chesslab") == "enabled"
    assert '"ok": true' in smoke_host.out("curl -s http://127.0.0.1:10019/healthz")


def test_env_is_private_and_users_exist(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out(f"stat -c '%a %U %G' {HOME}/site/.env") == "600 chesslab chesslab"
    assert smoke_host.out(f"stat -c '%a %U %G' {HOME}/.ops-deploy-users") == "600 root root"
    query = "select u.is_superuser, p.lichess_username from auth_user u join accounts_profile p on p.user_id = u.id"
    assert smoke_host.out(f"sqlite3 -readonly {DB} '{query}'") == "1|smoke_owner"


def test_traefik_serves_internal_clients_and_guards_the_rest(smoke_host: SmokeHost, deployed: Deployed) -> None:
    curl = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/healthz"
    # 127.0.0.1/32 is one of chesslab's internal ranges: no auth from the host itself.
    assert smoke_host.out(curl) == "200"
    route = smoke_host.out("cat /etc/traefik/dynamic/chesslab.yml")
    assert "chesslab-ext:" in route
    assert '- "admin:$2y$05$' in route


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        if key == "users":
            continue
        found = smoke_host.run(
            f"grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root {HOME} --exclude=.env --exclude='chess.db*' "
            "|| true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
    password = json.loads(deployed.secrets["users"])[0]["password"]
    found = smoke_host.run(f"grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root {HOME} || true", input=password)
    assert found.stdout.strip() == ""
    assert deployed.secrets["basic_auth_password"] not in smoke_host.out("cat /etc/traefik/dynamic/chesslab.yml")


def test_port_preflight_refuses_another_listener(smoke_host: SmokeHost, deployed: Deployed) -> None:
    smoke_host.run("systemctl stop chesslab")
    squatter = "systemd-run --unit=chesslab-port-squatter python3 -m http.server 10019 --bind 127.0.0.1"
    smoke_host.run(f"{squatter} && sleep 1")
    try:
        run = run_deploy_ssh(
            deploy_chesslab,
            deployed.cfg,
            deployed.secrets,
            host_name=smoke_host.name,
            host_data=smoke_host.host_data,
        )
        assert not run.succeeded
        failed = [op.name for op in run.ops if not op.succeeded]
        assert failed
        assert failed[0] == "Deploy chesslab | Port preflight tcp/10019"
        assert run.mutating_changed_ops == []
    finally:
        smoke_host.run("systemctl stop chesslab-port-squatter; systemctl start chesslab", check=False)
    assert smoke_host.out("systemctl is-active chesslab") == "active"
