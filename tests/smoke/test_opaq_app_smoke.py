"""Deploy opaq_app to the smoke target twice: real end state, then a converged rerun.

Needs a daybook checkout: ``DAYBOOK_SOURCE``, else ``$PROJECTS_ROOT/daybook``. Its
committed ``HEAD`` is exported, so local databases and uncommitted files never
reach the VM. The Echoport and Nyxmon upserts need those services on the host
and are covered by the coexistence smoke in ops-control.
"""

from __future__ import annotations

import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.opaq_app import OpaqAppConfig, deploy_opaq_app
from ops_deploy.services.opaq_app.deploy import RouteChecks
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "opaq.example.invalid"
HOME = "/home/opaq-app"
CURL = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443"


def daybook_checkout() -> Path | None:
    configured = os.environ.get("DAYBOOK_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "daybook" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: OpaqAppConfig
    secrets: SecretValues
    first: SshRun
    second: SshRun
    fresh_clone: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = daybook_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no daybook checkout (set DAYBOOK_SOURCE or PROJECTS_ROOT)")
    source = tmp_path_factory.mktemp("daybook")
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive.stdout, check=True)
    address = smoke_host.out("hostname -I").split()[0]
    ref = SecretRef("secrets/smoke/opaq_app.yml")
    cfg = OpaqAppConfig(
        source_path=source,
        secrets=ref,
        traefik_host=HOST,
        # Loopback is admitted, the host's own address is not.
        allowed_networks=("127.0.0.0/8",),
        route_checks=RouteChecks(refused_address=address, verify_tls=False),
    )
    values = SecretValues(
        ref,
        {
            "django_secret_key": f"smoke-key-{secrets.token_hex(32)}",
            "upload_token": f"smoke-upload-{secrets.token_hex(24)}",
        },
    )
    # The same commit exported again with fresh mtimes (``tar -m``), as a new clone has.
    fresh = tmp_path_factory.mktemp("daybook-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=archive.stdout, check=True)
    runs = []
    fresh_cfg = cfg.model_copy(update={"source_path": fresh})
    for label, config in (("first", cfg), ("second", cfg), ("fresh clone", fresh_cfg)):
        run = run_deploy_ssh(deploy_opaq_app, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"opaq_app {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    return Deployed(cfg, values, *runs)


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Write environment file") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_fresh_clone_of_unchanged_code_is_a_noop(deployed: Deployed) -> None:
    assert deployed.fresh_clone.mutating_changed_ops == []


def test_unit_runs_hardened(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active opaq-app") == "active"
    assert smoke_host.out("systemctl is-enabled opaq-app") == "enabled"
    assert smoke_host.out("systemctl show -p ProtectSystem --value opaq-app") == "strict"
    assert smoke_host.out("curl -s http://127.0.0.1:10065/healthz") == "ok"


def test_tree_database_and_env_are_private(smoke_host: SmokeHost, deployed: Deployed) -> None:
    listing = smoke_host.out(
        f"stat -c '%a %U %G %n' {HOME} {HOME}/data {HOME}/data/db.sqlite3 {HOME}/static {HOME}/opaq-app.env"
    )
    assert listing
    for line in listing.splitlines():
        mode = line.split()[0]
        assert mode in ("600", "700"), line
        assert line.split()[1:3] == ["opaq-app", "opaq-app"], line
    # The venv, the Python install and the collected static files (public
    # content) sit behind the 0700 home and static directory.
    tree = f"{HOME}/site {HOME}/data"
    assert smoke_host.out(f"find {tree} \\( -perm /077 -o ! -user opaq-app \\) | head") == ""
    assert smoke_host.out(f"find {HOME} -name '.ops-secret.*'") == ""


def test_migrations_are_applied(smoke_host: SmokeHost, deployed: Deployed) -> None:
    script = (
        f"set -a; . {HOME}/opaq-app.env; set +a; "
        f"cd {HOME}/site/services/opaq_app && exec {HOME}/venv/bin/python manage.py migrate --check"
    )
    smoke_host.run(f"runuser -u opaq-app -- bash -c '{script}'")


def test_allowlist_then_login(smoke_host: SmokeHost, deployed: Deployed) -> None:
    address = smoke_host.out("hostname -I").split()[0]
    # Admitted source: the app sends an anonymous visitor to the login.
    answer = smoke_host.out(
        f"curl -ks -o /dev/null -w '%{{http_code}} %{{redirect_url}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/"
    )
    assert answer == f"302 https://{HOST}/login/?next=/"
    assert smoke_host.out(f"{CURL}:{address} https://{HOST}/login/") == "403"


def test_no_secret_on_disk_outside_its_file(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        found = smoke_host.run(
            f"grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root {HOME} "
            "--exclude=opaq-app.env --exclude=db.sqlite3 || true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
    route = smoke_host.out("cat /etc/traefik/dynamic/opaq-app.yml")
    for value in deployed.secrets.values():
        assert value not in route
