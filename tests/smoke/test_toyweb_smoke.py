"""Deploy toyweb to the smoke target twice: real end state, then a converged rerun."""

from __future__ import annotations

import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.toyweb import ToywebConfig, deploy_toyweb
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

APP_SOURCE = Path(__file__).parents[2] / "smoke" / "toyweb_app"
HOST = "toyweb.example.invalid"
SITE = "/home/toyweb/site"


@dataclass(frozen=True)
class Deployed:
    cfg: ToywebConfig
    secrets: SecretValues
    first: SshRun
    second: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    source = tmp_path_factory.mktemp("toyweb") / "app"
    shutil.copytree(APP_SOURCE, source, ignore=shutil.ignore_patterns("__pycache__"))
    ref = SecretRef("secrets/smoke/toyweb.yml")
    cfg = ToywebConfig(source_path=source, secrets=ref)
    # Fresh values each session: the first run must rewrite the .env and the
    # route, and the leak checks look for values no earlier run could have left.
    values = SecretValues(
        ref,
        {
            "basic_auth_password": f"smoke-pw-{secrets.token_hex(12)}",
            "django_secret_key": f"smoke-key-{secrets.token_hex(24)}",
        },
    )

    first = run_deploy_ssh(deploy_toyweb, cfg, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
    TIMINGS["toyweb first run"] = first.seconds
    assert first.succeeded, first.error
    second = run_deploy_ssh(deploy_toyweb, cfg, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
    TIMINGS["toyweb second run"] = second.seconds
    return Deployed(cfg, values, first, second)


def test_first_run_changes_the_host(deployed: Deployed) -> None:
    assert deployed.first.mutating_changed_ops
    assert any(name.endswith("| Write .env") for name in deployed.first.changed_ops)


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert deployed.second.succeeded, deployed.second.error
    assert deployed.second.mutating_changed_ops == []
    # The health checks still ran (and are reported as read-only).
    assert any(op.read_only and op.succeeded for op in deployed.second.ops)


def test_service_is_running(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active toyweb.service") == "active"
    assert smoke_host.out("systemctl is-enabled toyweb.service") == "enabled"
    assert smoke_host.out(f"curl -fsS -H 'Host: {HOST}' http://127.0.0.1:{deployed.cfg.app_port}/") == "toyweb ok"


def test_migrations_are_applied(smoke_host: SmokeHost, deployed: Deployed) -> None:
    # ``migrate --check`` exits non-zero while any migration is unapplied.
    script = "set -a; . ../.env; set +a; exec ../.venv/bin/python manage.py migrate --check"
    smoke_host.run(f"cd {SITE}/app && runuser -u toyweb -- sh -c '{script}'")
    assert smoke_host.out(f"stat -c %U {SITE}/app/db.sqlite3") == "toyweb"


def test_env_file_is_private(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/.env") == "600 toyweb toyweb"
    assert smoke_host.out(f"find {SITE} -maxdepth 1 -name '.ops-secret.*'") == ""


def test_traefik_route_requires_auth_from_outside_internal_ranges(smoke_host: SmokeHost, deployed: Deployed) -> None:
    # 127.0.0.1 is not in the internal ranges, so the authenticated router applies.
    curl = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/"
    assert smoke_host.out(curl) == "401"
    password = deployed.secrets["basic_auth_password"]
    # The password goes on curl's stdin config, never on a command line.
    authed = smoke_host.run(f"{curl} --config -", input=f'user = "admin:{password}"\n')
    assert authed.stdout.strip() == "200"


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key in ("basic_auth_password", "django_secret_key"):
        value = deployed.secrets[key]
        found = smoke_host.run(
            "grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root /home/toyweb --exclude=.env || true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
    # Only the bcrypt hash reaches the route, never the password.
    route = smoke_host.out("cat /etc/traefik/dynamic/toyweb.yml")
    assert deployed.secrets["basic_auth_password"] not in route
    assert "admin:$2y$05$" in route
