"""Actual PostgreSQL/Dovecot fixture, explicitly provisioned using smoke/mail-monitoring-bootstrap.sh."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.mail_monitoring import MailMonitoringConfig, deploy_mail_monitoring
from ops_deploy.testing import run_deploy_ssh
from tests.smoke.conftest import SmokeHost

pytestmark = pytest.mark.skipif(os.environ.get("MAIL_MONITORING_FIXTURE") != "1", reason="needs owned mail fixture")


def test_mailbox_rotation_repeat_and_role_metadata(smoke_host: SmokeHost) -> None:
    # The bootstrap marker is installed only on the disposable mail fixture.
    smoke_host.run("test -f /etc/ops-deploy-mail-fixture")
    cfg = MailMonitoringConfig(
        address="smoke@example.test",
        schema_mode="postfixadmin",
        site_path="/var/lib/mail-fixture",
        cleanup_enabled=False,
        relay_probe_enabled=False,
        relay_probe_service_name="smoke-mail-relay",
    )
    ref = SecretRef("fixture.yml")
    initial = SecretValues(ref, {"monitor_password": "fixture-smoke-initial"})
    rotated = SecretValues(ref, {"monitor_password": "fixture-smoke-rotated"})

    def run(values: SecretValues) -> int:
        result = run_deploy_ssh(
            deploy_mail_monitoring, cfg, values, host_name=smoke_host.name, host_data=smoke_host.host_data
        )
        assert result.succeeded, str(result.error)
        return len(result.mutating_changed_ops)

    run(initial)
    assert run(initial) == 0
    # Actual Dovecot SQL authentication, against synthetic credentials only.
    smoke_host.run("doveadm auth test smoke@example.test fixture-smoke-initial >/dev/null 2>&1")
    assert smoke_host.out("stat -c '%u:%g %a' /var/lib/mail-fixture/example.test/smoke") == "5000:5000 700"
    assert run(rotated) == 1
    assert run(rotated) == 0
    smoke_host.run("doveadm auth test smoke@example.test fixture-smoke-rotated >/dev/null 2>&1")
    assert (
        smoke_host.run(
            "doveadm auth test smoke@example.test fixture-smoke-initial >/dev/null 2>&1", check=False
        ).returncode
        != 0
    )
    # Both missing domain and ambiguous mailbox must fail before row mutation.
    script = (Path(__file__).parents[2] / "src/ops_deploy/services/mail_monitoring/files/mailbox.py").read_text()
    import json

    command = shlex.join(["runuser", "-u", "postgres", "--", "python3", "-I", "-c", script, "apply"])
    before = smoke_host.out("runuser -u postgres -- psql -d mail -Atc 'SELECT count(*) FROM mailbox'")
    result = smoke_host.run(
        command,
        input=json.dumps(
            {
                "address": "missing@absent.test",
                "password": "fixture",
                "schema_mode": "postfixadmin",
                "database": "mail",
                "active": True,
            }
        ),
        check=False,
    )
    assert result.returncode != 0
    assert "domain missing or ambiguous" in result.stderr

    assert smoke_host.out("runuser -u postgres -- psql -d mail -Atc 'SELECT count(*) FROM mailbox'") == before
    smoke_host.run(
        "runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d mail",
        input="""
        DELETE FROM mail_users WHERE localpart='ambiguous';
        INSERT INTO mail_users(domain_id,localpart,password,active)
        SELECT id, 'ambiguous', 'fixture-verifier', true FROM mail_domains WHERE name='example.test';
        INSERT INTO mail_users(domain_id,localpart,password,active)
        SELECT id, 'ambiguous', 'fixture-verifier', true FROM mail_domains WHERE name='example.test';
    """,
    )
    before = smoke_host.out("runuser -u postgres -- psql -d mail -Atc 'SELECT count(*) FROM mail_users'")
    result = smoke_host.run(
        command,
        input=json.dumps(
            {
                "address": "ambiguous@example.test",
                "password": "fixture",
                "schema_mode": "legacy",
                "database": "mail",
                "active": True,
            }
        ),
        check=False,
    )
    assert result.returncode != 0
    assert "mailbox identity is ambiguous" in result.stderr
    assert smoke_host.out("runuser -u postgres -- psql -d mail -Atc 'SELECT count(*) FROM mail_users'") == before
