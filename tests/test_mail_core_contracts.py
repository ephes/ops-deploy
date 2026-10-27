"""Mail core admission contracts that refuse before any host is touched."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import SecretStr
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta

from ops_deploy.core.config import ConfigValidationError
from ops_deploy.services.mail_backend import MailBackendConfig
from ops_deploy.services.mail_backend.config import DomainAlias
from ops_deploy.services.mail_backend.deploy import _catalog
from ops_deploy.services.mail_spam import MailSpamConfig
from ops_deploy.services.mail_spam.config import MonitoringProbe
from ops_deploy.testing import run_deploy_fake


def probe(source: str) -> MonitoringProbe:
    return MonitoringProbe(
        source_ip=source, sender="probe@example.test", recipient="monitor@example.test", subject_prefix="[probe]"
    )


@pytest.mark.parametrize("source", ["192.168.104.1", "10.1.2.3", "127.0.0.1", "100.64.0.9"])
def test_spam_probe_source_inside_local_or_relay_networks_refuses(source: str) -> None:
    # Sanitized config errors withhold the message; the control isolates the cause.
    MailSpamConfig(local_addrs_extra=("100.64.0.9/32",))
    with pytest.raises(ConfigValidationError, match="MailSpamConfig"):
        MailSpamConfig(monitoring_probe=probe(source), local_addrs_extra=("100.64.0.9/32",))


def test_spam_probe_external_source_is_admitted() -> None:
    config = MailSpamConfig(monitoring_probe=probe("100.64.0.10"), local_addrs_extra=("100.64.0.9/32",))
    assert config.monitoring_probe is not None


def test_legacy_domain_alias_needs_hosted_alias_domain() -> None:
    mapping = DomainAlias(alias_domain="alias.test", target_domain="example.test")
    with pytest.raises(ConfigValidationError, match="MailBackendConfig"):
        MailBackendConfig(domains=("example.test",), postfixadmin_domain_aliases=(mapping,))
    MailBackendConfig(domains=("example.test", "alias.test"), postfixadmin_domain_aliases=(mapping,))
    MailBackendConfig(domains=("example.test",), schema_mode="postfixadmin", postfixadmin_domain_aliases=(mapping,))


@pytest.mark.parametrize("pending", [False, True])
def test_catalog_skips_probe_when_a_prerequisite_such_as_the_role_is_pending(pending: bool) -> None:
    @deploy("Owned catalog")
    def owned() -> None:
        _catalog(
            name="Reconcile core mail catalog",
            prerequisites=cast(
                "tuple[OperationMeta, ...]",
                (SimpleNamespace(will_change=False), SimpleNamespace(will_change=pending)),
            ),
            payload=SecretStr("{}"),
        )

    run = run_deploy_fake(owned, responses={"python3 -I -c": '{"state": "current"}'})
    assert run.succeeded, run.error
    checks = [command for command in run.fact_commands if "' check" in command]
    applies = [command for command in run.executed_commands if "' apply" in command]
    assert (bool(checks), len(applies)) == ((False, 1) if pending else (True, 0))


def test_backend_refuses_legacy_forwards_and_unrendered_sql_port() -> None:
    from ops_deploy.services.mail_backend.config import ForwardAlias

    forward = ForwardAlias(address="hallo@example.test", destinations=("dest@remote.test",))
    MailBackendConfig(domains=("example.test",), schema_mode="postfixadmin", forward_aliases=(forward,))
    with pytest.raises(ConfigValidationError, match="MailBackendConfig"):
        MailBackendConfig(domains=("example.test",), forward_aliases=(forward,))
    with pytest.raises(ConfigValidationError, match="MailBackendConfig"):
        MailBackendConfig(domains=("example.test",), postgres_port=5433)
