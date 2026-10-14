import pytest
from pydantic import ValidationError

from ops_deploy.base import HostnameConfig, deploy_hostname
from ops_deploy.testing import run_deploy_fake
from tests.fakehost import LINUX

HOSTNAMECTL = {"command -v hostnamectl": ["/usr/bin/hostnamectl"]}


def test_sets_hostname_when_it_differs() -> None:
    run = run_deploy_fake(
        deploy_hostname, HostnameConfig(hostname="web-1"), responses={**LINUX, **HOSTNAMECTL, "uname -n": ["old"]}
    )

    assert run.succeeded, run.error
    assert run.executed_commands == ["hostnamectl set-hostname web-1"]


def test_converged_host_changes_nothing() -> None:
    run = run_deploy_fake(
        deploy_hostname, HostnameConfig(hostname="web-1"), responses={**LINUX, **HOSTNAMECTL, "uname -n": ["web-1"]}
    )

    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert run.executed_commands == []


@pytest.mark.parametrize("name", ["", "-leading-dash", "with space", "semi;colon"])
def test_rejects_invalid_hostnames(name: str) -> None:
    with pytest.raises(ValidationError):
        HostnameConfig(hostname=name)
