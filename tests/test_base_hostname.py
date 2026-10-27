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


@pytest.mark.parametrize("drift", [None, "HostName", "ComputerName", "LocalHostName"])
def test_darwin_checks_all_three_names_and_converges_together(drift: str | None) -> None:
    responses = {
        "uname -s": ["Darwin"],
        **{
            f"/usr/sbin/scutil --get {key}": ["old" if key == drift else "studio"]
            for key in ("HostName", "ComputerName", "LocalHostName")
        },
    }
    run = run_deploy_fake(deploy_hostname, HostnameConfig(hostname="studio"), responses=responses)
    assert run.succeeded, run.error
    assert run.executed_commands == (
        []
        if drift is None
        else [f"/usr/sbin/scutil --set {key} studio" for key in ("HostName", "ComputerName", "LocalHostName")]
    )
    assert run.uploaded_paths == []


@pytest.mark.parametrize(
    ("name", "local"), [("web.test", "webtest"), ("web_name", "web-name"), ("web--name", "webname"), ("web-", "web")]
)
def test_darwin_uses_authoritative_ansible_scrub(name: str, local: str) -> None:
    from ops_deploy.base.hostname import darwin_local_hostname

    assert darwin_local_hostname(name) == local


def test_unset_darwin_hostname_is_drift_not_a_failed_fact() -> None:
    command = "/usr/sbin/scutil --get HostName 2>/dev/null || true"
    run = run_deploy_fake(
        deploy_hostname,
        HostnameConfig(hostname="fixture"),
        responses={
            "uname -s": ["Darwin"],
            command: [],
            "/usr/sbin/scutil --get ComputerName": ["old"],
            "/usr/sbin/scutil --get LocalHostName": ["old"],
        },
    )
    assert run.succeeded, run.error
    assert any(command in fact for fact in run.fact_commands)
    assert run.executed_commands == [
        f"/usr/sbin/scutil --set {key} fixture" for key in ("HostName", "ComputerName", "LocalHostName")
    ]
