from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import NodejsInstallConfig, deploy_nodejs_install
from ops_deploy.base.nodejs_install import PREFERENCES
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

APT = {**LINUX, "command -v apt-get": ["/usr/bin/apt-get"]}
SOURCES = "deb [signed-by=/etc/apt/keyrings/nodesource.asc] https://deb.nodesource.com/node_24.x nodistro main\n"


def converged(version: str = "24.13.1-1nodesource1") -> dict[str, Any]:
    return {
        **APT,
        "dpkg-query -W -f '${Status} ${Version}' nodejs": [f"install ok installed {version}"],
        **fakehost.directory("/etc/apt/keyrings"),
        **fakehost.file("/etc/apt/keyrings/nodesource.asc", "key"),
        **fakehost.directory("/etc/apt/sources.list.d"),
        **fakehost.directory("/etc/apt/preferences.d"),
        **fakehost.file("/etc/apt/sources.list.d/nodesource.list", SOURCES),
        **fakehost.file("/etc/apt/preferences.d/nodesource", PREFERENCES),
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed("ca-certificates"),
    }


def test_first_run_configures_repository_and_installs_major() -> None:
    run = run_deploy_fake(deploy_nodejs_install, NodejsInstallConfig(), responses=APT)

    assert run.succeeded, run.error
    assert run.upload("/etc/apt/sources.list.d/nodesource.list") == SOURCES.encode()
    assert run.upload("/etc/apt/preferences.d/nodesource") == PREFERENCES.encode()
    commands = run.executed_commands
    assert any("https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key" in c for c in commands)
    assert "DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades 'nodejs=24.*'" in commands
    assert commands.index("apt-get update -q") < commands.index(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades 'nodejs=24.*'"
    )


def test_converged_host_only_runs_the_read_only_check() -> None:
    run = run_deploy_fake(deploy_nodejs_install, NodejsInstallConfig(), responses=converged())

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.changed_ops == ["Install Node.js | Check Node.js is v24.x"]


def test_other_major_is_switched() -> None:
    run = run_deploy_fake(deploy_nodejs_install, NodejsInstallConfig(major=22), responses=converged())

    assert (
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades 'nodejs=22.*'" in run.executed_commands
    )
    assert run.upload("/etc/apt/sources.list.d/nodesource.list") == SOURCES.replace("node_24", "node_22").encode()


def test_removed_package_with_leftover_config_is_installed() -> None:
    responses = {**converged(), "dpkg-query -W -f '${Status} ${Version}' nodejs": ["deinstall ok config-files 24.1.0"]}

    run = run_deploy_fake(deploy_nodejs_install, NodejsInstallConfig(), responses=responses)

    assert "apt-get update -q" in run.executed_commands


def test_check_fails_the_deploy_on_the_wrong_node() -> None:
    responses = {**converged(), "/usr/bin/node --version": {"success": False, "stderr": "expected v24.x"}}

    run = run_deploy_fake(deploy_nodejs_install, NodejsInstallConfig(), responses=responses)

    assert not run.succeeded


def test_refuses_non_debian_host() -> None:
    run = run_deploy_fake(deploy_nodejs_install, NodejsInstallConfig(), responses=LINUX)

    assert "Debian-family" in str(run.error)


@pytest.mark.parametrize("overrides", [{"major": 0}, {"major": "24.x"}, {"key_url": "http://x"}, {"keyring": "rel"}])
def test_rejects_invalid_config(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        NodejsInstallConfig(**overrides)
