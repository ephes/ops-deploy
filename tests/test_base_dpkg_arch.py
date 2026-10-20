from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import DpkgArchRemoveConfig, deploy_dpkg_arch_remove
from ops_deploy.helpers.probes import FAILED
from ops_deploy.testing import run_deploy_fake
from tests.fakehost import LINUX

DEBIAN = {**LINUX, "command -v apt-get": ["/usr/bin/apt-get"]}
FOREIGN = "dpkg --print-foreign-architectures"
INSTALLED = "dpkg-query -W"


def run(cfg: DpkgArchRemoveConfig, foreign: list[str], installed: list[str] | None = None) -> Any:
    responses: dict[str, Any] = {**DEBIAN, FOREIGN: foreign}
    if installed is not None:
        responses[INSTALLED] = installed
    return run_deploy_fake(deploy_dpkg_arch_remove, cfg, responses=responses)


def test_no_foreign_target_reads_only_the_architectures() -> None:
    result = run(DpkgArchRemoveConfig(), foreign=["armhf"])

    assert result.succeeded, result.error
    assert result.ops == []
    assert result.executed_commands == []
    # Packages are only listed when a target architecture is configured.
    assert not any(INSTALLED in command for command in result.fact_commands)


def test_converged_host_without_foreign_architectures_changes_nothing() -> None:
    result = run(DpkgArchRemoveConfig(), foreign=[])

    assert result.succeeded, result.error
    assert result.ops == []


def test_removes_a_present_target_without_packages_and_updates_the_cache() -> None:
    result = run(DpkgArchRemoveConfig(), foreign=["i386"], installed=["bash amd64", "tzdata all"])

    assert result.succeeded, result.error
    assert result.executed_commands == ["dpkg --remove-architecture i386", "apt-get update"]
    assert any("dpkg-query -W -f='${Package} ${Architecture}\\n'" in command for command in result.fact_commands)


def test_update_cache_false_only_removes() -> None:
    result = run(DpkgArchRemoveConfig(update_cache=False), foreign=["i386"], installed=["bash amd64"])

    assert result.executed_commands == ["dpkg --remove-architecture i386"]


def test_only_targets_that_are_configured_are_removed_in_target_order() -> None:
    cfg = DpkgArchRemoveConfig(targets=("armhf", "i386", "arm64"), update_cache=False)

    result = run(cfg, foreign=["  i386 ", "armhf"], installed=["bash amd64"])

    assert result.executed_commands == ["dpkg --remove-architecture armhf", "dpkg --remove-architecture i386"]


def test_packages_of_a_target_fail_before_any_change() -> None:
    cfg = DpkgArchRemoveConfig(targets=("armhf", "i386"))
    installed = ["bash amd64", "libc6 i386", "zlib1g i386", "i386-helper amd64"]

    result = run(cfg, foreign=["i386", "armhf"], installed=installed)

    assert not result.succeeded
    message = str(result.error)
    assert "found packages for architecture 'i386': libc6:i386, zlib1g:i386." in message
    assert "purging is not supported" in message
    assert "armhf'" not in message
    assert "i386-helper" not in message
    # armhf has no packages, but nothing is removed while i386 blocks.
    assert result.ops == []
    assert result.executed_commands == []


def test_a_failing_architecture_probe_fails_before_any_change() -> None:
    result = run(DpkgArchRemoveConfig(), foreign=[FAILED])

    assert "cannot read the foreign architectures" in str(result.error)
    assert result.ops == []


def test_a_failing_package_listing_fails_before_any_change() -> None:
    result = run(DpkgArchRemoveConfig(), foreign=["i386"], installed=["bash amd64", FAILED])

    assert "cannot read the installed packages" in str(result.error)
    assert result.ops == []


def test_refuses_hosts_without_apt() -> None:
    result = run_deploy_fake(deploy_dpkg_arch_remove, DpkgArchRemoveConfig(), responses=LINUX)

    assert "needs a Debian-family host" in str(result.error)
    assert not any(FOREIGN in command for command in result.fact_commands)


def test_refuses_non_linux_hosts() -> None:
    result = run_deploy_fake(deploy_dpkg_arch_remove, DpkgArchRemoveConfig(), responses={"uname -s": ["Darwin"]})

    assert "supports Linux hosts only" in str(result.error)


@pytest.mark.parametrize(
    ("targets", "expected"),
    [
        ("i386", ("i386",)),
        ([" i386 ", "", "armhf", "i386"], ("i386", "armhf")),
        ((), ()),
    ],
)
def test_targets_are_normalized_like_the_role(targets: Any, expected: tuple[str, ...]) -> None:
    assert DpkgArchRemoveConfig(targets=targets).targets == expected


@pytest.mark.parametrize("overrides", [{"purge_packages": True}, {"autoremove": True}])
def test_package_removal_is_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="not supported"):
        DpkgArchRemoveConfig(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"targets": ("I386",)},
        {"targets": ("-i386",)},
        {"targets": ("i386;reboot",)},
        {"targets": ("i 386",)},
        {"targets": (386,)},
        {"targets": 386},
        {"update_cache": "maybe"},
        {"purge": True},
    ],
)
def test_rejects_invalid_config(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DpkgArchRemoveConfig(**overrides)
