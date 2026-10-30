from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import UvInstallConfig, deploy_uv_install
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

X86 = {**LINUX, "uname -m": ["x86_64"]}
SHA_X86 = "f68d291c75783122dad58ab77def0e13f3233f358731db5d6d7e8715603b928f"


def installed(version: str) -> dict[str, Any]:
    return {"/usr/local/bin/uv --version": [f"uv {version} (x86_64-unknown-linux-gnu)"]}


def install_command(run: Any) -> str:
    (command,) = [c for c in run.executed_commands if "release.tar.gz" in c]
    return str(command)


def test_installs_verified_release_when_missing() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=X86)

    assert run.succeeded, run.error
    command = install_command(run)
    assert "https://github.com/astral-sh/uv/releases/download/0.13.5/uv-x86_64-unknown-linux-gnu.tar.gz" in command
    assert f"echo {SHA_X86}'  '\"$tmp/release.tar.gz\" | sha256sum -c --quiet -" in command
    # Checksum first, then each binary staged and renamed into place, then a version check.
    assert command.index("sha256sum") < command.index("install -o root -g root -m 0755")
    assert "&& mv -f /usr/local/bin/.uv.ops-deploy-new /usr/local/bin/uv" in command
    assert "&& mv -f /usr/local/bin/.uvx.ops-deploy-new /usr/local/bin/uvx" in command
    assert command.endswith("&& /usr/local/bin/uv --version")


def test_same_version_changes_nothing() -> None:
    responses = {
        **X86,
        **installed("0.13.5"),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.file("/usr/local/bin/uvx", "binary", mode="-rwxr-xr-x"),
    }

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_other_version_is_replaced_unless_updates_are_off() -> None:
    responses = {
        **X86,
        **installed("0.9.0"),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.file("/usr/local/bin/uvx", "binary", mode="-rwxr-xr-x"),
    }

    assert "release.tar.gz" in "\n".join(
        run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses).executed_commands
    )
    kept = run_deploy_fake(deploy_uv_install, UvInstallConfig(update_existing=False), responses=responses)
    assert kept.changed_ops == []


def test_symlinked_uv_is_replaced() -> None:
    responses = {**X86, **installed("0.13.5"), **fakehost.symlink("/usr/local/bin/uv", "/root/.local/bin/uv")}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)

    assert install_command(run)


def test_force_reinstall() -> None:
    responses = {**X86, **installed("0.13.5")}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(force_reinstall=True), responses=responses)

    assert install_command(run)


def test_arm_host_uses_the_aarch64_archive() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**LINUX, "uname -m": ["aarch64"]})

    assert "uv-aarch64-unknown-linux-gnu.tar.gz" in install_command(run)


def test_unpinned_architecture_fails_before_any_change() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**LINUX, "uname -m": ["riscv64"]})

    assert "no pinned checksum for unsupported-unknown-linux-gnu" in str(run.error)
    assert run.executed_commands == []


def test_refuses_macos() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={"uname -s": ["Darwin"]})

    assert "Linux hosts only" in str(run.error)


@pytest.mark.parametrize(
    "overrides",
    [{"install_dir": "/"}, {"install_dir": "relative"}, {"version": "latest"}, {"checksums": {"x": "nothex"}}],
)
def test_rejects_invalid_config(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UvInstallConfig(**overrides)


def test_missing_uvx_is_reinstalled() -> None:
    responses = {**X86, **installed("0.13.5"), **fakehost.directory("/usr/local/bin")}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)

    assert install_command(run)


def test_installs_curl_when_missing() -> None:
    responses = {**X86, "command -v curl": [], "command -v apt-get": ["/usr/bin/apt-get"]}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)

    assert run.succeeded, run.error
    assert any("apt-get" in c and "curl" in c for c in run.executed_commands)
