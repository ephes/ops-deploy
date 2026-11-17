"""The pinned ``mc`` install shared by the Echoport deploy and the runner registrations."""

from __future__ import annotations

import shlex

from ops_deploy.services._echoport.mc import (
    MC_DOWNLOAD_URL,
    MC_PATH,
    MC_SHA256,
    MC_VERSION,
    binary_install_command,
    install_mc,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost


def test_the_pin_is_the_linux_amd64_release() -> None:
    assert MC_VERSION == "RELEASE.2025-08-13T08-35-41Z"
    assert MC_SHA256 == "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
    assert MC_DOWNLOAD_URL == (
        "https://github.com/minio/mc/releases/download/RELEASE.2025-08-13T08-35-41Z/"
        "mc.linux-amd64.RELEASE.2025-08-13T08-35-41Z"
    )
    assert MC_PATH == "/usr/local/bin/mc"


def test_an_installed_pinned_mc_changes_nothing() -> None:
    run = run_deploy_fake(install_mc, responses=fakehost.mc_installed())

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert not any("curl" in command for command in run.executed_commands)


def test_a_wrong_owner_or_mode_is_fixed_without_a_download() -> None:
    responses = {
        **fakehost.mc_installed(),
        **fakehost.stat(MC_PATH, user="echoport", mode="-rwxrwxrwx"),
    }
    run = run_deploy_fake(install_mc, responses=responses)

    assert run.succeeded, run.error
    assert [name.split(" | ")[-1] for name in run.mutating_changed_ops] == ["Preserve pinned MinIO client executable"]
    assert not any("curl" in command for command in run.executed_commands)


def test_a_missing_or_different_mc_is_downloaded_and_verified() -> None:
    for responses in ({}, {f"sha256sum {MC_PATH} ": [f"{'0' * 64}  {MC_PATH}"]}):
        run = run_deploy_fake(install_mc, responses=responses)

        assert run.succeeded, run.error
        assert [name.split(" | ")[-1] for name in run.mutating_changed_ops] == ["Download pinned MinIO client"]
        assert any(MC_SHA256 in command for command in run.executed_commands)


def test_the_download_is_verified_before_it_replaces_the_file() -> None:
    script = shlex.split(binary_install_command(MC_PATH, MC_SHA256, MC_DOWNLOAD_URL))[2]

    assert script.startswith("set -eu; umask 077; tmp=$(mktemp -d /usr/local/bin/.minio-artifact.XXXXXX); ")
    parts = ("curl -fsSL", "sha256sum -c --status -", "install -o root -g root -m 0755")
    order = [script.index(part) for part in parts]
    assert order == sorted(order)
    assert script.endswith('mv -f "$tmp/binary" /usr/local/bin/mc')
