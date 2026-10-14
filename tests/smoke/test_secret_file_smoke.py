"""``secret_file`` fault and leak tests on a real host.

The interrupted-upload cases run the exact host command ``secret_file``
yields (:func:`install_command`) over SSH, so the stream can be cut or the
session killed at a chosen point.
"""

from __future__ import annotations

import secrets
import signal
import subprocess
import time
from collections.abc import Iterator
from pathlib import PurePosixPath

import pytest
from pyinfra.api import deploy

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_file
from ops_deploy.ops.secret_file import encode_payload, install_command, temp_pattern, temp_tag
from ops_deploy.testing import run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

DIR = PurePosixPath("/root/ops-deploy-smoke-secrets")
DEST = DIR / "app.env"
OLD = "OLD=unchanged\n"


@pytest.fixture
def secret_dir(smoke_host: SmokeHost) -> Iterator[PurePosixPath]:
    smoke_host.run(f"rm -rf {DIR} && install -d -m 0755 {DIR} && printf %s '{OLD}' > {DEST} && chmod 0644 {DEST}")
    yield DIR
    smoke_host.run(f"rm -rf {DIR}")


def marker() -> str:
    return f"smoke-secret-{secrets.token_hex(16)}"


def leftovers(host: SmokeHost) -> str:
    return host.out(f"find {DIR} -mindepth 1 -maxdepth 1 -name '{temp_pattern(DEST)}'")


def assert_untouched(host: SmokeHost) -> None:
    assert host.out(f"cat {DEST}") == OLD.strip()
    assert host.out(f"stat -c %a {DEST}") == "644"
    assert leftovers(host) == ""


def assert_nowhere_in_tmp(host: SmokeHost, value: str) -> None:
    found = host.run("grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm || true", input=f"{value}\n")
    assert found.stdout.strip() == ""


def test_truncated_stream_leaves_destination_untouched(smoke_host: SmokeHost, secret_dir: PurePosixPath) -> None:
    content = SecretContent(f"TOKEN={marker()}\n" * 50)
    payload = encode_payload(content)

    # Cut at a line boundary, as pyinfra writes stdin line by line.
    lines = payload.splitlines(keepends=True)
    result = smoke_host.run(
        install_command(DEST, len(content), mode="0600"), input="".join(lines[: len(lines) // 2]), check=False
    )

    assert result.returncode == 1
    assert "interrupted upload" in result.stderr
    assert_untouched(smoke_host)


def test_killed_ssh_session_mid_stream_leaves_destination_untouched(
    smoke_host: SmokeHost, secret_dir: PurePosixPath
) -> None:
    value = marker()
    content = SecretContent(f"TOKEN={value}\n" * 2000)
    payload = encode_payload(content).encode()
    command = install_command(DEST, len(content), mode="0600")

    proc = subprocess.Popen(
        smoke_host.ssh_argv(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert proc.stdin is not None
    proc.stdin.write(payload[: len(payload) // 3])
    proc.stdin.flush()
    # Wait until the installer is reading on the host, then cut the session.
    deadline = time.monotonic() + 30
    while "python3 -I -c" not in smoke_host.out("ps -eo args"):
        assert time.monotonic() < deadline, "installer never started"
        time.sleep(0.2)
    proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=10)

    deadline = time.monotonic() + 30
    while "python3 -I -c" in smoke_host.out("ps -eo args"):
        assert time.monotonic() < deadline, "installer still running after the session died"
        time.sleep(0.2)
    assert_untouched(smoke_host)
    assert_nowhere_in_tmp(smoke_host, value)


def test_failed_rename_removes_staging(smoke_host: SmokeHost, secret_dir: PurePosixPath) -> None:
    # A non-empty directory at the destination makes the final rename fail.
    blocked = DIR / "blocked"
    smoke_host.run(f"mkdir {blocked} && touch {blocked}/keep")
    content = SecretContent(f"TOKEN={marker()}\n")

    result = smoke_host.run(
        install_command(blocked, len(content), mode="0600"), input=encode_payload(content), check=False
    )

    assert result.returncode == 1
    assert smoke_host.out(f"ls {blocked}") == "keep"
    assert smoke_host.out(f"find {DIR} -name '{temp_pattern(blocked)}'") == ""
    assert_untouched(smoke_host)


@deploy("Smoke secret")
def install_secret(content: SecretContent) -> None:
    secret_file(name="Install smoke secret", path=DEST, content=content, user="nobody", group="nogroup", mode="0600")


def test_deploy_replaces_leftovers_and_writes_0600(smoke_host: SmokeHost, secret_dir: PurePosixPath) -> None:
    # What a run killed after staging leaves behind: a private staging dir.
    stale = DIR / f".ops-secret.{temp_tag(DEST)}.0123456789abcdef"
    smoke_host.run(f"install -d -m 0700 {stale} && printf stale > {stale}/content")
    value = marker()
    content = SecretContent(f"TOKEN={value}\n")

    first = run_deploy_ssh(install_secret, content, host_name=smoke_host.name, host_data=smoke_host.host_data)
    TIMINGS["secret_file deploy"] = first.seconds
    second = run_deploy_ssh(install_secret, content, host_name=smoke_host.name, host_data=smoke_host.host_data)

    assert first.succeeded, first.error
    assert first.changed_ops == ["Smoke secret | Install smoke secret"]
    assert second.succeeded, second.error
    assert second.changed_ops == []
    assert smoke_host.out(f"cat {DEST}") == f"TOKEN={value}"
    assert smoke_host.out(f"stat -c '%a %U %G' {DEST}") == "600 nobody nogroup"
    assert leftovers(smoke_host) == ""
    assert_nowhere_in_tmp(smoke_host, value)
    assert value not in smoke_host.out("journalctl -q --no-pager -n 2000 || true")
