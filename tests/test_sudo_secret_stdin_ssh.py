"""Standard sudo prompt/secret-stdin plumbing in an owned no-network SSH fixture."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import shlex
import subprocess
from pathlib import Path

import pytest
from pyinfra.api import Config, Inventory, State, StringCommand, deploy
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.connectors import util

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin
from tests.test_base_ssh_guard_docker import Container


def test_standard_sudo_command_masks_password_and_leaves_stdin_for_payload() -> None:
    password = secrets.token_hex(24)
    command = util.make_unix_command(
        StringCommand("cat"), _sudo=True, _sudo_password=password, _sudo_askpass_path="/tmp/fixture-askpass"
    )
    masked = command.get_masked_value()
    if password in masked:
        pytest.fail("standard connector exposed the fixture password")
    assert "SUDO_ASKPASS=" in masked
    assert "sudo -H -A -k" in masked
    assert command.get_raw_value() != masked


@pytest.mark.skipif(not os.environ.get("SSH_GUARD_DOCKER_CONTAINER"), reason="no owned SSH container")
def test_real_ssh_prompt_uses_standard_askpass_without_consuming_secret_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    box = Container()
    user = "opsstdin" + secrets.token_hex(4)
    password = secrets.token_hex(24)
    key = tmp_path / "fixture-key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True, capture_output=True)
    box.sh(
        f"useradd -m -s /bin/sh {user}; "
        f"install -d -o {user} -g {user} -m 0700 /home/{user}/.ssh; "
        f"printf '%s ALL=(root) ALL\\n' {user} > /etc/sudoers.d/{user}; "
        f"chmod 0440 /etc/sudoers.d/{user}"
    )
    subprocess.run(
        [box.binary, "exec", "-i", box.identifier, "chpasswd"],
        input=user + ":" + password + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        [
            box.binary,
            "exec",
            "-i",
            box.identifier,
            "sh",
            "-c",
            f"cat > /home/{user}/.ssh/authorized_keys; "
            f"chown {user}:{user} /home/{user}/.ssh/authorized_keys; "
            f"chmod 0600 /home/{user}/.ssh/authorized_keys",
        ],
        input=key.with_suffix(".pub").read_text(),
        text=True,
        capture_output=True,
        check=True,
    )
    config = tmp_path / "ssh-config"
    config.write_text(
        "Host fixture\n  ProxyCommand "
        + shlex.join([box.binary, "exec", "-i", box.identifier, "nc", "127.0.0.1", "22"])
        + "\n"
    )
    payload = secrets.token_hex(32)
    expected = hashlib.sha256((payload + "\n").encode()).hexdigest()
    script = (
        "import hashlib,os,sys; assert os.geteuid()==0; assert hashlib.sha256(sys.stdin.buffer.read()).hexdigest()=="
        + repr(expected)
    )

    @deploy("Owned sudo stdin")
    def subject() -> None:
        secret_stdin(
            name="Verify privileged secret stdin",
            command=shlex.join(["python3", "-c", script]),
            content=SecretContent(payload + "\n"),
        )

    prompts: list[str] = []

    def prompt(message: str) -> str:
        prompts.append(message)
        return password

    monkeypatch.setattr(util, "getpass", prompt)
    caplog.set_level(logging.DEBUG)
    data = {
        "ssh_hostname": "fixture",
        "ssh_user": user,
        "ssh_key": str(key),
        "ssh_config_file": str(config),
        "ssh_known_hosts_file": str(tmp_path / "known-hosts"),
        "ssh_strict_host_key_checking": "accept-new",
        "ssh_allow_agent": False,
        "ssh_look_for_keys": False,
    }
    state = State(Inventory(([("fixture", data)], {})), Config(SUDO=True))
    try:
        connect_all(state)
        assert state.activated_hosts
        add_deploy(state, subject)
        run_ops(state)
        from ops_deploy.testing.harness import collect_ops

        operations = collect_ops(state, "fixture")
        assert operations
        assert all(op.succeeded for op in operations)
        assert prompts
        host = state.inventory.get_host("fixture")
        assert host is not None
        if host.connector_data.get("prompted_sudo_password") != password:
            pytest.fail("standard connector did not retain the prompted credential in memory")
    finally:
        disconnect_all(state)
        box.sh(f"rm -f /etc/sudoers.d/{user}; userdel -r {user}")
    output = capsys.readouterr()
    logs = output.out + output.err + caplog.text
    if password in logs or payload in logs:
        pytest.fail("connector leaked fixture input")
