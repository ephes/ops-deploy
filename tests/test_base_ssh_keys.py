from pathlib import Path

import jinja2
import pytest
from pydantic import ValidationError

from ops_deploy.base import AuthorizedKey, SshAuthorizedKeysConfig, deploy_ssh_authorized_keys
from ops_deploy.base.ssh_authorized_keys import render_authorized_keys
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

VENDORED = Path(__file__).parent / "parity" / "ansible"
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTestsOnly000000000000"
ENTRIES = (
    AuthorizedKey(key=KEY, comment="operator"),
    AuthorizedKey(key=f"  {KEY}2 ", comment=" backup ", key_options='command="/usr/local/sbin/x.sh",no-pty'),
    AuthorizedKey(key=f"{KEY}3"),
)


def render_ansible(entries: list[dict[str, str]]) -> str:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(VENDORED), trim_blocks=True, keep_trailing_newline=True)
    template = env.get_template("ssh_authorized_keys_manage__authorized_keys.j2")
    return template.render(ssh_authorized_keys_manage_entries=entries)


def test_rendering_matches_the_role() -> None:
    cfg = SshAuthorizedKeysConfig(entries=ENTRIES)
    as_role = [entry.model_dump() for entry in ENTRIES]

    assert render_authorized_keys(cfg) == render_ansible(as_role)
    assert render_authorized_keys(cfg).splitlines()[1:] == [
        f"{KEY} operator",
        f'command="/usr/local/sbin/x.sh",no-pty {KEY}2 backup',
        f"{KEY}3",
    ]


def test_first_run_creates_ssh_dir_and_installs_file_atomically() -> None:
    cfg = SshAuthorizedKeysConfig(entries=ENTRIES)

    run = run_deploy_fake(deploy_ssh_authorized_keys, cfg, responses=LINUX)

    assert run.succeeded, run.error
    assert "mkdir -p /root/.ssh" in run.executed_commands
    assert "chmod 700 /root/.ssh" in run.executed_commands
    (install,) = [command for command in run.executed_commands if "python3 -I -c" in command]
    assert "/root/.ssh authorized_keys" in install
    assert "0600 root root" in install
    # The content goes over stdin (base64), never into a command or upload.
    assert run.uploads == []
    assert KEY not in run.all_text()


def test_converged_host_changes_nothing() -> None:
    cfg = SshAuthorizedKeysConfig(entries=ENTRIES)
    responses = {
        **LINUX,
        **fakehost.directory("/root/.ssh", mode="drwx------"),
        **fakehost.file("/root/.ssh/authorized_keys", render_authorized_keys(cfg), mode="-rw-------"),
    }

    run = run_deploy_fake(deploy_ssh_authorized_keys, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_non_root_user_defaults() -> None:
    cfg = SshAuthorizedKeysConfig(user="deploy", entries=ENTRIES[:1])

    run = run_deploy_fake(deploy_ssh_authorized_keys, cfg, responses=LINUX)

    assert "chown deploy:deploy /home/deploy/.ssh" in run.executed_commands
    assert any("0600 deploy deploy" in command for command in run.executed_commands)


@pytest.mark.parametrize(
    "entries",
    [(), ({"key": " "},), ({"key": "ssh-ed25519 AAA\nssh-rsa BBB"},), ({"key": KEY, "comment": "a\nb"},)],
)
def test_rejects_empty_or_multiline_entries(entries: tuple[dict[str, str], ...]) -> None:
    with pytest.raises(ValidationError):
        SshAuthorizedKeysConfig.model_validate({"entries": entries})
