import base64

import pytest
from pydantic import ValidationError

from ops_deploy.base import AuthorizedKey, SshAuthorizedKeyEntriesConfig, deploy_ssh_authorized_key_entries
from ops_deploy.base.ssh_authorized_key_entries import reconcile_authorized_keys
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqkxFNiNn9mPTgZIQJX7CSkm16TBsxgodykb4BXKpjL"
OLD = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTestsOnly000000000000"
CFG = SshAuthorizedKeyEntriesConfig(user="root", home="/root", group="root", present=(AuthorizedKey(key=KEY),))


def test_foreign_lines_and_forced_commands_preserved_byte_for_byte() -> None:
    foreign = (f'# Ansible header\r\n\r\ncommand="echo {KEY}",no-pty {OLD} foreign\r\n\xff not utf8\n').encode("latin1")
    updated = reconcile_authorized_keys(foreign, CFG)
    assert updated == foreign + (KEY + "\n").encode()
    assert reconcile_authorized_keys(updated, CFG) == updated


def test_absent_removes_all_matches_and_present_collapses_duplicates() -> None:
    cfg = CFG.model_copy(update={"absent": (AuthorizedKey(key=OLD),)})
    original = f"{OLD} one\nno-pty {OLD} two\n{KEY} old\n{KEY} duplicate\n# keep\n".encode()
    assert reconcile_authorized_keys(original, cfg) == f"{KEY}\n# keep\n".encode()


def test_option_change_and_quoted_spaces() -> None:
    cfg = CFG.model_copy(update={"present": (AuthorizedKey(key=KEY, key_options='from="100.64.0.1"', comment="new"),)})
    original = f'command="echo \\"hello world\\"",no-pty {KEY} old\r\n\r\n'.encode()
    assert reconcile_authorized_keys(original, cfg) == f'from="100.64.0.1" {KEY} new\n\r\n'.encode()


def test_crlf_blank_lines_and_missing_final_newline() -> None:
    content = f"# header\r\n\r\n{KEY}\r\n\r\n# last".encode()
    assert reconcile_authorized_keys(content, CFG) == content
    assert reconcile_authorized_keys(b"# last", CFG) == f"# last\n{KEY}\n".encode()


@pytest.mark.parametrize(("home", "user", "group"), [("/root", "root", "root"), ("/Users/jochen", "jochen", "staff")])
def test_deploy_atomic_permissions_and_idempotence(home: str, user: str, group: str) -> None:
    cfg = CFG.model_copy(update={"home": home, "user": user, "group": group})
    first = run_deploy_fake(deploy_ssh_authorized_key_entries, cfg, responses=LINUX)
    assert first.succeeded, first.error
    assert any(f"0600 {user} {group}" in c for c in first.executed_commands)
    assert f"chmod 700 {home}/.ssh" in first.executed_commands
    content = f"# header\r\n\r\n{KEY}\r\n"
    responses = {
        **LINUX,
        **fakehost.stat(f"{home}/.ssh", user=user, group=group, mode="drwx------"),
        **fakehost.file(f"{home}/.ssh/authorized_keys", content, user=user, mode="-rw-------"),
        **fakehost.stat(f"{home}/.ssh/authorized_keys", user=user, group=group, mode="-rw-------"),
        f"base64 < {home}/.ssh/authorized_keys": [base64.b64encode(content.encode()).decode()],
    }
    second = run_deploy_fake(deploy_ssh_authorized_key_entries, cfg, responses=responses)
    assert second.succeeded, second.error
    assert second.changed_ops == []


@pytest.mark.parametrize(
    "patch",
    [
        {"present": ()},
        {"absent": (AuthorizedKey(key=KEY),)},
        {"present": (AuthorizedKey(key="bad"),)},
        {"present": (AuthorizedKey(key=KEY), AuthorizedKey(key=KEY, comment="dup"))},
    ],
)
def test_invalid_sets_refused(patch: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SshAuthorizedKeyEntriesConfig.model_validate({**CFG.model_dump(), **patch})
