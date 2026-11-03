import base64
import hashlib
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import AuthorizedKey, SshAuthorizedKeyEntriesConfig, deploy_ssh_authorized_key_entries
from ops_deploy.base.ssh_authorized_key_entries import AuthorizedKeysFile, key_material, merge_authorized_keys
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

ROOT_FILE = "/root/.ssh/authorized_keys"
HEADER = "# Managed by Ansible - local.ops_library.ssh_authorized_keys_manage\n"


def key(seed: int, key_type: str = "ssh-ed25519") -> str:
    """A syntactically valid public key line without comment."""

    name = key_type.encode()
    blob = len(name).to_bytes(4, "big") + name + (32).to_bytes(4, "big") + bytes([seed]) * 32
    return f"{key_type} {base64.b64encode(blob).decode()}"


A, B, C, D = key(1), key(2), key(3), key(4)
FORCED = f'command="/usr/local/libexec/echoport-command-guard",restrict,from="100.93.155.101" {D} deploy@macmini'


def config(**overrides: Any) -> SshAuthorizedKeyEntriesConfig:
    values: dict[str, Any] = {
        "user": "root",
        "group": "root",
        "home": "/root",
        "present": (AuthorizedKey(key=f"{A} studio"),),
    }
    values.update(overrides)
    return SshAuthorizedKeyEntriesConfig(**values)


def host_file(path: str, content: bytes, *, user: str = "root", group: str = "root") -> dict[str, Any]:
    """The ``AuthorizedKeysFile`` fact plus stat/sha256 facts ``secret_file`` reads."""

    text = content.decode("utf-8", "surrogateescape")
    responses = fakehost.file(path, text, user=user, mode="-rw-------")
    stat = f"user={user} group={group} mode=-rw------- atime=0 mtime=0 ctime=0 size=10 '{path}'"
    responses[f"test -e {path} ||"] = [stat]
    responses[f"if [ -L {path} ]"] = ["file", *base64.encodebytes(content).decode().splitlines()]
    responses[f"sha256sum {path} "] = [f"{hashlib.sha256(content).hexdigest()}  {path}"]
    return responses


def written(run: Any, path: str = ROOT_FILE) -> bytes:
    (content,) = [data for dest, data in run.secret_files if dest == path]
    return bytes(content)


# --- merge -----------------------------------------------------------------


def test_matches_by_key_material_not_comment_or_options() -> None:
    assert key_material(f"{A} one") == key_material(f'no-pty,command="x y" {A} other')
    assert key_material("# comment") is None
    assert key_material("") is None
    assert key_material("not a key line") is None
    assert key_material("ssh-ed25519 !!!notbase64") is None


def test_foreign_lines_and_header_stay_byte_for_byte() -> None:
    existing = f"{HEADER}{FORCED}\n# a note\n\n{B} jochen@meos\n".encode()

    merged = merge_authorized_keys(existing, [f"{A} studio"], [])

    assert merged == existing + f"{A} studio\n".encode()


def test_second_run_is_idempotent() -> None:
    once = merge_authorized_keys(f"{HEADER}{FORCED}\n".encode(), [f"{A} studio"], [f"{C} old"])

    assert merge_authorized_keys(once, [f"{A} studio"], [f"{C} old"]) == once


def test_absent_removes_every_line_with_that_key() -> None:
    existing = f"{C} old\n{FORCED}\nrestrict {C} copy\n{A} studio\n".encode()

    merged = merge_authorized_keys(existing, [f"{A} studio"], [f"{C} whatever-comment"])

    assert merged == f"{FORCED}\n{A} studio\n".encode()


def test_option_or_comment_change_rewrites_in_place() -> None:
    existing = f"{FORCED}\nno-pty {A} laptop\n{B} other\n".encode()

    merged = merge_authorized_keys(existing, [f'from="100.82.50.50" {A} studio'], [])

    assert merged == f'{FORCED}\nfrom="100.82.50.50" {A} studio\n{B} other\n'.encode()


def test_duplicates_collapse_to_one_line() -> None:
    existing = f"{A} first\n{B} other\n{A} second\nno-pty {A} third\n".encode()

    merged = merge_authorized_keys(existing, [f"{A} studio"], [])

    assert merged == f"{A} studio\n{B} other\n".encode()


def test_crlf_blank_lines_and_missing_final_newline() -> None:
    existing = f"{HEADER}\r\n\r\n{B} meos\r\n{C} old\r\n   \n{FORCED}".encode()

    merged = merge_authorized_keys(existing, [f"{A} studio", f"{B} jochen@meos"], [C])

    assert merged == (f"{HEADER}\r\n\r\n{B} jochen@meos\r\n   \n{FORCED}\n{A} studio\n").encode()


def test_unchanged_present_line_without_final_newline_stays() -> None:
    existing = f"{FORCED}\n{A} studio".encode()

    assert merge_authorized_keys(existing, [f"{A} studio"], []) == existing


def test_non_utf8_and_unparsable_lines_survive() -> None:
    existing = b"\xff\xfe garbage\nssh-ed25519 not-base64!\n" + f"{A} studio\n".encode()

    assert merge_authorized_keys(existing, [f"{A} studio"], [C]) == existing


def test_missing_file_gets_only_the_present_keys() -> None:
    assert merge_authorized_keys(b"", [f"{A} studio", B], []) == f"{A} studio\n{B}\n".encode()


# --- config ----------------------------------------------------------------


def test_empty_present_set_is_refused() -> None:
    with pytest.raises(ValidationError):
        config(present=())


def test_empty_present_set_needs_the_explicit_flag() -> None:
    cfg = config(present=(), absent=(C,), allow_empty_present=True)
    assert cfg.present_lines() == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"present": (AuthorizedKey(key="not a key"),)},
        {"present": (AuthorizedKey(key=A), AuthorizedKey(key=A, comment="again"))},
        {"absent": (f"{A} same key",)},
        {"absent": ("garbage",)},
        {"absent": (f"{C}\nssh-rsa x",)},
        {"home": "relative/path"},
        {"user": None},
    ],
)
def test_invalid_configs_are_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**overrides)


def test_home_and_group_are_required() -> None:
    with pytest.raises(ValidationError):
        SshAuthorizedKeyEntriesConfig.model_validate({"user": "root", "present": [{"key": A}]})


# --- deploy ----------------------------------------------------------------


def test_fact_reads_the_file_base64_encoded() -> None:
    fact = AuthorizedKeysFile()
    assert "base64 < /root/.ssh/authorized_keys" in fact.command(ROOT_FILE)
    payload = base64.encodebytes(b"a\r\nb").decode().splitlines()
    assert fact.process(["file", *payload]) == ("file", b"a\r\nb")
    assert fact.process(["missing"]) == ("missing", b"")


def test_first_run_on_linux_preserves_foreign_lines() -> None:
    existing = f"{HEADER}{FORCED}\n".encode()
    responses = {**LINUX, **fakehost.directory("/root/.ssh", mode="drwx------"), **host_file(ROOT_FILE, existing)}

    run = run_deploy_fake(deploy_ssh_authorized_key_entries, config(absent=(C,)), responses=responses)

    assert run.succeeded, run.error
    assert written(run) == existing + f"{A} studio\n".encode()
    (install,) = [command for command in run.executed_commands if "python3 -I -c" in command]
    assert "/root/.ssh authorized_keys" in install
    assert "0600 root root" in install
    assert run.uploads == []


def test_converged_host_changes_nothing() -> None:
    existing = f"{HEADER}{FORCED}\n{A} studio\n".encode()
    responses = {**LINUX, **fakehost.directory("/root/.ssh", mode="drwx------"), **host_file(ROOT_FILE, existing)}

    run = run_deploy_fake(deploy_ssh_authorized_key_entries, config(absent=(C,)), responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_missing_file_and_ssh_dir_are_created() -> None:
    responses = {**LINUX, "if [ -L /root/.ssh/authorized_keys ]": ["missing"]}

    run = run_deploy_fake(deploy_ssh_authorized_key_entries, config(), responses=responses)

    assert run.succeeded, run.error
    assert "mkdir -p /root/.ssh" in run.executed_commands
    assert "chmod 700 /root/.ssh" in run.executed_commands
    assert written(run) == f"{A} studio\n".encode()


def test_macos_account_uses_given_home_and_group() -> None:
    path = "/Users/jochen/.ssh/authorized_keys"
    existing = f"{FORCED}\n".encode()
    responses = {
        "uname -s": ["Darwin"],
        **fakehost.stat("/Users/jochen/.ssh", user="jochen", group="staff", mode="drwx------"),
        **host_file(path, existing, user="jochen", group="staff"),
    }
    cfg = config(user="jochen", group="staff", home="/Users/jochen")

    run = run_deploy_fake(deploy_ssh_authorized_key_entries, cfg, responses=responses)

    assert run.succeeded, run.error
    assert written(run, path) == existing + f"{A} studio\n".encode()
    (install,) = [command for command in run.executed_commands if "python3 -I -c" in command]
    assert "/Users/jochen/.ssh authorized_keys" in install
    assert "0600 jochen staff" in install
    assert not any("/root" in command for command in run.executed_commands)


def test_macos_root_home() -> None:
    responses = {"uname -s": ["Darwin"], "if [ -L /var/root/.ssh/authorized_keys ]": ["missing"]}
    cfg = config(group="wheel", home="/var/root")

    run = run_deploy_fake(deploy_ssh_authorized_key_entries, cfg, responses=responses)

    assert run.succeeded, run.error
    assert "chown root:wheel /var/root/.ssh" in run.executed_commands
    assert written(run, "/var/root/.ssh/authorized_keys") == f"{A} studio\n".encode()


def test_empty_present_removes_absent_keys_and_keeps_other_lines() -> None:
    path = "/Users/vibe/.ssh/authorized_keys"
    existing = f"{C} jochen@meos\nmoshi-pair: keep\n{B} other\n".encode()
    responses = {
        "uname -s": ["Darwin"],
        **fakehost.stat("/Users/vibe/.ssh", user="vibe", group="vibe", mode="drwx------"),
        **host_file(path, existing, user="vibe", group="vibe"),
    }
    cfg = config(user="vibe", group="vibe", home="/Users/vibe", present=(), absent=(C,), allow_empty_present=True)

    run = run_deploy_fake(deploy_ssh_authorized_key_entries, cfg, responses=responses)

    assert run.succeeded, run.error
    assert written(run, path) == f"moshi-pair: keep\n{B} other\n".encode()


def test_empty_present_can_leave_an_empty_file() -> None:
    existing = f"{C} jochen@meos\n".encode()
    responses = {**LINUX, **fakehost.directory("/root/.ssh", mode="drwx------"), **host_file(ROOT_FILE, existing)}

    run = run_deploy_fake(
        deploy_ssh_authorized_key_entries,
        config(present=(), absent=(C,), allow_empty_present=True),
        responses=responses,
    )

    assert run.succeeded, run.error
    assert written(run) == b""


def test_empty_present_leaves_a_missing_file_missing() -> None:
    responses = {**LINUX, "if [ -L /root/.ssh/authorized_keys ]": ["missing"]}

    run = run_deploy_fake(
        deploy_ssh_authorized_key_entries,
        config(present=(), absent=(C,), allow_empty_present=True),
        responses=responses,
    )

    assert run.succeeded, run.error
    assert run.written_paths == []
    assert not any("mkdir" in command for command in run.executed_commands)


@pytest.mark.parametrize("kind", ["symlink", "other", "unreadable"])
def test_refuses_anything_but_a_regular_file(kind: str) -> None:
    responses = {**LINUX, "if [ -L /root/.ssh/authorized_keys ]": [kind]}

    run = run_deploy_fake(deploy_ssh_authorized_key_entries, config(), responses=responses)

    assert not run.succeeded
    assert run.written_paths == []


def test_options_follow_sshd_escaping() -> None:
    # sshd: \" is an escaped quote; a backslash before anything else is literal.
    line = f'command="x\\\\" y" {C} revoked'
    assert key_material(line) == key_material(C)
    assert merge_authorized_keys(f"{line}\n{A} studio\n".encode(), [f"{A} studio"], [C]) == f"{A} studio\n".encode()
    assert key_material(f'command="echo \\"hi there\\"",no-pty {C}') == key_material(C)


def test_unparsable_line_with_an_absent_key_fails_closed() -> None:
    existing = f'command="never closed {C} revoked\n{A} studio\n'.encode()

    with pytest.raises(ValueError, match="must be removed"):
        merge_authorized_keys(existing, [f"{A} studio"], [C])
    # A comment mentioning the key is not a login line.
    assert merge_authorized_keys(f"# {C}\n".encode(), [A], [C]) == f"# {C}\n{A}\n".encode()


def test_unparsable_line_with_an_absent_key_refuses_the_deploy() -> None:
    existing = f'command="never closed {C} revoked\n'.encode()
    responses = {**LINUX, **fakehost.directory("/root/.ssh", mode="drwx------"), **host_file(ROOT_FILE, existing)}

    run = run_deploy_fake(deploy_ssh_authorized_key_entries, config(absent=(C,)), responses=responses)

    assert not run.succeeded
    assert run.written_paths == []


def test_failed_read_and_unsearchable_ssh_dir_are_refused() -> None:
    assert AuthorizedKeysFile.default() == ("unreadable", b"")
    assert "[ ! -x /root/.ssh ]; then echo unreadable" in AuthorizedKeysFile().command(ROOT_FILE)


def test_only_space_and_tab_separate_fields() -> None:
    # sshd reads "ssh-ed25519\x0c<A>" as an options field and then accepts C.
    line = f"{A.replace(' ', chr(12))} {C} revoked"
    assert key_material(line) == key_material(C)
    assert merge_authorized_keys(f"{line}\n".encode(), [B], [C]) == f"{B}\n".encode()


def test_line_of_another_key_carrying_an_absent_blob_fails_closed() -> None:
    existing = f"{B} comment-with-{C.split()[1]}\n".encode()

    with pytest.raises(ValueError, match="must be removed"):
        merge_authorized_keys(existing, [A], [C])


@pytest.mark.parametrize("separator", ["\x0c", "\x0b", "\r"])
def test_absent_blob_split_by_whitespace_fails_closed(separator: str) -> None:
    # sshd's base64 decoder skips whitespace inside the blob and reads a lone CR as part of the line.
    blob = C.split()[1]
    line = f"ssh-ed25519 {blob[:20]}{separator}{blob[20:]} revoked"

    with pytest.raises(ValueError, match="must be removed"):
        merge_authorized_keys(f"{A} studio\n{line}\n".encode(), [f"{A} studio"], [C])


def test_lone_cr_does_not_split_lines() -> None:
    existing = f"# note\r{B} other\n".encode()

    assert merge_authorized_keys(existing, [A], []) == existing + f"{A}\n".encode()
