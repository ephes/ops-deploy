"""``secret_file`` against the fake connector: commands, gating and leaks."""

import base64
import hashlib
import shlex
from pathlib import PurePosixPath
from typing import Any

import pytest
from pyinfra.api import deploy
from pyinfra.connectors.fake import FakeConnector

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_file
from ops_deploy.ops.secret_file import INSTALLER_SOURCE, temp_pattern, temp_tag
from ops_deploy.testing import run_deploy_fake

DEST = "/etc/app/secrets.env"
SECRET = "API_TOKEN=hunter2-s3cr3t\n"
CONTENT = SecretContent(SECRET)


@deploy("Secrets")
def secrets_deploy(content: SecretContent = CONTENT, **options: Any) -> None:
    secret_file(name="Write secrets", path=DEST, content=content, **options)


@deploy("Secrets")
def unnamed_deploy() -> None:
    secret_file(path=DEST, content=CONTENT, user="app", group="app")


def present(*, content: bytes = SECRET.encode(), mode: str = "-rw-------", user: str = "root") -> dict[str, Any]:
    stat = f"user={user} group={user} mode={mode} atime=0 mtime=0 ctime=0 size={len(content)} '{DEST}'"
    return {
        f"sha256sum {DEST} ": f"{hashlib.sha256(content).hexdigest()}  {DEST}",
        f"test -e {DEST} ||": stat,
    }


def test_absent_file_is_written_over_stdin_only() -> None:
    run = run_deploy_fake(secrets_deploy)

    assert run.succeeded, run.error
    assert run.changed_ops == ["Secrets | Write secrets"]
    assert run.uploads == []
    [(command, stdin)] = run.stdin
    assert command in run.executed_commands
    assert base64.b64decode(stdin) == SECRET.encode()
    assert "hunter2" not in run.all_text()


def test_command_runs_the_installer_with_metadata_only() -> None:
    run = run_deploy_fake(secrets_deploy, user="app", group="www", mode="0640")

    [(command, _)] = run.stdin
    argv = shlex.split(command)
    assert argv[:3] == ["python3", "-I", "-c"]
    assert argv[3] == INSTALLER_SOURCE
    tag = temp_tag(PurePosixPath(DEST))
    assert argv[4:] == ["/etc/app", "secrets.env", tag, str(len(SECRET)), "0640", "app", "www"]


def test_stdin_command_never_inherits_a_pty_or_another_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []
    original = FakeConnector.run_shell_command

    def spy(self: FakeConnector, command: Any, *args: Any, **kwargs: Any) -> Any:
        if kwargs.get("_stdin") is not None:
            seen.append(kwargs)
        return original(self, command, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", spy)

    @deploy("Pty")
    def pty_deploy() -> None:
        secret_file(name="Write", path=DEST, content=CONTENT, _get_pty=True, _shell_executable="bash")

    run = run_deploy_fake(pty_deploy)

    assert run.succeeded, run.error
    [kwargs] = seen
    assert kwargs["_get_pty"] is False
    assert kwargs["_shell_executable"] == "sh"


def test_secret_never_appears_in_op_arguments_of_unnamed_op() -> None:
    run = run_deploy_fake(unnamed_deploy)

    assert run.succeeded, run.error
    [op] = run.ops
    assert "content=SecretContent(<redacted>)" in op.args
    assert "hunter2" not in run.all_text()


def test_up_to_date_file_is_a_noop() -> None:
    run = run_deploy_fake(secrets_deploy, responses=present())

    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert run.executed_commands == []
    assert run.stdin == []


@pytest.mark.parametrize(
    ("state", "options"),
    [
        ({"content": b"API_TOKEN=old\n"}, {}),
        ({"mode": "-rw-r--r--"}, {}),
        ({"user": "nobody"}, {"user": "root"}),
        ({}, {"mode": "0640"}),
    ],
    ids=["content", "mode", "owner", "wanted-mode"],
)
def test_drift_rewrites_the_file(state: dict[str, Any], options: dict[str, Any]) -> None:
    run = run_deploy_fake(secrets_deploy, responses=present(**state), **options)

    assert run.changed_ops == ["Secrets | Write secrets"]
    assert len(run.stdin) == 1
    assert "hunter2" not in run.all_text()


def test_leftover_temp_files_trigger_the_installer_even_when_up_to_date() -> None:
    pattern = temp_pattern(PurePosixPath(DEST))
    leftover = f"/etc/app/{pattern[:-1]}Ab12Cd34"
    responses = {"find /etc/app -type d": [leftover], **present()}

    run = run_deploy_fake(secrets_deploy, responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == ["Secrets | Write secrets"]
    assert len(run.stdin) == 1


@pytest.mark.parametrize("name", ["token[1].env", "*.env", "a?b"])
def test_temp_pattern_has_no_glob_metacharacters(name: str) -> None:
    pattern = temp_pattern(PurePosixPath("/etc/app") / name)

    assert pattern.endswith(".*")
    assert not set(pattern[:-1]) & set("*?[]\\")


def test_binary_content_round_trips() -> None:
    blob = bytes(range(256)) * 3
    run = run_deploy_fake(secrets_deploy, content=SecretContent(blob))

    [(command, stdin)] = run.stdin
    assert base64.b64decode(stdin) == blob
    assert shlex.split(command)[7] == str(len(blob))


def test_directory_at_destination_fails() -> None:
    responses = {f"test -e {DEST} ||": f"user=root group=root mode=drwx------ atime=0 mtime=0 ctime=0 size=0 '{DEST}'"}

    run = run_deploy_fake(secrets_deploy, responses=responses)

    assert not run.succeeded
    assert "not a regular file" in str(run.error)


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"path": "relative/secret"}, "absolute file path"),
        ({"path": "/etc/app/../secret"}, "absolute file path"),
        ({"mode": "644; rm -rf /"}, "mode must be octal"),
        ({"user": "app; id"}, "not a valid name"),
        ({"content": "hunter2-plain"}, "must be a SecretContent"),
    ],
)
def test_invalid_arguments_are_rejected(options: dict[str, Any], message: str) -> None:
    @deploy("Bad")
    def bad() -> None:
        secret_file(name="Bad", **{"path": DEST, "content": CONTENT, **options})

    run = run_deploy_fake(bad)

    assert not run.succeeded
    assert message in str(run.error)
    assert "hunter2" not in str(run.error)


def test_secret_content_is_redacted_and_unpicklable() -> None:
    import pickle

    assert "hunter2" not in repr(CONTENT)
    assert "hunter2" not in str(CONTENT)
    assert "hunter2" not in f"{CONTENT}"
    with pytest.raises(TypeError, match="must not be pickled"):
        pickle.dumps(CONTENT)
