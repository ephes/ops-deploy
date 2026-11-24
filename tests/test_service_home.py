"""The building blocks that deploy into a service's home as the service user."""

import logging
import os
import shlex
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from pyinfra.api import deploy

from ops_deploy.helpers import system_user
from ops_deploy.ops.sync_tree import MANDATORY_EXCLUDES
from ops_deploy.services._service_home import (
    _RSYNC_GUARD,
    as_user,
    remote_rsync_command,
    sync_dry_run_as_user,
    sync_tree_as_user,
    trusted_home_check,
    user_directories,
    user_directories_pending,
    uv_sync_as_user,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost

HOME = PurePosixPath("/home/app")
SITE = PurePosixPath("/home/app/site")
ROOT_HOST = {"ssh_hostname": "app.example.invalid"}
REMOTE = (
    "--rsync-path=cd / && runuser -u app -- "
    """sh -c 'test -d "$1" && test ! -L "$1" && shift && exec rsync "$@"' rsync /home/app/site"""
)
ACCOUNT = {**fakehost.system_account("app", "/home/app"), **fakehost.directory("/home/app", user="app")}
DEPLOYED = {**ACCOUNT, **fakehost.directory("/home/app/site", user="app")}


def run(body: Any, responses: dict[str, Any] | None = None, host_data: dict[str, Any] | None = None) -> FakeRun:
    @deploy("Test")
    def _deploy() -> None:
        body()

    return run_deploy_fake(_deploy, responses={**fakehost.LINUX, **(responses or {})}, host_data=host_data or ROOT_HOST)


# --- as_user ------------------------------------------------------------------


def test_as_user_leaves_roots_directory_and_enters_as_the_user() -> None:
    assert as_user("app", HOME, {"A": "1"}, ["uv", "sync"], cwd=SITE) == (
        "cd / && runuser -u app -- env HOME=/home/app A=1 "
        """sh -c 'cd "$1" && shift && exec "$@"' sh /home/app/site uv sync"""
    )
    assert as_user("app", HOME, {}, ["id"]) == "cd / && runuser -u app -- env HOME=/home/app id"


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
def test_entering_runs_the_program_in_the_directory_or_not_at_all(tmp_path: Path) -> None:
    script = 'cd "$1" && shift && exec "$@"'
    inside = subprocess.run(["sh", "-c", script, "sh", str(tmp_path), "pwd", "-P"], capture_output=True, text=True)
    assert inside.stdout.strip() == str(tmp_path.resolve())
    marker = tmp_path / "ran"
    missing = subprocess.run(
        ["sh", "-c", script, "sh", str(tmp_path / "missing"), "touch", str(marker)], capture_output=True, text=True
    )
    assert missing.returncode != 0
    assert not marker.exists()


# --- the home and the directories below it --------------------------------------


def _layout(group: str = "app", directories: tuple[PurePosixPath, ...] = (SITE,), home: PurePosixPath = HOME) -> Any:
    def body() -> None:
        trusted_home_check("app", home)
        system_user("app", group=group, home=home)
        user_directories("app", group, home, directories)

    return body


def test_root_makes_only_the_home_after_the_path_check() -> None:
    result = run(_layout())

    assert result.succeeded, result.error
    commands = result.executed_commands
    check = next(c for c in commands if "-maxdepth 0 -type d -user root ! -perm /022" in c)
    assert "for p in / /home; do" in check
    assert "find /home/app -maxdepth 0 -type d -user app" in check
    assert commands.index(check) < commands.index("groupadd -r app")
    assert [c for c in commands if "mkdir" in c] == [
        "mkdir -p /home/app",
        "cd / && runuser -u app -- mkdir -p -m 0755 /home/app/site",
    ]
    assert not any(c.startswith(("chown", "chmod")) and c.endswith("/home/app/site") for c in commands)
    assert result.op("Test | Check the path to /home/app").read_only


def test_present_directories_are_a_noop() -> None:
    result = run(_layout(), DEPLOYED)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []


def test_the_user_corrects_its_own_mode() -> None:
    responses = {**ACCOUNT, **fakehost.directory("/home/app/site", user="app", mode="drwxrwxr-x")}

    result = run(_layout(), responses)

    assert result.succeeded, result.error
    assert [c for c in result.executed_commands if "find" not in c] == [
        "cd / && runuser -u app -- chmod 0755 /home/app/site"
    ]


@pytest.mark.parametrize(
    ("site", "message"),
    [
        (fakehost.directory("/home/app/site", user="root"), "belongs to root:root"),
        (fakehost.symlink("/home/app/site", "/etc", user="app"), "not a directory"),
        (fakehost.stat("/home/app/site", user="app"), "not a directory"),
    ],
)
def test_root_never_repairs_a_directory_by_path(site: dict[str, Any], message: str) -> None:
    result = run(_layout(), {**ACCOUNT, **site})

    assert not result.succeeded
    assert message in str(result.error)
    assert "Root does not repair it" in str(result.error)
    assert result.executed_commands == []


def test_the_group_must_be_the_accounts_primary_group() -> None:
    result = run(_layout(group="web"), ACCOUNT)

    assert not result.succeeded
    assert "primary group" in str(result.error)
    assert result.executed_commands == []


@pytest.mark.parametrize(
    ("home", "directories", "message"),
    [
        (HOME, (PurePosixPath("/srv/elsewhere"),), "below the home"),
        (HOME, (HOME,), "below the home"),
        (PurePosixPath("/home/my app"), (), "plain normalized absolute path"),
        (HOME, (PurePosixPath("/home/app/$(id)"),), "plain normalized absolute path"),
        (HOME, (PurePosixPath("/home/app/../x"),), "plain normalized absolute path"),
        (PurePosixPath("/"), (), "plain normalized absolute path"),
    ],
)
def test_paths_outside_the_home_or_with_specials_are_rejected(
    home: PurePosixPath, directories: tuple[PurePosixPath, ...], message: str
) -> None:
    result = run(_layout(directories=directories, home=home))

    assert not result.succeeded
    assert message in str(result.error)
    assert result.executed_commands == []


def _pending(responses: dict[str, Any], group: str = "app") -> tuple[FakeRun, list[str]]:
    found: list[str] = []
    result = run(lambda: found.extend(user_directories_pending("app", group, HOME, [SITE])), responses)
    return result, found


@pytest.mark.parametrize(
    ("responses", "expected"),
    [
        (DEPLOYED, []),
        (ACCOUNT, ["/home/app/site is missing"]),
        (
            {**ACCOUNT, **fakehost.directory("/home/app/site", user="app", mode="drwx------")},
            ["/home/app/site is not 0755"],
        ),
        ({}, ["the account app does not exist", "/home/app/site is missing"]),
    ],
    ids=["converged", "missing", "mode", "no account"],
)
def test_pending_directories_are_reported_without_queuing(responses: dict[str, Any], expected: list[str]) -> None:
    result, found = _pending(responses)

    assert result.succeeded, result.error
    assert found == expected
    assert result.ops == []
    assert result.executed_commands == []


def test_pending_directories_refuse_a_symlink_also_without_the_account() -> None:
    result, _ = _pending(fakehost.symlink("/home/app/site", "/etc", user="app"))

    assert not result.succeeded
    assert "not a directory" in str(result.error)


@pytest.mark.parametrize(
    ("user", "path"),
    [("app\n", "/home/app"), ("app", "/home/app\n"), ("app", "/home/app\n/x"), ("app\nroot", "/home/app")],
)
def test_a_trailing_or_embedded_newline_is_not_plain(user: str, path: str) -> None:
    from ops_deploy.services._service_home import require_plain

    with pytest.raises(ValueError, match="not a plain"):
        require_plain(user, PurePosixPath(path))


@pytest.mark.parametrize(("group", "mode"), [("app\n", "0755"), ("app", "0755\n"), ("app", "755 /etc")])
def test_group_and_mode_are_matched_whole(group: str, mode: str) -> None:
    result = run(lambda: user_directories("app", group, HOME, [SITE], mode=mode), ACCOUNT)

    assert not result.succeeded
    assert "plain group name and an octal mode" in str(result.error)
    assert result.executed_commands == []


@pytest.mark.parametrize(
    ("site", "group", "message"),
    [
        (fakehost.symlink("/home/app/site", "/etc", user="app"), "app", "not a directory"),
        (fakehost.directory("/home/app/site", user="root"), "app", "belongs to root:root"),
        (fakehost.directory("/home/app/site", user="app"), "web", "primary group"),
    ],
)
def test_pending_directories_refuse_what_the_operation_refuses(site: dict[str, Any], group: str, message: str) -> None:
    result, _ = _pending({**ACCOUNT, **site}, group)

    assert not result.succeeded
    assert message in str(result.error)


# --- sync_tree_as_user ----------------------------------------------------------


@pytest.fixture
def source(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("print('hi')\n")
    return tmp_path


def _sync(source: Path, rsync: RecordingRsyncRunner, **kwargs: Any) -> Any:
    return lambda: sync_tree_as_user(name="Sync tree", src=source, dest=SITE, user="app", runner=rsync, **kwargs)


def _dry(rsync: RecordingRsyncRunner) -> list[list[str]]:
    return [call for call in rsync.calls if "--dry-run" in call]


def _real(rsync: RecordingRsyncRunner) -> list[list[str]]:
    return [call for call in rsync.calls if "--dry-run" not in call]


def test_the_user_receives_the_dry_run_and_the_transfer(source: Path) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f.st...... app.py"]})

    result = run(_sync(source, rsync, excludes=(".env",)), DEPLOYED)

    assert result.succeeded, result.error
    assert result.function_calls == ["_run_rsync"]
    assert _real(rsync) == [
        [
            "rsync", "-rl", "--checksum", "--omit-dir-times", "--delete", "--no-owner", "--no-group",
            *(f"--exclude={pattern}" for pattern in (*MANDATORY_EXCLUDES, ".env")),
            REMOTE,
            "-e", "ssh", f"{source}/", "root@app.example.invalid:/home/app/site/",
        ]
    ]  # fmt: skip
    (dry,) = _dry(rsync)
    assert REMOTE in dry
    assert not any(arg.startswith("--chown") for call in rsync.calls for arg in call)


def test_no_itemized_change_is_a_noop(source: Path) -> None:
    rsync = RecordingRsyncRunner()

    result = run(_sync(source, rsync), DEPLOYED)

    assert result.succeeded, result.error
    assert result.changed_ops == []
    assert _real(rsync) == []
    assert len(_dry(rsync)) == 1


def test_the_remote_command_is_logged(source: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="pyinfra"):
        run(_sync(source, RecordingRsyncRunner()), DEPLOYED)

    assert any(
        "sync_tree remote command: cd / && runuser -u app -- sh -c" in record.getMessage() for record in caplog.records
    )


@pytest.mark.parametrize(
    "responses",
    [ACCOUNT, fakehost.directory("/home/app/site", user="app"), {}],
    ids=["no destination", "no account", "neither"],
)
def test_a_first_deploy_has_no_dry_run_and_transfers_in_order(source: Path, responses: dict[str, Any]) -> None:
    # Nobody can dry-run as a user that does not exist yet, or into a directory
    # an earlier operation of this deploy creates.
    rsync = RecordingRsyncRunner()

    result = run(_sync(source, rsync), responses)

    assert result.succeeded, result.error
    assert _dry(rsync) == []
    (real,) = _real(rsync)
    assert REMOTE in real
    assert result.changed_ops == ["Test | Sync tree"]


def test_a_destination_that_is_not_a_directory_is_refused(source: Path) -> None:
    rsync = RecordingRsyncRunner()

    result = run(_sync(source, rsync), {**ACCOUNT, **fakehost.symlink("/home/app/site", "/etc", user="app")})

    assert not result.succeeded
    assert "not a directory" in str(result.error)
    assert rsync.calls == []


def test_a_root_connection_is_required(source: Path) -> None:
    rsync = RecordingRsyncRunner()

    result = run(_sync(source, rsync), DEPLOYED, host_data={**ROOT_HOST, "ssh_user": "deploy"})

    assert not result.succeeded
    assert "root connection" in str(result.error)
    assert rsync.calls == []


def test_a_missing_source_is_rejected(tmp_path: Path) -> None:
    rsync = RecordingRsyncRunner()

    result = run(_sync(tmp_path / "missing", rsync), DEPLOYED)

    assert not result.succeeded
    assert "not a directory" in str(result.error)
    assert rsync.calls == []


@pytest.mark.parametrize(
    ("user", "dest", "message"),
    [
        ("app; id", "/srv/app", "plain user or group name"),
        ("-u", "/srv/app", "plain user or group name"),
        ("app", "/srv/my app", "plain normalized absolute path"),
        ("app", "/srv/$(id)", "plain normalized absolute path"),
        ("app", "/srv/../etc", "plain normalized absolute path"),
        ("app", "/", "plain normalized absolute path"),
        ("app", "relative", "plain normalized absolute path"),
    ],
)
def test_names_a_shell_would_read_are_rejected(user: str, dest: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        remote_rsync_command(user, PurePosixPath(dest))


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
@pytest.mark.parametrize(("kind", "runs"), [("directory", True), ("missing", False), ("symlink", False)])
def test_the_guard_only_runs_rsync_in_a_real_directory(tmp_path: Path, kind: str, runs: bool) -> None:
    dest = tmp_path / "dest"
    if kind == "directory":
        dest.mkdir()
    elif kind == "symlink":
        (tmp_path / "real").mkdir()
        dest.symlink_to(tmp_path / "real")
    marker = tmp_path / "ran"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    rsync = fake_bin / "rsync"
    rsync.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {shlex.quote(str(marker))}\n')
    rsync.chmod(0o755)

    done = subprocess.run(
        ["sh", "-c", _RSYNC_GUARD, "rsync", str(dest), "--server", "-x", ".", f"{dest}/"],
        env={"PATH": f"{fake_bin}:{os.environ['PATH']}"},
        check=False,
    )

    assert (done.returncode == 0) is runs
    assert marker.exists() is runs
    if runs:
        # The guard's destination argument is consumed; rsync gets its own arguments.
        assert marker.read_text().splitlines() == ["--server", "-x", ".", f"{dest}/"]


# --- uv_sync_as_user ------------------------------------------------------------

UV = (
    "cd / && runuser -u app -- env HOME=/home/app UV_PROJECT_ENVIRONMENT=/home/app/site/.venv "
    """sh -c 'cd "$1" && shift && exec "$@"' sh /home/app/site /usr/local/bin/uv sync --frozen --python 3.14"""
)


def _uv(changed: bool) -> Any:
    from pyinfra.operations import server

    def body() -> None:
        code = server.shell(name="Code", commands=["true"], _if=lambda: changed)
        uv_sync_as_user(
            SITE, user="app", home=HOME, venv=SITE / ".venv", python="3.14", args=("--frozen",), when_changed=[code]
        )

    return body


@pytest.mark.parametrize(("changed", "venv", "runs"), [(True, True, True), (False, True, False), (False, False, True)])
def test_uv_sync_runs_on_a_change_or_without_an_interpreter(changed: bool, venv: bool, runs: bool) -> None:
    responses = {**DEPLOYED, **(fakehost.venv("/home/app/site/.venv") if venv else {})}

    result = run(_uv(changed), responses)

    assert result.succeeded, result.error
    assert (UV in result.executed_commands) is runs


# --- sync_dry_run_as_user -------------------------------------------------------


def _dry_run(source: Path, rsync: RecordingRsyncRunner, responses: dict[str, Any]) -> tuple[FakeRun, list[Any]]:
    answer: list[Any] = []
    result = run(lambda: answer.append(sync_dry_run_as_user(source, SITE, "app", (".env",), rsync)), responses)
    return result, answer


@pytest.mark.parametrize("itemized", [[], [">f.st...... app.py"]])
def test_dry_run_reports_the_itemized_changes_and_queues_nothing(source: Path, itemized: list[str]) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": itemized})

    result, answer = _dry_run(source, rsync, DEPLOYED)

    assert result.succeeded, result.error
    assert answer == [itemized]
    assert result.ops == []
    assert result.function_calls == []
    (call,) = rsync.calls
    assert "--dry-run" in call
    assert REMOTE in call
    assert "--exclude=.env" in call


@pytest.mark.parametrize("responses", [ACCOUNT, fakehost.directory("/home/app/site", user="app")])
def test_dry_run_has_nothing_to_compare_with_before_a_first_deploy(source: Path, responses: dict[str, Any]) -> None:
    rsync = RecordingRsyncRunner()

    result, answer = _dry_run(source, rsync, responses)

    assert result.succeeded, result.error
    assert answer == [None]
    assert rsync.calls == []


def test_dry_run_refuses_a_destination_that_is_not_a_directory(source: Path) -> None:
    rsync = RecordingRsyncRunner()

    result, _ = _dry_run(source, rsync, {**ACCOUNT, **fakehost.symlink("/home/app/site", "/etc", user="app")})

    assert not result.succeeded
    assert "not a directory" in str(result.error)
    assert rsync.calls == []
