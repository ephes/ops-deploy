import re
from collections.abc import Callable

import pytest
from pyinfra.api import FunctionCommand, deploy, operation
from pyinfra.api.command import FunctionCommand as CommandClass
from pyinfra.connectors.fake import FakeConnector
from pyinfra.operations import files, server
from pyinfra.operations.util import any_changed

from ops_deploy.core.rsync import RsyncResult
from ops_deploy.testing import RecordingRsyncRunner, run_deploy_fake

CALLBACK_LOG: list[str] = []


def _callback(value: str) -> None:
    CALLBACK_LOG.append(value)


@operation()
def callback_op(value: str):  # type: ignore[no-untyped-def]
    yield FunctionCommand(_callback, (value,), {})


@deploy("Sample")
def sample_deploy(marker: str) -> None:
    server.shell(name="Say hello", commands=[f"echo {marker}"])
    callback_op(name="Run callback", value=marker)


def test_records_shell_and_function_calls_in_execution_order() -> None:
    CALLBACK_LOG.clear()
    run = run_deploy_fake(sample_deploy, "m1")

    assert run.succeeded
    assert [(event.kind, event.value) for event in run.executed] == [
        ("shell", "echo m1"),
        ("function", "_callback"),
    ]
    assert CALLBACK_LOG == ["m1"]
    assert run.changed_ops == ["Sample | Say hello", "Sample | Run callback"]


def test_fact_commands_are_separated_from_execution() -> None:
    @deploy("Facts")
    def facts_deploy() -> None:
        files.directory(name="Dir", path="/srv/x")

    run = run_deploy_fake(facts_deploy, responses={})

    assert any("test -e /srv/x" in command for command in run.fact_commands)
    assert "mkdir -p /srv/x" in run.executed_commands
    assert "mkdir -p /srv/x" not in run.fact_commands


def test_scripted_responses_drive_facts_and_gating() -> None:
    @deploy("Gated")
    def gated() -> None:
        changed = files.directory(name="Dir", path="/srv/x")
        server.shell(name="Only on change", commands=["echo changed"], _if=any_changed(changed))

    stat = "user=root group=root mode=drwxr-xr-x atime=0 mtime=0 ctime=0 size=4096 '/srv/x'"
    run = run_deploy_fake(gated, responses={"test -e /srv/x ||": stat})

    assert run.executed_commands == []
    assert any("test -e /srv/x" in event.value for event in run.executed if event.kind == "fact")
    assert run.op("Gated | Dir").changed is False
    assert run.op("Gated | Only on change").changed is False


def test_records_upload_content() -> None:
    from io import StringIO

    @deploy("Upload")
    def upload() -> None:
        files.put(name="Put", src=StringIO("content\n"), dest="/etc/x.conf")

    run = run_deploy_fake(upload)

    assert run.uploads == [("/etc/x.conf", b"content\n")]
    assert ("put", "/etc/x.conf") in [(event.kind, event.value) for event in run.executed]
    assert "content" in run.all_text()


def test_records_every_upload_to_the_same_path() -> None:
    from io import StringIO

    @deploy("Twice")
    def twice() -> None:
        files.put(name="First", src=StringIO("first-secret\n"), dest="/etc/x.conf")
        files.put(name="Second", src=StringIO("second\n"), dest="/etc/x.conf")

    run = run_deploy_fake(twice)

    assert run.uploads == [("/etc/x.conf", b"first-secret\n"), ("/etc/x.conf", b"second\n")]
    assert "first-secret" in run.all_text()
    with pytest.raises(KeyError, match="exactly one upload"):
        run.upload("/etc/x.conf")


def test_failing_command_is_reported_not_raised() -> None:
    run = run_deploy_fake(sample_deploy, "boom", responses={"echo boom": {"success": False, "stderr": "nope"}})

    assert not run.succeeded
    assert run.op("Sample | Say hello").succeeded is False
    assert "_callback" not in run.function_calls


def test_masked_values_are_recorded_masked() -> None:
    from pyinfra.api import StringCommand
    from pyinfra.api.hiddenvalue import HiddenValue

    @deploy("Masked")
    def masked() -> None:
        server.shell(name="Secret", commands=[StringCommand("echo", HiddenValue("t0p-s3cret"))])  # type: ignore[list-item]

    run = run_deploy_fake(masked)

    assert run.executed_commands == ["echo *MASKED*"]
    assert "t0p-s3cret" not in run.all_text()


def test_patches_are_restored_after_run_even_on_error() -> None:
    originals: tuple[Callable[..., object], ...] = (
        FakeConnector.run_shell_command,
        FakeConnector.put_file,
        CommandClass.execute,
    )

    @deploy("Broken")
    def broken() -> None:
        raise RuntimeError("planning failed")

    try:
        run_deploy_fake(broken)
    except RuntimeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected planning error to propagate")

    assert (FakeConnector.run_shell_command, FakeConnector.put_file, CommandClass.execute) == originals


def test_recording_rsync_runner_matches_in_order() -> None:
    runner = RecordingRsyncRunner(
        responses={
            "--dry-run": [">f+++++++++ a.py", "*deleting old.py"],
            re.compile(r"^rsync -a"): RsyncResult(23, stderr="partial"),
        }
    )

    assert runner(["rsync", "--dry-run", "src/", "dest/"]).itemized_lines == [">f+++++++++ a.py", "*deleting old.py"]
    assert runner(["rsync", "-a", "src/", "dest/"]).returncode == 23
    assert runner(["rsync", "-r"]).stdout == ""
    assert runner.calls == [
        ["rsync", "--dry-run", "src/", "dest/"],
        ["rsync", "-a", "src/", "dest/"],
        ["rsync", "-r"],
    ]


@pytest.mark.parametrize("gate", [lambda: True, lambda: False])
def test_commands_a_fish_login_shell_would_alter_fail_the_run(gate: Callable[[], bool]) -> None:
    @deploy("Fish")
    def fish_deploy() -> None:
        server.shell(name="Pair", commands=["printf %s 'a\\\\b'"], _if=gate)

    with pytest.raises(AssertionError, match="fish login shell"):
        run_deploy_fake(fish_deploy)


def test_single_backslashes_are_fish_safe() -> None:
    @deploy("Fish")
    def fish_deploy() -> None:
        server.shell(name="Single", commands=["printf '%s\\n' x"], _if=lambda: False)

    assert run_deploy_fake(fish_deploy).succeeded
