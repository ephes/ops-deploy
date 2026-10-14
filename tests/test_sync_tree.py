import shlex
from collections.abc import Sequence
from pathlib import Path

import pytest
from pyinfra.api import deploy

from ops_deploy.core.rsync import RsyncError, RsyncResult
from ops_deploy.ops import sync_tree
from ops_deploy.ops.sync_tree import MANDATORY_EXCLUDES
from ops_deploy.testing import RecordingRsyncRunner, run_deploy_fake

HOST_DATA = {"ssh_hostname": "app.example.invalid", "ssh_user": "deploy"}


@pytest.fixture
def source(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("print('hi')\n")
    return tmp_path


@deploy("Sync")
def sync_deploy(
    src: Path,
    rsync: RecordingRsyncRunner,
    user: str | None = None,
    group: str | None = None,
    excludes: Sequence[str] = (),
    delete: bool = True,
) -> None:
    sync_tree(
        name="Sync tree",
        src=src,
        dest="/srv/app",
        user=user,
        group=group,
        excludes=excludes,
        delete=delete,
        runner=rsync,
    )


def _dry_runs(rsync: RecordingRsyncRunner) -> list[list[str]]:
    return [argv for argv in rsync.calls if "--dry-run" in argv]


def _real_runs(rsync: RecordingRsyncRunner) -> list[list[str]]:
    return [argv for argv in rsync.calls if "--dry-run" not in argv]


def test_noop_when_dry_run_itemizes_nothing(source: Path) -> None:
    rsync = RecordingRsyncRunner()

    run = run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA)

    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert run.function_calls == []
    assert _real_runs(rsync) == []


def test_change_runs_real_rsync_once(source: Path) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f.st...... app.py"]})

    run = run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA)

    assert run.succeeded, run.error
    assert run.changed_ops == ["Sync | Sync tree"]
    assert run.function_calls == ["_run_rsync"]
    assert _real_runs(rsync) == [
        [
            "rsync", "-rlt", "--omit-dir-times", "--delete", "--no-owner", "--no-group",
            *(f"--exclude={pattern}" for pattern in MANDATORY_EXCLUDES),
            "-e", "ssh", f"{source}/", "deploy@app.example.invalid:/srv/app/",
        ]
    ]  # fmt: skip


@pytest.mark.parametrize("itemized", [[], [">f.st...... app.py"]], ids=["noop", "change"])
def test_dry_run_happens_once_although_the_op_body_runs_twice(source: Path, itemized: list[str]) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": itemized})

    run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA)

    assert len(_dry_runs(rsync)) == 1


def test_execution_follows_the_planned_dry_run(source: Path) -> None:
    # A runner whose answer changes after the first call: execution must act on
    # the plan, not re-ask rsync.
    results = iter([RsyncResult(0, ">f.st...... app.py\n"), RsyncResult(0, "")])

    calls: list[list[str]] = []

    def runner(argv: Sequence[str]) -> RsyncResult:
        calls.append(list(argv))
        return next(results) if "--dry-run" in argv else RsyncResult(0)

    @deploy("Sync")
    def flaky() -> None:
        sync_tree(name="Sync tree", src=source, dest="/srv/app", runner=runner)

    run = run_deploy_fake(flaky, host_data=HOST_DATA)

    assert run.changed_ops == ["Sync | Sync tree"]
    assert [argv for argv in calls if "--dry-run" not in argv] != []


def test_excludes_follow_the_mandatory_ones(source: Path) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f+++++++++ new.py"]})

    run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA, excludes=("data/", "*.sqlite3"))

    for argv in rsync.calls:
        excludes = [arg.removeprefix("--exclude=") for arg in argv if arg.startswith("--exclude=")]
        assert excludes == [*MANDATORY_EXCLUDES, "data/", "*.sqlite3"]


def test_state_markers_are_always_excluded() -> None:
    assert ".pyinfra-*" in MANDATORY_EXCLUDES
    assert ".ops-deploy-*" in MANDATORY_EXCLUDES


def test_owner_is_set_with_chown_never_preserved(source: Path) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f+++++++++ app.py"]})

    run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA, user="app", group="www")

    for argv in rsync.calls:
        assert "--no-owner" in argv
        assert "--no-group" in argv
        assert "--chown=app:www" in argv
        assert not {"-a", "-o", "-g", "--owner", "--group"} & set(argv)


def test_owner_group_defaults_to_user(source: Path) -> None:
    rsync = RecordingRsyncRunner()

    run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA, user="app")

    assert "--chown=app:app" in rsync.calls[0]


def test_without_owner_no_chown(source: Path) -> None:
    rsync = RecordingRsyncRunner()

    run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA)

    assert not any(arg.startswith("--chown") for arg in rsync.calls[0])


def test_delete_can_be_disabled(source: Path) -> None:
    rsync = RecordingRsyncRunner()

    run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA, delete=False)

    assert "--delete" not in rsync.calls[0]


def test_ssh_port_from_host_data(source: Path) -> None:
    rsync = RecordingRsyncRunner()

    run_deploy_fake(sync_deploy, source, rsync, host_data={**HOST_DATA, "ssh_port": 2222})

    argv = rsync.calls[0]
    assert argv[argv.index("-e") + 1] == "ssh -p 2222"


def test_ssh_key_and_host_key_options_from_host_data(source: Path) -> None:
    rsync = RecordingRsyncRunner()
    host_data = {
        **HOST_DATA,
        "ssh_key": "/keys/id ed25519",
        "ssh_known_hosts_file": "/keys/known_hosts",
        "ssh_strict_host_key_checking": "yes",
    }

    run_deploy_fake(sync_deploy, source, rsync, host_data=host_data)

    argv = rsync.calls[0]
    assert shlex.split(argv[argv.index("-e") + 1]) == [
        "ssh",
        "-i",
        "/keys/id ed25519",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "UserKnownHostsFile=/keys/known_hosts",
        "-o",
        "StrictHostKeyChecking=yes",
    ]


def test_failed_dry_run_aborts(source: Path) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": RsyncResult(23, stderr="partial transfer")})

    with pytest.raises(RsyncError, match="partial transfer"):
        run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA)


def test_failed_real_rsync_fails_the_op(source: Path) -> None:
    rsync = RecordingRsyncRunner(
        responses={
            "--dry-run": [">f.st...... app.py"],
            "rsync": RsyncResult(12, stderr="protocol error"),
        }
    )

    run = run_deploy_fake(sync_deploy, source, rsync, host_data=HOST_DATA)

    assert not run.succeeded
    assert not run.op("Sync | Sync tree").succeeded


@pytest.mark.parametrize(
    ("dest", "group", "message"),
    [
        ("relative/app", None, "must be absolute"),
        ("/srv/app", "www", "group requires user"),
    ],
)
def test_invalid_arguments_are_rejected(source: Path, dest: str, group: str | None, message: str) -> None:
    @deploy("Bad")
    def bad() -> None:
        sync_tree(name="Sync", src=source, dest=dest, group=group, runner=RecordingRsyncRunner())

    run = run_deploy_fake(bad, host_data=HOST_DATA)

    assert not run.succeeded
    assert message in str(run.error)


def test_missing_source_is_rejected(tmp_path: Path) -> None:
    run = run_deploy_fake(sync_deploy, tmp_path / "missing", RecordingRsyncRunner(), host_data=HOST_DATA)

    assert not run.succeeded
    assert "not a directory" in str(run.error)
