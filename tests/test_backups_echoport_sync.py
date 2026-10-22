"""The synchronous Echoport backup step: parsing, verification and failures.

Most tests drive :func:`run_echoport_backup` with a fake runner that answers
per script. The last ones run the real scripts with bash on this machine,
with stub ``runuser``, Echoport and ``mc`` executables on ``PATH``.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ops_deploy.backups import (
    CommandResult,
    EchoportBackupError,
    EchoportBackupResult,
    EchoportSite,
    RemoteCommandError,
    SshTarget,
    SubprocessRunner,
    run_echoport_backup,
    ssh_runner,
)
from ops_deploy.backups.echoport_sync import (
    BACKUP_SCRIPT,
    CHECKSUM_SCRIPT,
    STAT_SCRIPT,
    parse_backup_output,
    parse_stat_output,
)
from ops_deploy.backups.remote import check_arg, ssh_command

SITE = EchoportSite(site_path="/srv/echoport/site", user="echoport", minio_alias="minio")
KEY = "nyxmon/2026-10-22T04-20-07.tar.gz"
CHECKSUM = "a" * 64


def backup_output(*, run_id: str = "4980", storage: str = f"backups/{KEY}", size: str = "2,946,343,706 bytes") -> str:
    return (
        "Starting backup for target 'nyxmon'...\n"
        "Backup completed successfully!\n"
        f"  Run ID: {run_id}\n"
        f"  Storage: {storage}\n"
        f"  Size: {size}\n"
        "  Duration: 81.2s\n"
    )


def stat_output(size: int = 2946343706, **extra: object) -> str:
    import json

    record = {"status": "success", "name": "2026-10-22T04-20-07.tar.gz", "size": size, "type": "file"}
    record["lastModified"] = "2026-10-22T04:21:28Z"
    record.update(extra)
    return json.dumps(record) + "\n"


class FakeRunner:
    """Answers each script with a queued result; records every call."""

    def __init__(self, **answers: CommandResult | Exception) -> None:
        self.answers = answers
        self.calls: list[tuple[str, list[str], float]] = []

    def __call__(self, script: str, args: Sequence[str], timeout: float) -> CommandResult:
        name = {BACKUP_SCRIPT: "backup", STAT_SCRIPT: "stat", CHECKSUM_SCRIPT: "checksum"}[script]
        self.calls.append((name, list(args), timeout))
        answer = self.answers[name]
        if isinstance(answer, Exception):
            raise answer
        return answer

    @property
    def steps(self) -> list[str]:
        return [name for name, _, _ in self.calls]


def ok(stdout: str) -> CommandResult:
    return CommandResult(0, stdout, "")


def clock() -> datetime:
    return datetime(2026, 10, 22, 4, 20, tzinfo=UTC)


def run(runner: FakeRunner, *, verify_checksum: bool = True) -> EchoportBackupResult:
    return run_echoport_backup(
        runner,
        SITE,
        "nyxmon",
        triggered_by="ops-control:predeploy:nyxmon@host",
        clock=clock,
        verify_checksum=verify_checksum,
    )


def test_success_returns_the_verified_run() -> None:
    runner = FakeRunner(backup=ok(backup_output()), stat=ok(stat_output()))
    result = run_echoport_backup(runner, SITE, "nyxmon", triggered_by="ops-control:predeploy", clock=clock)
    assert result.run_id == 4980
    assert result.object == f"backups/{KEY}"
    assert result.size_bytes == result.object_size == 2946343706
    assert result.checksum_sha256 is None
    assert not result.checksum_verified
    assert result.restore_hint == "manage.py restore nyxmon 4980"
    assert result.as_record()["run_id"] == 4980
    assert result.started_at == "2026-10-22T04:20:00+00:00"
    assert runner.steps == ["backup", "stat"]
    backup_args = runner.calls[0][1]
    assert backup_args == [
        "runuser",
        "echoport",
        "/srv/echoport/site",
        "/srv/echoport/site/.venv/bin/python",
        "nyxmon",
        "ops-control:predeploy",
    ]
    assert runner.calls[1][1] == ["runuser", "echoport", "/usr/local/bin/mc", f"minio/backups/{KEY}"]


def test_reported_checksum_is_verified_against_the_object() -> None:
    output = backup_output() + f"  Checksum: {CHECKSUM}\n"
    runner = FakeRunner(backup=ok(output), stat=ok(stat_output()), checksum=ok(f"{CHECKSUM}  -\n"))
    result = run(runner)
    assert result.checksum_verified
    assert runner.steps == ["backup", "stat", "checksum"]


def test_checksum_mismatch_fails() -> None:
    output = backup_output() + f"  Checksum: {CHECKSUM}\n"
    runner = FakeRunner(backup=ok(output), stat=ok(stat_output()), checksum=ok(f"{'b' * 64}  -\n"))
    with pytest.raises(EchoportBackupError, match="checksum differs"):
        run(runner)


def test_checksum_verification_can_be_skipped() -> None:
    output = backup_output() + f"  Checksum: {CHECKSUM}\n"
    runner = FakeRunner(backup=ok(output), stat=ok(stat_output()))
    result = run(runner, verify_checksum=False)
    assert not result.checksum_verified
    assert runner.steps == ["backup", "stat"]


def test_runner_failure_stops_before_any_check() -> None:
    failed = CommandResult(
        1, "Starting backup...\nBackup failed with status: failed\n", "CommandError: Backup failed\n"
    )
    runner = FakeRunner(backup=failed)
    with pytest.raises(EchoportBackupError, match=r"backup failed \(exit 1\): CommandError: Backup failed"):
        run(runner)
    assert runner.steps == ["backup"]


def test_runner_error_is_a_backup_error() -> None:
    runner = FakeRunner(backup=RemoteCommandError("ssh: no result within 10800s"))
    with pytest.raises(EchoportBackupError, match="no result within"):
        run(runner)


def test_missing_artifact_fails() -> None:
    missing = CommandResult(1, '{"status": "error", "error": {"message": "Object does not exist"}}\n', "")
    runner = FakeRunner(backup=ok(backup_output()), stat=missing)
    with pytest.raises(EchoportBackupError, match="not found in MinIO"):
        run(runner)


def test_size_mismatch_fails() -> None:
    runner = FakeRunner(backup=ok(backup_output()), stat=ok(stat_output(size=1024)))
    with pytest.raises(EchoportBackupError, match="object is 1024 bytes, Echoport reported 2946343706"):
        run(runner)


def test_folder_instead_of_file_fails() -> None:
    runner = FakeRunner(backup=ok(backup_output()), stat=ok(stat_output(type="folder")))
    with pytest.raises(EchoportBackupError, match="did not report a file"):
        run(runner)


@pytest.mark.parametrize(
    ("output", "message"),
    [
        ("Starting backup...\n", "did not report a successful run"),
        (backup_output(run_id="none"), "no run ID"),
        (backup_output(storage="backups"), "no bucket/key"),
        (backup_output(storage="backups/other/x.tar.gz"), "not under nyxmon/"),
        (backup_output(storage="backups/nyxmon/../x.tar.gz"), "not under nyxmon/"),
        (backup_output(size="unknown"), "no positive size"),
        (backup_output(size="0 bytes"), "no positive size"),
        (backup_output() + "  Checksum: xyz\n", "malformed checksum"),
    ],
)
def test_unusable_output_fails(output: str, message: str) -> None:
    runner = FakeRunner(backup=ok(output))
    with pytest.raises(EchoportBackupError, match=message):
        run(runner)
    assert runner.steps == ["backup"]


def test_colored_output_is_parsed() -> None:
    colored = (
        backup_output()
        .replace("Backup completed", "\x1b[32;1mBackup completed")
        .replace("s\n  Duration", "s\x1b[0m\n  Duration")
    )
    assert parse_backup_output("nyxmon", colored).run_id == 4980


def test_stat_output_needs_exactly_one_object() -> None:
    with pytest.raises(EchoportBackupError, match="2 objects"):
        parse_stat_output(stat_output() + stat_output())
    assert parse_stat_output("mc: progress\n" + stat_output()) == (2946343706, "2026-10-22T04:21:28Z")


@pytest.mark.parametrize(
    ("target", "label"),
    [("nyx mon", "ops-control"), ("-x", "ops-control"), ("nyxmon", "a b"), ("nyxmon", "x" * 101), ("nyxmon", "")],
)
def test_bad_target_or_label_never_reaches_the_host(target: str, label: str) -> None:
    runner = FakeRunner()
    with pytest.raises(ValueError, match="invalid"):
        run_echoport_backup(runner, SITE, target, triggered_by=label)
    assert runner.calls == []


def test_site_validation() -> None:
    with pytest.raises(ValueError, match="site_path"):
        EchoportSite(site_path="relative", user="echoport", minio_alias="minio")
    with pytest.raises(ValueError, match="site_path"):
        EchoportSite(site_path="/", user="echoport", minio_alias="minio")
    with pytest.raises(ValueError, match="Echoport user"):
        EchoportSite(site_path="/srv/e", user="Echo Port", minio_alias="minio")
    with pytest.raises(ValueError, match="become"):
        EchoportSite(site_path="/srv/e", user="echoport", minio_alias="minio", become="su")  # type: ignore[arg-type]


def test_scripts_are_fish_and_quote_safe() -> None:
    for script in (BACKUP_SCRIPT, STAT_SCRIPT, CHECKSUM_SCRIPT):
        assert "\\" not in script
        assert "'" not in script


# --- transport ---------------------------------------------------------------


def test_ssh_command_is_batch_mode_and_ends_options() -> None:
    target = SshTarget(
        "host.example", user="root", port=2222, key="/k", known_hosts_file="/kh", options=(("ConnectTimeout", "10"),)
    )
    assert ssh_command(target) == (
        "ssh", "-o", "BatchMode=yes", "-p", "2222", "-i", "/k", "-o", "UserKnownHostsFile=/kh",
        "-o", "ConnectTimeout=10", "-l", "root", "--", "host.example",
    )  # fmt: skip
    runner = ssh_runner(target)
    assert runner.quote
    assert runner.remote_timeout


def test_arguments_with_backslashes_or_newlines_are_refused() -> None:
    for value in ("a\\b", "a\nb", "a\0b"):
        with pytest.raises(RemoteCommandError):
            check_arg(value)
    with pytest.raises(RemoteCommandError):
        SubprocessRunner()("true", ["a\\b"], 5)


def test_remote_quoting_keeps_arguments_whole(tmp_path: Path) -> None:
    # A stand-in for ssh: joins its words into one line for a shell, like sshd.
    fake_ssh = tmp_path / "fake-ssh"
    fake_ssh.write_text('#!/usr/bin/env bash\nexec bash -c "$*"\n')
    fake_ssh.chmod(0o755)
    runner = SubprocessRunner(prefix=(str(fake_ssh),), quote=True)
    result = runner('printf "%s|" "$@"', ["a b", "it's", "$HOME"], 10)
    assert result.stdout == "a b|it's|$HOME|"


def test_remote_timeout_wraps_the_command_and_reports_a_stop(tmp_path: Path) -> None:
    log = tmp_path / "ssh.log"
    fake_ssh = tmp_path / "fake-ssh"
    fake_ssh.write_text(f'#!/usr/bin/env bash\necho "$*" >{log}\nexec bash -c "$*"\n')
    fake_ssh.chmod(0o755)
    # A stand-in for coreutils timeout: drops "-k GRACE SECONDS", exits 124 on "stop".
    fake_timeout = tmp_path / "timeout"
    fake_timeout.write_text(
        '#!/usr/bin/env bash\nshift 3\n"$@"\nstatus=$?\n[ "$status" = 7 ] && exit 124\nexit $status\n'
    )
    fake_timeout.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}"}
    runner = SubprocessRunner(prefix=(str(fake_ssh),), quote=True, env=env, remote_timeout=True)
    assert runner('echo "$1"', ["ok"], 5).stdout == "ok\n"
    assert log.read_text().startswith("timeout -k 30 5 bash -s -- ")
    with pytest.raises(RemoteCommandError, match="stopped on the host"):
        runner("exit 7", [], 5)


def test_local_timeout_stops_the_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "partial"
    script = (
        'cleanup() { rm -f "$1"; }\nstop() { cleanup "$1"; exit 1; }\ntrap "stop $1" TERM\n: >"$1"\nsleep 60 &\nwait\n'
    )
    with pytest.raises(RemoteCommandError, match="no result within 1s; stopped"):
        SubprocessRunner()(script, [str(marker)], 1)
    assert not marker.exists()


def test_timeout_kills_group_members_that_ignore_sigterm(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    script = '(trap "" TERM; exec sleep 60 </dev/null >/dev/null 2>&1) &\necho $! >"$1"\nwait\n'
    runner = SubprocessRunner(stop_grace=1)
    with pytest.raises(RemoteCommandError, match="stopped"):
        runner(script, [str(pid_file)], 1)
    pid = int(pid_file.read_text())
    # The member was reparented when the leader died; until its new parent
    # reaps it, a killed member is a zombie that still answers signal 0 (Linux).
    deadline = time.monotonic() + 5
    while not _process_ended(pid):
        assert time.monotonic() < deadline, f"group member {pid} still runs after the stop"
        time.sleep(0.05)


def _process_ended(pid: int) -> bool:
    """Whether ``pid`` is gone or a zombie, i.e. can never run again."""

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    if Path("/proc/self/stat").exists():
        try:
            fields = (Path("/proc") / str(pid) / "stat").read_text().rpartition(")")[2].split()
        except FileNotFoundError:
            return True
        return fields[0] in ("Z", "X")
    ps = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False)
    state = ps.stdout.strip()
    if not state:
        # Gone between the two probes, or ps failed: only signal 0 can tell.
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        return False
    return state.startswith("Z")


# --- the real scripts, with stubs --------------------------------------------


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def host(tmp_path: Path) -> tuple[SubprocessRunner, EchoportSite, Path]:
    """A fake Echoport host: site dir, stub runuser, python and mc."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    site = tmp_path / "site"
    (site / ".venv" / "bin").mkdir(parents=True)
    (site / "manage.py").write_text("")
    store = tmp_path / "minio"
    (store / "backups" / "nyxmon").mkdir(parents=True)
    log = tmp_path / "calls.log"
    _stub(
        bin_dir / "runuser",
        f'[ "$1" = -u ] && [ "$3" = -- ] || exit 9\necho "runuser $2" >>{log}\nshift 3\nexec "$@"\n',
    )
    _stub(
        site / ".venv" / "bin" / "python",
        f'[ -f manage.py ] || {{ echo "not in the site dir" >&2; exit 7; }}\n'
        f'echo "python $*" >>{log}\n'
        'if [ "$3" = broken ]; then echo "CommandError: Backup failed" >&2; exit 1; fi\n'
        f'printf "content" >{store}/backups/nyxmon/run.tar.gz\n'
        'printf "Starting backup...\\nBackup completed successfully!\\n  Run ID: 7\\n'
        "  Storage: backups/nyxmon/run.tar.gz\\n  Size: 7 bytes\\n"
        f'  Checksum: {hashlib.sha256(b"content").hexdigest()}\\n"\n',
    )
    _stub(
        bin_dir / "mc",
        f'echo "mc $*" >>{log}\n'
        f"store={store}\n"
        'if [ "$1" = stat ]; then\n'
        '  file="$store/${3#minio/}"\n'
        '  [ -f "$file" ] || { echo \'{"status":"error"}\'; exit 1; }\n'
        '  printf \'{"status":"success","type":"file","size":%s}\\n\' "$(wc -c <"$file" | tr -d " ")"\n'
        'elif [ "$1" = cat ]; then cat "$store/${2#minio/}"; fi\n',
    )
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    runner = SubprocessRunner(env=env)
    echoport = EchoportSite(site_path=str(site), user="echoport", minio_alias="minio", mc_path=str(bin_dir / "mc"))
    return runner, echoport, log


def test_real_scripts_back_up_and_verify(host: tuple[SubprocessRunner, EchoportSite, Path]) -> None:
    runner, site, log = host
    result = run_echoport_backup(runner, site, "nyxmon", triggered_by="ops-control:manual")
    assert (result.run_id, result.object, result.object_size) == (7, "backups/nyxmon/run.tar.gz", 7)
    assert result.checksum_verified
    calls = log.read_text().splitlines()
    assert calls[:2] == ["runuser echoport", "python manage.py backup nyxmon --triggered-by ops-control:manual"]
    assert "mc stat --json minio/backups/nyxmon/run.tar.gz" in calls
    assert "mc cat minio/backups/nyxmon/run.tar.gz" in calls


def test_real_scripts_report_a_failed_run(host: tuple[SubprocessRunner, EchoportSite, Path]) -> None:
    runner, site, log = host
    with pytest.raises(EchoportBackupError, match="CommandError: Backup failed"):
        run_echoport_backup(runner, site, "broken", triggered_by="ops-control:manual")
    assert not any(line.startswith("mc ") for line in log.read_text().splitlines())
