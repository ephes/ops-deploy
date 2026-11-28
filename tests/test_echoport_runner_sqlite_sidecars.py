"""The marina runner template (marina staging/production, durchreiche) and SQLite's sidecar files.

The rendered script runs in-process against a fake host: a directory that
stands for the remote filesystem, with ``ssh``/``scp`` replaced by file
operations on it and ``mc`` by a local "bucket" directory. The cases are the
ones a WAL or rollback journal makes dangerous:

- backup: an existing ``-wal`` (or ``-journal``) must arrive, or the run fails;
  committed changes that live only in the WAL are in the archive;
- the service restarts right after the copy, before the upload;
- restore: the live database and its sidecars are moved aside, never deleted,
  and put back when the restore fails.
"""

from __future__ import annotations

import json
import shlex
import shutil
import sqlite3
import subprocess
import types
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services._echoport_runner.render import render_runner
from tests.echoport_runner_data import INPUTS

SPEC = INPUTS["marina-production-backup"]
DB = "/home/marina/site/db.sqlite3"
MEDIA = "/home/marina/site/media"


class FakeHost:
    """The remote side: paths under ``root``, the unit's state and a call log."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[str] = []
        self.running = True
        self.fail: dict[str, int] = {}
        # (command prefix, times): the command runs, but ssh reports a failure.
        self.lost_reply: dict[str, int] = {}
        # Whether the application answers its ready URL once the unit runs.
        self.app_ok = True
        self.refuse: list[str] = []

    def local(self, remote: str) -> Path:
        return self.root / remote.lstrip("/")

    def ssh(self, cmd: str) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        argv = shlex.split(cmd)
        if any(cmd.startswith(prefix) for prefix in self.refuse):
            return subprocess.CompletedProcess(argv, 1, "", "refused")
        lost = next((prefix for prefix in self.lost_reply if cmd.startswith(prefix) and self.lost_reply[prefix]), None)
        if lost is not None:
            self.lost_reply[lost] -= 1
            self._run(argv)
            return subprocess.CompletedProcess(argv, 255, "", "Connection reset")
        if self.fail.get(argv[0]):
            self.fail[argv[0]] -= 1
            return subprocess.CompletedProcess(argv, 1, "", f"{argv[0]} failed")
        return self._run(argv)

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[0] == "systemctl":
            self.running = argv[1] == "start"
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "readlink":
            return subprocess.CompletedProcess(argv, 0, argv[2] + "\n", "")
        if argv[0] == "test":
            path = self.local(argv[2])
            ok = path.is_dir() if argv[1] == "-d" else path.exists()
            return subprocess.CompletedProcess(argv, 0 if ok else 1, "", "")
        if argv[0] == "mv":
            source, target = self.local(argv[1]), self.local(argv[2])
            assert not target.exists() or argv[1] == argv[2] + ".tmp", f"mv onto {argv[2]}"
            source.rename(target)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "curl":
            ok = self.running and self.app_ok
            return subprocess.CompletedProcess(argv, 0 if ok else 22, "", "" if ok else "curl: (7)")
        if argv[0] == "mkdir":
            self.local(argv[2]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "chown":
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unexpected remote command: {argv}")


def _runner(tmp_path: Path, host: FakeHost) -> Any:
    text = render_runner(SPEC["template"], SPEC["inputs"])
    module: Any = types.ModuleType("marina_runner")
    exec(compile(text.replace('if __name__ == "__main__":', "if False:"), "runner", "exec"), module.__dict__)
    work = tmp_path / "work"
    bucket = tmp_path / "bucket"
    bucket.mkdir()
    events: list[dict[str, Any]] = []

    def open_run_dir(prefix: str, label: str) -> Path:
        path = work / prefix.rstrip("-")
        path.mkdir(parents=True)
        return path

    def ssh(remote_host: str, remote_user: str, cmd: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = host.ssh(cmd)
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
        return result

    def scp_from_remote(remote_host: str, remote_user: str, remote_path: str, local_path: str) -> None:
        host.calls.append(f"scp-from {remote_path}")
        if host.fail.get("scp-from"):
            host.fail["scp-from"] -= 1
            raise subprocess.CalledProcessError(1, "scp", "", "lost connection")
        shutil.copyfile(host.local(remote_path), local_path)

    def scp_to_remote(remote_host: str, remote_user: str, local_path: str, remote_path: str) -> None:
        host.calls.append(f"scp-to {remote_path}")
        shutil.copyfile(local_path, host.local(remote_path))

    real_run = subprocess.run

    def run(argv: Any, *args: Any, **kwargs: Any) -> Any:
        if argv and argv[0] == module.MC_PATH:
            host.calls.append(f"mc {argv[1]} (service running: {host.running})")
            if argv[1] == "cp":
                source, target = argv[2], argv[3]
                if source.startswith(module.MINIO_ALIAS):
                    shutil.copyfile(bucket / Path(source).name, target)
                else:
                    shutil.copyfile(source, bucket / Path(target).name)
            return subprocess.CompletedProcess(argv, 0, "", "")
        return real_run(argv, *args, **kwargs)

    module.READY_ATTEMPTS = 3
    module.READY_DELAY_SECONDS = 0
    module.open_run_dir = open_run_dir
    module.ssh = ssh
    module.scp_from_remote = scp_from_remote

    def rsync_to_remote(remote_host: str, remote_user: str, local_path: str, remote_path: str) -> None:
        host.calls.append(f"rsync-to {remote_path}")
        shutil.copytree(local_path, host.local(remote_path), dirs_exist_ok=True)

    module.scp_to_remote = scp_to_remote
    module.rsync_to_remote = rsync_to_remote
    module.subprocess = types.SimpleNamespace(**{**vars(subprocess), "run": run})
    module.emit_step = lambda name, state, message="": events.append({"step": name, "state": state})
    module.emit_result = lambda **kw: events.append({"result": kw})
    module.finish_stdout = lambda status, message=None: None
    module.events = events
    module.bucket = bucket
    return module


def _wal_database(path: Path) -> None:
    """A WAL database whose last committed row lives only in the -wal file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE t (v TEXT)")
    writer.execute("INSERT INTO t VALUES ('checkpointed')")
    writer.commit()
    writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    writer.execute("INSERT INTO t VALUES ('only-in-wal')")
    writer.commit()
    # Copy the files while the writer still holds them (like a crash), so the
    # -wal survives next to the database.
    shutil.copytree(path.parent, path.parent.with_name("snapshot"))
    writer.close()
    shutil.rmtree(path.parent)
    path.parent.with_name("snapshot").rename(path.parent)
    assert Path(f"{path}-wal").stat().st_size > 0


def _rows(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [row[0] for row in connection.execute("SELECT v FROM t ORDER BY rowid")]
    finally:
        connection.close()


def _backup(runner: Any) -> int:
    result: int = runner.backup(
        "marina.example.invalid", "root", DB, [], "marina.service", "backups", "marina-production/x", "x"
    )
    return result


@pytest.fixture
def host(tmp_path: Path) -> FakeHost:
    return FakeHost(tmp_path / "remote")


def test_backup_carries_committed_changes_from_the_wal(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)

    assert _backup(runner) == 0
    assert f"scp-from {DB}-wal" in host.calls
    archive = runner.bucket / "x.tar.gz"
    extract = tmp_path / "extract"
    shutil.unpack_archive(archive, extract, filter="data")
    assert _rows(extract / "db_backup.sqlite3") == ["checkpointed", "only-in-wal"]


def test_a_wal_that_does_not_arrive_fails_the_backup(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    real = runner.scp_from_remote

    def flaky(remote_host: str, remote_user: str, remote_path: str, local_path: str) -> None:
        if remote_path.endswith("-wal"):
            raise subprocess.CalledProcessError(1, "scp", "", "lost connection")
        real(remote_host, remote_user, remote_path, local_path)

    runner.scp_from_remote = flaky
    assert _backup(runner) == 1
    assert not (runner.bucket / "x.tar.gz").exists()
    assert host.running


def test_a_refused_existence_check_fails_instead_of_skipping(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    real = runner.ssh

    def refusing(remote_host: str, remote_user: str, cmd: str, check: bool = True) -> Any:
        if cmd.startswith("test -e") and cmd.endswith("-wal"):
            return subprocess.CompletedProcess(cmd, 1, "", "refused: path not allowed")
        return real(remote_host, remote_user, cmd, check)

    runner.ssh = refusing
    assert _backup(runner) == 1
    assert host.running


def test_the_service_restarts_before_the_upload(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)

    assert _backup(runner) == 0
    uploads = [call for call in host.calls if call.startswith("mc cp")]
    assert uploads == ["mc cp (service running: True)"]
    starts = [i for i, call in enumerate(host.calls) if call == "systemctl start marina.service"]
    assert len(starts) == 1


def _archive_with(tmp_path: Path, rows: list[str], media: dict[str, str] | None = None) -> tuple[Path, str]:
    work = tmp_path / "make-archive"
    work.mkdir()
    db = work / "db_backup.sqlite3"
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE t (v TEXT)")
    connection.executemany("INSERT INTO t VALUES (?)", [(row,) for row in rows])
    connection.commit()
    connection.close()
    files = [MEDIA] if media is not None else []
    (work / "manifest.json").write_text(json.dumps({"database": {"filename": "db_backup.sqlite3"}, "files": files}))
    if media is not None:
        (work / "media").mkdir()
        for name, text in media.items():
            (work / "media" / name).write_text(text)
    import hashlib
    import tarfile

    tarball = tmp_path / "restore.tar.gz"
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(db, arcname="db_backup.sqlite3")
        tar.add(work / "manifest.json", arcname="manifest.json")
        if media is not None:
            tar.add(work / "media", arcname="media")
    return tarball, hashlib.sha256(tarball.read_bytes()).hexdigest()


def _restore(runner: Any, tmp_path: Path, rows: list[str], media: dict[str, str] | None = None) -> int:
    tarball, checksum = _archive_with(tmp_path, rows, media)
    shutil.copyfile(tarball, runner.bucket / "restore.tar.gz")
    result: int = runner.restore(
        "marina.example.invalid",
        "root",
        DB,
        [],
        "marina.service",
        "marina:marina",
        "backups",
        "marina-production/restore.tar.gz",
        checksum,
    )
    return result


def test_restore_moves_the_live_database_and_wal_aside(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)

    assert _restore(runner, tmp_path, ["restored"]) == 0
    assert _rows(host.local(DB)) == ["restored"]
    assert not Path(f"{host.local(DB)}-wal").exists()
    aside = sorted(p.name for p in host.local(DB).parent.iterdir() if ".pre-restore-" in p.name)
    assert any(name.endswith("-wal") for name in aside)
    # The previous set is complete: database plus WAL give back every commit.
    kept = host.local(DB).parent / next(n for n in aside if not n.endswith(("-wal", "-shm", "-journal")))
    probe = tmp_path / "probe"
    probe.mkdir()
    for name in aside:
        shutil.copyfile(host.local(DB).parent / name, probe / name.replace(kept.name, "db.sqlite3"))
    assert _rows(probe / "db.sqlite3") == ["checkpointed", "only-in-wal"]
    # The upload happened before the service stopped.
    assert host.calls.index(f"scp-to {DB}.tmp") < host.calls.index("systemctl stop marina.service")
    assert host.running


def test_a_failed_restore_puts_the_previous_database_back(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    host.fail["chown"] = 1  # fails after the new database is in place

    assert _restore(runner, tmp_path, ["restored"]) == 1
    # Checked before reading: opening the database checkpoints the WAL away.
    assert Path(f"{host.local(DB)}-wal").exists()
    assert _rows(host.local(DB)) == ["checkpointed", "only-in-wal"]
    assert host.running


def test_a_service_that_does_not_start_gets_the_previous_set_back(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    host.fail["systemctl"] = 0
    real = host._run
    starts = {"n": 0}

    def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["systemctl", "start"]:
            starts["n"] += 1
            if starts["n"] == 1:
                return subprocess.CompletedProcess(argv, 1, "", "start failed")
        return real(argv)

    host._run = run  # type: ignore[method-assign]
    assert _restore(runner, tmp_path, ["restored"]) == 1
    assert Path(f"{host.local(DB)}-wal").exists()
    assert _rows(host.local(DB)) == ["checkpointed", "only-in-wal"]
    assert starts["n"] == 2
    assert host.running


def test_a_lost_reply_after_a_rename_is_reconciled(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    host.lost_reply[f"mv {DB} "] = 1  # the rename of the live database happens, its reply is lost

    assert _restore(runner, tmp_path, ["restored"]) == 0
    assert _rows(host.local(DB)) == ["restored"]
    assert host.running


def test_an_incomplete_rollback_leaves_the_service_stopped(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    host.fail["chown"] = 1
    host.refuse.append(f"mv {DB}.pre-restore-")  # moving the aside files back is refused

    assert _restore(runner, tmp_path, ["restored"]) == 1
    assert not host.running
    assert any(p.name.endswith("-wal") and ".pre-restore-" in p.name for p in host.local(DB).parent.iterdir())


def test_a_failed_restore_also_puts_the_previous_files_back(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    host.local(MEDIA).mkdir(parents=True)
    (host.local(MEDIA) / "old.jpg").write_text("previous")
    runner = _runner(tmp_path, host)
    host.fail["chown"] = 1

    assert _restore(runner, tmp_path, ["restored"], media={"new.jpg": "restored"}) == 1
    assert sorted(p.name for p in host.local(MEDIA).iterdir()) == ["old.jpg"]
    assert _rows(host.local(DB)) == ["checkpointed", "only-in-wal"]
    assert host.running


def test_a_successful_restore_replaces_the_files_and_keeps_the_previous_ones(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    host.local(MEDIA).mkdir(parents=True)
    (host.local(MEDIA) / "old.jpg").write_text("previous")
    runner = _runner(tmp_path, host)

    assert _restore(runner, tmp_path, ["restored"], media={"new.jpg": "restored"}) == 0
    assert sorted(p.name for p in host.local(MEDIA).iterdir()) == ["new.jpg"]
    kept = [p for p in host.local(MEDIA).parent.iterdir() if p.name.startswith("media.pre-restore-")]
    assert len(kept) == 1
    assert (kept[0] / "old.jpg").read_text() == "previous"


def test_heis_moves_sidecars_with_the_database_and_never_starts_an_incomplete_rollback() -> None:
    spec = INPUTS["heis-production-backup"]
    text = render_runner(spec["template"], spec["inputs"])
    restore = text[text.index("def restore(") :]
    move_db = restore.index('mv "$site_db" "$safety/db.sqlite3"')
    move_sidecars = restore.index('mv "$site_db$suffix" "$safety/db.sqlite3$suffix"')
    assert move_db < move_sidecars
    assert 'rm -f "$site_db-wal" "$site_db-shm"\n' not in restore
    rollback = restore[restore.index("rollback_restore() {") :]
    assert rollback.index('if test "$rollback_failed" != 0; then') < rollback.index("systemctl start")
    # A rollback that cannot stop the units moves nothing.
    assert rollback.index("if ! systemctl stop") < rollback.index('rm -f "$site_db"')
    # The watchdog starts the units only while no inconsistency marker exists;
    # the marker is set before the first move and cleared once a set is complete.
    watchdog = restore[restore.index("systemd-run --unit=") :]
    command = watchdog.split("\n", 3)[1]
    assert "/.inconsistent" in command
    assert "|| /bin/systemctl start" in command
    first_move = restore.index('mv "$site_db" "$safety/db.sqlite3"; old_db_moved=1')
    assert restore.index('touch "$marker"\n        systemd-run') < first_move
    assert restore.index('rm -f "$marker"\n        systemctl start') > restore.index("migrate --noinput")


def test_an_app_that_does_not_get_ready_rolls_the_restore_back(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    real = host._run
    starts = {"n": 0}

    def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["systemctl", "start"]:
            starts["n"] += 1
            host.app_ok = starts["n"] > 1  # crashes on the restored set only
        return real(argv)

    host._run = run  # type: ignore[method-assign]
    assert _restore(runner, tmp_path, ["restored"]) == 1
    assert Path(f"{host.local(DB)}-wal").exists()
    assert _rows(host.local(DB)) == ["checkpointed", "only-in-wal"]
    assert host.running
    assert host.app_ok


def test_without_a_confirmed_stop_nothing_is_moved_back(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    host.app_ok = False
    real = host._run
    stops = {"n": 0}

    def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["systemctl", "stop"]:
            stops["n"] += 1
            if stops["n"] > 1:  # the first stop (before the restore) works
                return subprocess.CompletedProcess(argv, 1, "", "stop refused")
        return real(argv)

    host._run = run  # type: ignore[method-assign]
    assert _restore(runner, tmp_path, ["restored"]) == 1
    assert _rows(host.local(DB)) == ["restored"]
    assert any(".pre-restore-" in p.name for p in host.local(DB).parent.iterdir())
    assert not any(".failed-restore-" in p.name for p in host.local(DB).parent.iterdir())


def test_a_lost_reply_while_moving_back_is_reconciled(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    host.fail["chown"] = 1
    host.lost_reply[f"mv {DB}.pre-restore-"] = 1  # the first move back happens, its reply is lost

    assert _restore(runner, tmp_path, ["restored"]) == 1
    assert Path(f"{host.local(DB)}-wal").exists()
    assert _rows(host.local(DB)) == ["checkpointed", "only-in-wal"]
    assert host.running


def test_a_backup_whose_site_does_not_come_back_still_archives_but_fails(tmp_path: Path, host: FakeHost) -> None:
    _wal_database(host.local(DB))
    runner = _runner(tmp_path, host)
    host.app_ok = False

    assert _backup(runner) == 1
    assert (runner.bucket / "x.tar.gz").exists()
