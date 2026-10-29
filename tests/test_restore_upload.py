"""Original restore-prelude rules, actual shell probes and bounded transfers."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ops_deploy.backups.remote import CommandResult, RemoteCommandError, SshTarget, SubprocessRunner
from ops_deploy.backups.restore_upload import (
    FINISH,
    PREPARE,
    REMOTE_PRESENT,
    RestoreUploadError,
    upload_restore_archives,
)

TEMPORARY = "/tmp/_backup_upload.AbCdEf0123"
TARGET = SshTarget("inventory.example", user="root", port=2222, key="/owned/key", options=(("ConnectTimeout", "20"),))


class Calls:
    def __init__(self, *, present: str = "upload", failure: str = "", timeout: bool = False) -> None:
        self.present = present
        self.failure = failure
        self.timeout = timeout
        self.calls: list[tuple[str, tuple[str, ...], float]] = []

    def __call__(self, script: str, args: object, timeout: float) -> CommandResult:
        assert isinstance(args, (tuple, list))
        self.calls.append((script, tuple(args), timeout))
        stage = {REMOTE_PRESENT: "check", PREPARE: "prepare", FINISH: "finish"}.get(script, "transfer")
        if stage == self.failure:
            if self.timeout:
                raise RemoteCommandError("must not export archive/body diagnostics")
            return CommandResult(1, "private output", "private error")
        return CommandResult(0, {"check": self.present, "prepare": TEMPORARY}.get(stage, ""), "")


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_bad_timeout_is_rejected_before_any_effect(tmp_path: Path, timeout: float) -> None:
    (tmp_path / "one.tar.gz").touch()
    calls = Calls()
    with pytest.raises(ValueError, match="finite and positive"):
        upload_restore_archives(TARGET, tmp_path, "/backup", timeout=timeout, remote=calls, transfer=calls)
    assert not calls.calls


@pytest.mark.parametrize("names", [[], ["other.tar.xz"]])
def test_no_local_trigger_never_connects(tmp_path: Path, names: list[str]) -> None:
    for name in names:
        (tmp_path / name).write_text("owned")
    calls = Calls()
    result = upload_restore_archives(TARGET, tmp_path, "/backup", remote=calls, transfer=calls)
    assert result.outcome == "no-local-archives"
    assert calls.calls == []
    assert upload_restore_archives(TARGET, tmp_path / "missing", "/backup", remote=calls).outcome == "no-local-archives"


def test_remote_present_skips_transfer_even_for_other_requested_archive(tmp_path: Path) -> None:
    (tmp_path / "requested.tar.gz").touch()
    calls = Calls(present="present")
    result = upload_restore_archives(TARGET, tmp_path, "/custom/root", remote=calls, transfer=calls)
    assert result.outcome == "remote-present"
    assert calls.calls == [(REMOTE_PRESENT, ("/custom/root",), 900)]


@pytest.mark.parametrize(
    ("first", "expected"),
    [
        (None, "upload"),
        ("one.tar.gz", "present"),
        ("one.tar.zst", "present"),
        ("a.tar.xz", "upload"),
        ("a.tar.gz.extra", "present"),
        ("__NO_BACKUPS__.tar.gz", "upload"),
    ],
)
def test_real_shell_first_name_matches_original_classifier(tmp_path: Path, first: str | None, expected: str) -> None:
    if first:
        (tmp_path / first).touch()
        (tmp_path / "z.tar.gz").touch()
    result = SubprocessRunner()(REMOTE_PRESENT, (str(tmp_path),), 10)
    assert result.returncode == 0
    assert result.stdout == expected + "\n"


def test_all_archives_and_one_inventory_transport(tmp_path: Path) -> None:
    names = ["one.tar.gz", "two.tar.zst", "three.tar.xz"]
    for name in [*names, ".hidden.tar.gz", "unrelated"]:
        (tmp_path / name).write_text("synthetic")
    calls = Calls()
    result = upload_restore_archives(TARGET, tmp_path, "/custom/root", timeout=45, remote=calls, transfer=calls)
    assert result.outcome == "uploaded"
    assert result.transferred_entries == 3
    transfer = calls.calls[2]
    assert transfer[0] == 'exec "$@"\n'
    argv = transfer[1]
    assert argv[:4] == ("rsync", "-avz", "--progress", "--chmod=F600")
    assert argv[argv.index("-e") + 1] == "ssh -o BatchMode=yes -p 2222 -i /owned/key -o ConnectTimeout=20 -l root --"
    assert argv[argv.index("--") + 1 : -1] == tuple(str(tmp_path / name) for name in sorted(names))
    assert argv[-1] == f"inventory.example:{TEMPORARY}/"
    assert "--rsync-path=timeout -k 30 45 rsync" in argv
    assert calls.calls[-1] == (FINISH, (TEMPORARY, "/custom/root"), 45)


def test_dotfile_trigger_keeps_original_unmatched_glob_failure(tmp_path: Path) -> None:
    (tmp_path / ".hidden.tar.gz").touch()
    calls = Calls(failure="transfer")
    with pytest.raises(RestoreUploadError):
        upload_restore_archives(TARGET, tmp_path, "/backup", remote=calls, transfer=calls)
    assert str(tmp_path / "*.tar.*") in calls.calls[-1][1]


@pytest.mark.parametrize("stage", ["check", "prepare", "transfer", "finish"])
@pytest.mark.parametrize("timeout", [False, True])
def test_failures_stop_and_retain_partial_effect_identity(tmp_path: Path, stage: str, timeout: bool) -> None:
    (tmp_path / "one.tar.gz").touch()
    calls = Calls(failure=stage, timeout=timeout)
    with pytest.raises(RestoreUploadError) as caught:
        upload_restore_archives(TARGET, tmp_path, "/backup", remote=calls, transfer=calls)
    assert "private" not in str(caught.value)
    assert "archive/body" not in str(caught.value)
    assert caught.value.temporary_directory == (TEMPORARY if stage in {"transfer", "finish"} else None)
    assert len(calls.calls) == {"check": 1, "prepare": 2, "transfer": 3, "finish": 4}[stage]
    assert all("rm -rf" not in call[0] for call in calls.calls)


def test_actual_transfer_timeout_reaps_owned_child(tmp_path: Path) -> None:
    (tmp_path / "one.tar.gz").touch()
    pid = tmp_path / "child.pid"
    local = SubprocessRunner(stop_grace=0.1)

    def transfer(_script: str, _args: object, _timeout: float) -> CommandResult:
        return local('sleep 60 &\nprintf "%s" "$!" > "$1"\nwait\n', (str(pid),), 0.2)

    with pytest.raises(RestoreUploadError, match="transfer"):
        upload_restore_archives(TARGET, tmp_path, "/backup", remote=Calls(), transfer=transfer)
    child = int(pid.read_text())
    try:
        os.kill(child, 0)
    except ProcessLookupError:
        return
    # Linux can leave an already-dead orphan awaiting its init reaper.
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(child)], capture_output=True, text=True, check=False)
    assert state.stdout.strip().startswith("Z")


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0 or not shutil.which("rsync"),
    reason="owned Linux root/rsync fixture; never an inventory host",
)
@pytest.mark.parametrize("existing", [False, True])
def test_owned_linux_real_copy_modes_and_root_identity(tmp_path: Path, existing: bool) -> None:
    local = tmp_path / "local"
    local.mkdir()
    for name in ("one.tar.gz", "two.tar.xz"):
        (local / name).write_bytes(b"owned synthetic archive")
    root = tmp_path / "remote"
    if existing:
        root.mkdir(mode=0o750)
        os.chown(root, 1234, 1234)
        (root / "z-old.tar.xz").write_bytes(b"owned synthetic archive")
        (root / "z-old.tar.xz").chmod(0o644)
    runner = SubprocessRunner()
    temporary: list[str] = []

    def remote(script: str, args: object, timeout: float) -> CommandResult:
        assert isinstance(args, (tuple, list))
        result = runner(script, args, timeout)
        if script == PREPARE and result.ok:
            temporary.append(result.stdout.strip())
        return result

    def transfer(script: str, args: object, timeout: float) -> CommandResult:
        assert isinstance(args, (tuple, list))
        # Real rsync, with only its SSH transport replaced by a local owned path.
        sources = list(args[args.index("--") + 1 : -1])
        return runner(
            script, ["rsync", "-avz", "--progress", "--chmod=F600", "--", *sources, temporary[-1] + "/"], timeout
        )

    try:
        result = upload_restore_archives(TARGET, local, str(root), remote=remote, transfer=transfer)
        assert result.outcome == "uploaded"
        assert result.transferred_entries == 2
        assert root.stat().st_mode & 0o777 == (0o750 if existing else 0o700)
        assert (root.stat().st_uid, root.stat().st_gid) == ((1234, 1234) if existing else (0, 0))
        for path in root.iterdir():
            assert path.read_bytes() == b"owned synthetic archive"
            assert path.stat().st_mode & 0o777 == 0o600
            assert (path.stat().st_uid, path.stat().st_gid) == (root.stat().st_uid, root.stat().st_gid)
        assert all(not Path(path).exists() for path in temporary)
        before = {path.name: path.stat() for path in root.iterdir()}
        assert (
            upload_restore_archives(TARGET, local, str(root), remote=remote, transfer=transfer).outcome
            == "remote-present"
        )
        assert before == {path.name: path.stat() for path in root.iterdir()}
    finally:
        for temporary_path in temporary:
            shutil.rmtree(temporary_path, ignore_errors=True)


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0 or not shutil.which("rsync"),
    reason="owned Linux root/rsync fixture; never an inventory host",
)
@pytest.mark.parametrize("fault", ["transfer", "partial-move"])
def test_owned_linux_actual_partial_failures_are_retained(tmp_path: Path, fault: str) -> None:
    local = tmp_path / "local"
    local.mkdir()
    for name in [".hidden.tar.gz"] if fault == "transfer" else ["a.tar.gz", "z.tar.gz"]:
        (local / name).write_bytes(b"owned")
    root = tmp_path / "remote"
    runner = SubprocessRunner()
    temporary: list[str] = []

    def remote(script: str, args: object, timeout: float) -> CommandResult:
        assert isinstance(args, (tuple, list))
        result = runner(script, args, timeout)
        if script == PREPARE and result.ok:
            temporary.append(result.stdout.strip())
        return result

    def transfer(script: str, args: object, timeout: float) -> CommandResult:
        assert isinstance(args, (tuple, list))
        sources = list(args[args.index("--") + 1 : -1])
        result = runner(script, ["rsync", "-avz", "--chmod=F600", "--", *sources, temporary[-1] + "/"], timeout)
        if fault == "partial-move":
            # An owned conflict after admission forces real mv to fail after
            # the first archive moved; no static failure mock can prove this.
            (root / "z.tar.gz").mkdir()
        return result

    try:
        with pytest.raises(RestoreUploadError) as caught:
            upload_restore_archives(TARGET, local, str(root), remote=remote, transfer=transfer)
        assert root.is_dir()
        assert caught.value.stage == ("transfer" if fault == "transfer" else "finish")
        assert caught.value.temporary_directory == temporary[0]
        assert Path(temporary[0]).is_dir()
        if fault == "partial-move":
            assert (root / "a.tar.gz").read_bytes() == b"owned"
            assert (Path(temporary[0]) / "z.tar.gz").read_bytes() == b"owned"
            assert (root / "z.tar.gz").is_dir()
    finally:
        for temporary_path in temporary:
            shutil.rmtree(temporary_path, ignore_errors=True)
