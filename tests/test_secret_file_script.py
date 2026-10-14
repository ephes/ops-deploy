"""Fault injection for the ``secret_file`` host installer.

The installer source is run exactly as shipped (``python3 -I -c <source>``)
for stream and signal faults, and imported for step faults (failing write,
``fchmod`` or rename). The destination must stay untouched and no temp file
may survive; symlinks on the path are never followed.
"""

import base64
import contextlib
import os
import shlex
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import _secret_install
from ops_deploy.ops.secret_file import encode_payload, install_command, temp_tag

OLD = b"OLD=keep-me\n"
NEW = SecretContent(b"NEW=hunter2\n" * 4096)


@pytest.fixture
def dest(tmp_path: Path) -> Path:
    # Resolve /var -> /private/var on macOS: the installer refuses symlinks.
    path = tmp_path.resolve() / "secrets.env"
    path.write_bytes(OLD)
    path.chmod(0o600)
    return path


def _argv(dest: Path, content: SecretContent = NEW, mode: str = "0600") -> list[str]:
    argv = shlex.split(install_command(PurePosixPath(dest), len(content), mode=mode))
    return [sys.executable, *argv[1:]]


def _payload(content: SecretContent = NEW) -> bytes:
    return encode_payload(content).encode()


def _temps(dest: Path) -> list[Path]:
    return sorted(dest.parent.glob(f"{_secret_install.TEMP_PREFIX}*"))


def _run(argv: list[str], stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, input=stdin, capture_output=True, check=False)


def test_installs_content_with_mode(dest: Path) -> None:
    result = _run(_argv(dest, mode="0640"), _payload())

    assert result.returncode == 0, result.stderr
    assert dest.read_bytes() == NEW.reveal()
    assert stat.S_IMODE(dest.stat().st_mode) == 0o640
    assert _temps(dest) == []


def test_creates_missing_destination(dest: Path) -> None:
    target = dest.parent / "new.env"

    assert _run(_argv(target), _payload()).returncode == 0

    assert target.read_bytes() == NEW.reveal()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_binary_content_round_trips(dest: Path) -> None:
    blob = SecretContent(bytes(range(256)) * 7)

    assert _run(_argv(dest, blob), _payload(blob)).returncode == 0

    assert dest.read_bytes() == blob.reveal()


@pytest.mark.parametrize("cut", [0, 4, 1000, 1001, -2], ids=["empty", "one-quantum", "aligned", "unaligned", "tail"])
def test_truncated_stream_leaves_destination_untouched(dest: Path, cut: int) -> None:
    result = _run(_argv(dest), _payload()[:cut])

    assert result.returncode == 1
    assert b"interrupted upload" in result.stderr or b"base64" in result.stderr
    assert dest.read_bytes() == OLD
    assert _temps(dest) == []


def test_errors_never_echo_the_payload(dest: Path) -> None:
    result = _run(_argv(dest), b"not base64 hunter2!!")

    assert result.returncode == 1
    assert b"hunter2" not in result.stdout + result.stderr


def _start_and_feed_half(dest: Path) -> subprocess.Popen[bytes]:
    payload = _payload()
    proc = subprocess.Popen(
        _argv(dest),
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert proc.stdin is not None
    proc.stdin.write(payload[: len(payload) // 2])
    proc.stdin.flush()
    time.sleep(0.3)  # let the interpreter start and block on the rest of stdin
    return proc


def _finish(proc: subprocess.Popen[bytes]) -> int:
    if proc.stdin is not None and not proc.stdin.closed:
        with contextlib.suppress(BrokenPipeError):
            proc.stdin.close()
    return proc.wait(timeout=10)


@pytest.mark.parametrize("sig", [signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGKILL], ids=lambda s: s.name)
def test_signal_mid_stream_keeps_destination(dest: Path, sig: signal.Signals) -> None:
    proc = _start_and_feed_half(dest)

    os.killpg(proc.pid, sig)

    assert _finish(proc) != 0
    assert dest.read_bytes() == OLD
    assert _temps(dest) == []


def test_connection_drop_mid_stream_keeps_destination(dest: Path) -> None:
    # Without a pty, sshd closes stdin when the client goes away; no signal.
    proc = _start_and_feed_half(dest)

    assert _finish(proc) == 1
    assert dest.read_bytes() == OLD
    assert _temps(dest) == []


@pytest.mark.parametrize("step", ["write", "fchmod", "fsync", "rename"])
def test_failing_step_keeps_destination_and_removes_staging(
    dest: Path, step: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        # The staged file exists and is 0600 when any of these steps runs.
        [stage] = _temps(dest)
        assert stat.S_IMODE(stage.lstat().st_mode) == 0o700
        assert stat.S_IMODE((stage / _secret_install.STAGED).lstat().st_mode) == 0o600
        raise OSError(5, "injected")

    monkeypatch.setattr(os, step, fail)

    with pytest.raises(OSError, match="injected"):
        _install(dest)

    assert dest.read_bytes() == OLD
    assert _temps(dest) == []


@pytest.mark.parametrize("step", ["fsync", "rmdir"])
def test_failure_after_the_rename_still_reports_success(dest: Path, step: str, monkeypatch: pytest.MonkeyPatch) -> None:
    original = getattr(os, step)
    renamed: list[bool] = []
    original_rename = os.rename

    def rename(*args: object, **kwargs: object) -> None:
        original_rename(*args, **kwargs)  # type: ignore[arg-type]
        renamed.append(True)

    def fail_after_commit(*args: object, **kwargs: object) -> object:
        if renamed:
            raise OSError(5, "injected")
        return original(*args, **kwargs)

    monkeypatch.setattr(os, "rename", rename)
    monkeypatch.setattr(os, step, fail_after_commit)

    _install(dest)

    assert dest.read_bytes() == NEW.reveal()


def test_swapping_the_staging_directory_name_cannot_redirect_the_install(
    dest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Someone who may write the destination directory renames the staging
    # directory away and plants a symlink under its name after staging.
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    (decoy / _secret_install.STAGED).symlink_to(tmp_path / "elsewhere")
    original = _secret_install.write_staged

    def write_then_swap(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        [stage] = _temps(dest)
        stage.rename(tmp_path / "moved-away")
        stage.symlink_to(decoy)

    monkeypatch.setattr(_secret_install, "write_staged", write_then_swap)

    _install(dest)

    assert not dest.is_symlink()
    assert dest.read_bytes() == NEW.reveal()


@pytest.mark.parametrize(
    "swap",
    ["foreign-owner", "group-writable", "not-empty"],
)
def test_replaced_staging_directory_is_refused(dest: Path, swap: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulates another user swapping the freshly created staging directory
    # between mkdir and open.
    real_fstat = os.fstat
    real_mkdir = os.mkdir

    def fstat(fd: int) -> Any:
        info = real_fstat(fd)
        if swap == "foreign-owner":
            return os.stat_result((info.st_mode, *info[1:4], os.geteuid() + 1, *info[5:]))
        if swap == "group-writable":
            return os.stat_result((info.st_mode | 0o077, *info[1:]))
        return info

    def mkdir(path: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        real_mkdir(path, mode, dir_fd=dir_fd)
        if swap == "not-empty":
            os.open(os.path.join(path, "planted"), os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=dir_fd)

    monkeypatch.setattr(os, "fstat", fstat)
    monkeypatch.setattr(os, "mkdir", mkdir)

    with pytest.raises(_secret_install.InstallError, match="replaced"):
        _install(dest)

    assert dest.read_bytes() == OLD


def test_leftover_swapped_after_stat_is_not_emptied(
    dest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    leftover = _leftover(dest, "deadbeef")
    leftover.mkdir(mode=0o700)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    (other / "data").write_bytes(b"precious")
    real_stat = os.stat

    def stat_then_swap(path: Any, *args: Any, **kwargs: Any) -> Any:
        info = real_stat(path, *args, **kwargs)
        if path == leftover.name:
            leftover.rmdir()
            other.rename(leftover)
        return info

    monkeypatch.setattr(os, "stat", stat_then_swap)

    _install(dest)

    assert (leftover / "data").read_bytes() == b"precious"


def test_leftover_with_open_permissions_is_not_emptied(dest: Path) -> None:
    leftover = _leftover(dest, "deadbeef")
    leftover.mkdir()
    leftover.chmod(0o777)
    (leftover / "data").write_bytes(b"precious")

    _install(dest)

    assert (leftover / "data").read_bytes() == b"precious"


def _install(dest: Path, content: SecretContent = NEW, mode: int = 0o600) -> None:
    import io

    stream = io.BytesIO(base64.encodebytes(content.reveal()))
    _secret_install.install(
        str(dest.parent), dest.name, temp_tag(PurePosixPath(dest)), len(content), mode, None, None, stream
    )


def _leftover(dest: Path, suffix: str) -> Path:
    return dest.parent / f"{_secret_install.TEMP_PREFIX}{temp_tag(PurePosixPath(dest))}.{suffix}"


def test_leftover_from_killed_run_is_removed(dest: Path) -> None:
    leftover = _leftover(dest, "deadbeef")
    leftover.mkdir(mode=0o700)
    # After fchown the staged file may belong to the target user; the
    # directory still belongs to the connecting user, which is what counts.
    (leftover / _secret_install.STAGED).write_bytes(b"stale secret")

    _install(dest)

    assert not leftover.exists()
    assert dest.read_bytes() == NEW.reveal()


def test_leftover_cleanup_never_follows_symlinks(dest: Path, tmp_path: Path) -> None:
    victim_dir = tmp_path / "victim"
    victim_dir.mkdir()
    (victim_dir / "precious").write_bytes(b"precious")
    _leftover(dest, "link").symlink_to(victim_dir)

    _install(dest)

    assert (victim_dir / "precious").read_bytes() == b"precious"


def test_other_files_temps_are_left_alone(dest: Path) -> None:
    other = dest.parent / f"{_secret_install.TEMP_PREFIX}{temp_tag(PurePosixPath('/x/other.env'))}.cafe"
    other.mkdir()

    _install(dest)

    assert other.exists()


def test_symlinked_directory_component_is_refused(dest: Path, tmp_path: Path) -> None:
    real = tmp_path.resolve() / "real"
    real.mkdir()
    (tmp_path.resolve() / "alias").symlink_to(real)
    target = tmp_path.resolve() / "alias" / "secrets.env"

    with pytest.raises(_secret_install.InstallError, match="alias"):
        _install(target)

    assert list(real.iterdir()) == []


def test_symlink_at_destination_is_replaced_not_followed(dest: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    dest.unlink()
    dest.symlink_to(victim)

    _install(dest)

    assert victim.read_bytes() == b"precious"
    assert not dest.is_symlink()
    assert dest.read_bytes() == NEW.reveal()


def test_unknown_owner_fails_before_anything_is_written(dest: Path) -> None:
    argv = shlex.split(install_command(PurePosixPath(dest), len(NEW), mode="0600", user="no-such-user-xyz"))

    result = _run([sys.executable, *argv[1:]], _payload())

    assert result.returncode == 1
    assert b"no-such-user-xyz" in result.stderr
    assert dest.read_bytes() == OLD
    assert _temps(dest) == []
