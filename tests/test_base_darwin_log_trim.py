"""darwin_log_trim: the plist, the trim script's behaviour, and the deploy's operations."""

from __future__ import annotations

import gzip
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base.darwin_log_trim import (
    DarwinLogTrimConfig,
    ancestry_command,
    deploy_darwin_log_trim,
    fingerprint,
    loaded_command,
    render_plist,
    render_script,
)
from ops_deploy.helpers.probes import probe_command
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

LOGS = ("/private/var/log/voxhelm/voxhelm.log", "/private/var/log/voxhelm-remote-worker/worker.err.log")
SCRIPT = "/usr/local/libexec/ops-deploy/log-trim"
PLIST = "/Library/LaunchDaemons/de.wersdoerfer.log-trim.plist"
DARWIN = {"uname -s": ["Darwin"]}
TRIM_PROGRAM_PATH = Path(__file__).parent.parent / "src/ops_deploy/base/files/darwin_log_trim.py"


def cfg(**changes: Any) -> DarwinLogTrimConfig:
    return DarwinLogTrimConfig.model_validate({"logs": LOGS, **changes})


def test_plist_runs_the_script_with_size_keep_and_files() -> None:
    plist = plistlib.loads(render_plist(cfg(max_bytes=2 * 1024 * 1024, keep=3, hour=5, minute=7)).encode())

    assert plist["Label"] == "de.wersdoerfer.log-trim"
    assert plist["ProgramArguments"] == ["/usr/bin/python3", "-I", SCRIPT, str(2 * 1024 * 1024), "3", *LOGS]
    assert plist["StartCalendarInterval"] == {"Hour": 5, "Minute": 7}
    assert plist["StandardOutPath"] == plist["StandardErrorPath"] == "/private/var/log/ops-log-trim.log"
    assert "RunAtLoad" not in plist


@pytest.mark.parametrize(
    "changes",
    [
        {"logs": ()},
        {"logs": ("relative.log",)},
        {"logs": ("/private/var/log/a b.log",)},
        {"logs": ("/private/var/log/../etc/passwd",)},
        {"logs": ("/private/var/log//a.log",)},
        {"logs": ("/private/var/log/x/",)},
        {"logs": ("/var/log/a.log",)},
        {"logs": ("/Users/jochen/a.log",)},
        {"logs": ("/private/var/log/a.log", "/private/var/log/a.log")},
        {"logs": ("/private/var/log/a.log", "/private/var/log/A.log")},
        {"logs": ("/private/var/log/ops-log-trim.log",)},
        {"logs": ("/private/var/log/x.log", "/private/var/log/x.log.trim-truncated")},
        {"logs": ("/private/var/log/",)},
        {"max_bytes": 1024},
        {"keep": 0},
        {"hour": 24},
        {"logs": ("/private/var/log/a.log", "/private/var/log/a.log.1.gz")},
        {"logs": ("/private/var/log/a.log", "/private/var/log/A.LOG.1.GZ")},
        {"logs": ("/private/var/log/a.log", "/private/var/log/a.log.trim-tmp")},
        {"logs": ("/private/var/log/a.log", "/private/var/log/a.log.trim-done")},
    ],
)
def test_invalid_configs_are_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        cfg(**changes)


darwin_only = pytest.mark.skipif(sys.platform != "darwin", reason="BSD stat; the script targets macOS")


def run_script(tmp_path: Path, max_bytes: int, keep: int, *logs: Path) -> subprocess.CompletedProcess[str]:
    script = tmp_path.parent / f"{tmp_path.name}-log-trim"
    script.write_text(render_script())
    return subprocess.run(
        ["/usr/bin/python3", "-I", str(script), str(max_bytes), str(keep), *map(str, logs)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@darwin_only
def test_script_copies_truncates_and_compresses_large_files_only(tmp_path: Path) -> None:
    big, small = tmp_path / "big.log", tmp_path / "small.log"
    big.write_text("x" * 2000)
    small.write_text("y" * 10)

    result = run_script(tmp_path, 1000, 3, big, small, tmp_path / "missing.log")

    assert result.returncode == 0, result.stderr
    assert big.read_text() == ""
    assert gzip.decompress((tmp_path / "big.log.1.gz").read_bytes()).decode() == "x" * 2000
    assert small.read_text() == "y" * 10
    assert not (tmp_path / "small.log.1.gz").exists()
    assert f"{big}: trimmed size=2000" in result.stdout
    assert (tmp_path / "big.log.1.gz").stat().st_mode & 0o777 == big.stat().st_mode & 0o777


@darwin_only
def test_script_shifts_generations_and_drops_the_oldest(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    for generation in range(1, 4):
        log.write_text(str(generation) * 2000)
        assert run_script(tmp_path, 1000, 2, log).returncode == 0
    copies = sorted(p.name for p in tmp_path.glob("a.log.*"))

    assert copies == ["a.log.1.gz", "a.log.2.gz"]
    assert gzip.decompress((tmp_path / "a.log.1.gz").read_bytes()).decode() == "3" * 2000
    assert gzip.decompress((tmp_path / "a.log.2.gz").read_bytes()).decode() == "2" * 2000


@darwin_only
def test_script_keeps_an_appending_writer_at_the_start(tmp_path: Path) -> None:
    log = tmp_path / "w.log"
    with log.open("a") as writer:
        writer.write("z" * 2000)
        writer.flush()
        assert run_script(tmp_path, 1000, 1, log).returncode == 0
        writer.write("after")
        writer.flush()

    assert log.read_text() == "after"


@darwin_only
def test_script_leaves_symlinks_alone(tmp_path: Path) -> None:
    target = tmp_path / "target.log"
    target.write_text("t" * 2000)
    link = tmp_path / "link.log"
    link.symlink_to(target)

    result = run_script(tmp_path, 1000, 1, link)

    # A symbolic link is not the file's canonical path.
    assert result.returncode == 1
    assert "refused" in result.stdout
    assert target.read_text() == "t" * 2000


@darwin_only
def test_script_leaves_hard_linked_files_alone(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_text("h" * 2000)
    (tmp_path / "other").hardlink_to(log)

    run_script(tmp_path, 1000, 1, log)

    assert log.read_text() == "h" * 2000


@darwin_only
def test_script_refuses_a_directory_others_can_write(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    log = shared / "a.log"
    log.write_text("s" * 2000)

    result = run_script(tmp_path, 1000, 1, log)

    assert result.returncode == 1
    assert "refused" in result.stdout
    assert log.read_text() == "s" * 2000


@darwin_only
def test_script_does_not_follow_a_planted_archive_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    log = tmp_path / "a.log"
    log.write_text("l" * 2000)
    (tmp_path / "a.log.trim-tmp").symlink_to(victim)

    result = run_script(tmp_path, 1000, 1, log)

    assert victim.read_text() == "keep me"
    assert log.read_text() == "l" * 2000
    assert result.returncode == 1
    assert "not a regular file" in result.stdout


def load_program() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location("darwin_log_trim_program", TRIM_PROGRAM_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@darwin_only
def test_a_failed_compression_leaves_the_log_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    program = load_program()
    log = tmp_path / "a.log"
    log.write_text("c" * 2000)

    def broken(self: Any, data: bytes) -> int:
        raise OSError("disk full")

    reached = []

    def broken_and_seen(self: Any, data: bytes) -> int:
        reached.append(len(data))
        return broken(self, data)

    monkeypatch.setattr(program.gzip.GzipFile, "write", broken_and_seen)

    assert program.main(["log-trim", "1000", "1", str(log)]) == 1
    assert reached
    assert log.read_text() == "c" * 2000
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.log"]


@darwin_only
def test_an_interrupted_compression_is_discarded(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_text("p" * 2000)
    (tmp_path / "a.log.trim-tmp").write_bytes(b"partial gzip")
    (tmp_path / "a.log.1.gz").write_bytes(gzip.compress(b"older"))

    result = run_script(tmp_path, 1000, 2, log)

    assert result.returncode == 0, result.stdout
    assert "removed an interrupted copy" in result.stdout
    assert gzip.decompress((tmp_path / "a.log.1.gz").read_bytes()) == b"p" * 2000
    assert gzip.decompress((tmp_path / "a.log.2.gz").read_bytes()) == b"older"


@darwin_only
def test_an_interrupted_shift_loses_no_generation(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_text("g" * 2000)
    # A shift .2 -> .3 happened, .1 -> .2 did not: slot 2 is free.
    (tmp_path / "a.log.1.gz").write_bytes(gzip.compress(b"one"))
    (tmp_path / "a.log.3.gz").write_bytes(gzip.compress(b"two"))

    assert run_script(tmp_path, 1000, 3, log).returncode == 0
    assert gzip.decompress((tmp_path / "a.log.1.gz").read_bytes()) == b"g" * 2000
    assert gzip.decompress((tmp_path / "a.log.2.gz").read_bytes()) == b"one"
    assert gzip.decompress((tmp_path / "a.log.3.gz").read_bytes()) == b"two"


@darwin_only
def test_a_locked_directory_is_skipped(tmp_path: Path) -> None:
    import fcntl
    import os

    log = tmp_path / "a.log"
    log.write_text("k" * 2000)
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        result = run_script(tmp_path, 1000, 1, log)
    finally:
        os.close(fd)

    assert "another rotation holds the directory" in result.stdout
    assert log.read_text() == "k" * 2000


@darwin_only
def test_a_non_canonical_path_is_refused(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_text("q" * 2000)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path)

    result = run_script(tmp_path, 1000, 1, alias / "a.log")

    assert result.returncode == 1
    assert "refused" in result.stdout
    assert log.read_text() == "q" * 2000


@darwin_only
def test_a_copy_left_after_truncation_is_recovered_first(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    (tmp_path / "a.log.trim-done").write_bytes(gzip.compress(b"first"))
    (tmp_path / "a.log.1.gz").write_bytes(gzip.compress(b"zeroth"))
    log.write_text("n" * 2000)

    result = run_script(tmp_path, 1000, 3, log)

    assert result.returncode == 0, result.stdout
    assert "published a copy left by an interrupted run" in result.stdout
    # One rotation per run: the file itself waits for the next run.
    assert gzip.decompress((tmp_path / "a.log.1.gz").read_bytes()) == b"first"
    assert gzip.decompress((tmp_path / "a.log.2.gz").read_bytes()) == b"zeroth"
    assert log.read_text() == "n" * 2000


def converged(c: DarwinLogTrimConfig, loaded: str = "loaded") -> dict[str, Any]:
    return {
        **DARWIN,
        **fakehost.directory("/usr/local/libexec/ops-deploy"),
        **fakehost.directory("/Library/LaunchDaemons"),
        **fakehost.file(SCRIPT, render_script(), mode="-rwxr-xr-x"),
        **fakehost.file(PLIST, render_plist(c)),
        probe_command(ancestry_command(c)): ["trusted"],
        probe_command(loaded_command(c)): [fingerprint(c) if loaded == "loaded" else loaded],
    }


def test_converged_host_changes_nothing() -> None:
    c = cfg()
    responses = converged(c)
    # fakehost reports root:root; the deploy wants root:wheel.
    for path in ("/usr/local/libexec/ops-deploy", SCRIPT, PLIST):
        key = f"test -e {path} ||"
        responses[key] = [responses[key][0].replace("group=root", "group=wheel")]
    result = run_deploy_fake(deploy_darwin_log_trim, c, responses=responses)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []


def test_first_run_installs_and_loads() -> None:
    c = cfg()
    responses = {
        **DARWIN,
        probe_command(ancestry_command(c)): ["trusted"],
        probe_command(loaded_command(c)): ["missing"],
    }
    result = run_deploy_fake(deploy_darwin_log_trim, c, responses=responses)

    assert result.succeeded, result.error
    assert result.upload(SCRIPT).decode() == render_script()
    assert result.upload(PLIST).decode() == render_plist(c)
    load = next(cmd for cmd in result.executed_commands if "launchctl bootstrap" in cmd)
    assert load == (
        "/bin/rm -f /private/var/db/ops-deploy/de.wersdoerfer.log-trim.loaded && "
        "/bin/launchctl enable system/de.wersdoerfer.log-trim && "
        "{ /bin/launchctl bootout system/de.wersdoerfer.log-trim 2>/dev/null; true; } && "
        f"/bin/launchctl bootstrap system {PLIST} && /bin/mkdir -p /private/var/db/ops-deploy && "
        f"printf '%s\\n' {fingerprint(c)} > /private/var/db/ops-deploy/de.wersdoerfer.log-trim.loaded"
    )


def test_a_changed_file_list_reloads_the_job() -> None:
    old, new = cfg(), cfg(logs=(*LOGS, "/private/var/log/other.log"))
    responses = converged(old)
    result = run_deploy_fake(deploy_darwin_log_trim, new, responses=responses)

    assert result.succeeded, result.error
    assert result.upload(PLIST).decode() == render_plist(new)
    assert any("launchctl bootstrap" in cmd for cmd in result.executed_commands)


def test_linux_is_refused() -> None:
    result = run_deploy_fake(deploy_darwin_log_trim, cfg(), responses=dict(fakehost.LINUX))

    assert not result.succeeded
    assert "macOS hosts only" in str(result.error)


def test_files_current_but_loaded_from_an_older_plist_reloads() -> None:
    c = cfg()
    responses = converged(c)
    responses[probe_command(loaded_command(c))] = ["0" * 64]
    result = run_deploy_fake(deploy_darwin_log_trim, c, responses=responses)

    assert result.succeeded, result.error
    assert any("launchctl bootstrap" in cmd for cmd in result.executed_commands)
    assert result.uploads == []


def test_untrusted_directories_stop_the_deploy() -> None:
    c = cfg()
    responses = {**converged(c), probe_command(ancestry_command(c)): ["untrusted /usr/local/libexec/ops-deploy"]}
    result = run_deploy_fake(deploy_darwin_log_trim, c, responses=responses)

    assert not result.succeeded
    assert "not root's alone (owner, mode or ACL): /usr/local/libexec/ops-deploy" in str(result.error)
    assert result.executed_commands == []


def test_ancestry_check_on_this_machine() -> None:
    import shlex as _shlex

    out = subprocess.run(_shlex.split(ancestry_command(cfg())), capture_output=True, text=True, timeout=30, check=False)
    if sys.platform != "darwin" or out.returncode != 0:
        pytest.skip("macOS python3 only")
    lines = out.stdout.splitlines()
    assert lines == ["trusted"] or (lines and all(line.startswith("untrusted /") for line in lines))


@darwin_only
def test_a_complete_copy_is_published_even_if_the_file_regrew(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_text("r" * 10)
    (tmp_path / "a.log.trim-done").write_bytes(gzip.compress(b"copy"))

    result = run_script(tmp_path, 100000, 2, log)

    assert result.returncode == 0, result.stdout
    assert gzip.decompress((tmp_path / "a.log.1.gz").read_bytes()) == b"copy"
    assert log.read_text() == "r" * 10


@darwin_only
def test_a_directory_in_a_generation_slot_stops_before_the_copy(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_text("d" * 2000)
    (tmp_path / "a.log.1.gz").mkdir()

    result = run_script(tmp_path, 1000, 2, log)

    assert result.returncode == 1
    assert "a.log.1.gz is not a regular file" in result.stdout
    assert log.read_text() == "d" * 2000
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.log", "a.log.1.gz"]


@darwin_only
def test_acls_are_seen_also_next_to_extended_attributes(tmp_path: Path) -> None:
    program = load_program()
    entry = tmp_path / "f"
    entry.write_text("x")
    subprocess.run(["/usr/bin/xattr", "-w", "com.example.x", "y", str(entry)], check=True)
    assert not program.has_acl(str(entry))
    subprocess.run(["/bin/chmod", "+a", "everyone deny write", str(entry)], check=True)
    try:
        assert program.has_acl(str(entry))
    finally:
        subprocess.run(["/bin/chmod", "-N", str(entry)], check=True)


@darwin_only
def test_the_staged_copy_is_root_or_runner_only_until_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    program = load_program()
    log = tmp_path / "a.log"
    log.write_text("m" * 2000)
    log.chmod(0o644)
    seen = []
    real = program.os.ftruncate

    def spy(fd: int, length: int) -> None:
        seen.append(oct((tmp_path / "a.log.trim-done").stat().st_mode & 0o777))
        real(fd, length)

    monkeypatch.setattr(program.os, "ftruncate", spy)

    assert program.main(["log-trim", "1000", "1", str(log)]) == 0
    assert seen == ["0o600"]
    assert (tmp_path / "a.log.1.gz").stat().st_mode & 0o777 == 0o644
    assert os.stat(log).st_size == 0
