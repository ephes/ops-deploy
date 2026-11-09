"""Owned runner admission and strict filesystem observer boundaries."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[1]
HARNESS = ROOT / "tests/integration/mail_web/harness.py"


def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("owned_mail_web_fixture", HARNESS)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "line",
    [
        '1 openat(AT_FDCWD, "/tmp/write", O_WRONLY|O_CREAT, 0600) = 3',
        '1 chmod("/etc/config", 0644) = 0',
        '1 openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = 3',
        '1 unlink("/tmp/file") = 0',
    ],
)
def test_trace_rejects_writes(line: str) -> None:
    with pytest.raises(AssertionError):
        harness().trace_read_only(line)


def test_trace_accepts_reads_and_exact_absent_tty() -> None:
    harness().trace_read_only(
        '1 openat(AT_FDCWD, "/etc/config", O_RDONLY) = 3\n'
        '1 openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = -1 ENXIO (No such device or address)'
    )


def test_runner_refuses_outside_owned_github_before_commands() -> None:
    result = subprocess.run(
        ["bash", str(HARNESS.with_name("run.sh"))], env={"PATH": "/usr/bin:/bin"}, capture_output=True
    )
    assert result.returncode != 0
    assert result.stdout == b""


def test_runner_syntax() -> None:
    subprocess.run(["bash", "-n", str(HARNESS.with_name("run.sh"))], check=True)


def test_trace_ignores_write_tokens_inside_exec_source() -> None:
    harness().trace_read_only('1 execve("/usr/bin/python3", ["python3", "-c", "os.chmod("/tmp/file", 0644)"], []) = 0')


def test_upgrader_observer_counts_only_successful_actual_exec() -> None:
    module = harness()
    good = '21 execve("/usr/bin/php", ["php", "public/upgrade.php"], []) = 0'
    assert module.is_upgrader_exec(good)
    assert not module.is_upgrader_exec(good.replace(" = 0", " = -1 ENOENT (No such file or directory)"))
    assert not module.is_upgrader_exec('21 execve("/usr/bin/python3", ["python3", "public/upgrade.php"], []) = 0')
