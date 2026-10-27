"""Guard the owned fixture's exact ephemeral-thread-name exception."""

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api.command import StringCommand


@pytest.fixture
def fixture_module(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setattr(sys, "argv", ["harness.py", str(tmp_path)])
    path = Path(__file__).parent / "integration/dns/harness.py"
    spec = importlib.util.spec_from_file_location("dns_trace_fixture", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIG = '12 execve("/usr/bin/dig", ["dig"], []) = 0\n'
COMM = '12 openat(AT_FDCWD, "/proc/self/task/14/comm", O_RDWR) = 11'


def test_actual_connector_command_types(fixture_module: Any) -> None:
    assert fixture_module.raw_command("uname -s") == "uname -s"
    assert fixture_module.raw_command(StringCommand("uname", "-s")) == "uname -s"


def test_dig_thread_name_and_read_only_file(fixture_module: Any) -> None:
    fixture_module.assert_trace(DIG + COMM)
    fixture_module.assert_trace('12 openat(AT_FDCWD, "/etc/unbound/unbound.conf", O_RDONLY) = 3')


@pytest.mark.parametrize(
    "trace",
    [
        COMM,
        DIG + COMM.replace("12 openat", "13 openat"),
        DIG.replace(" = 0", " = -1 ENOENT") + COMM,
        DIG + '12 execve("/usr/bin/other", ["other"], []) = -1 ENOENT\n' + COMM,
        DIG.replace("/usr/bin/dig", "/usr/bin/python3") + COMM,
        DIG + COMM.replace("/proc/self/task/14/comm", "/proc/sys/kernel/hostname"),
        DIG + COMM.replace("O_RDWR", "O_RDWR|O_CREAT"),
        DIG + COMM.replace(" = 11", " = -1 EACCES"),
        DIG + COMM.replace("/proc/self/task/14/comm", "/etc/unbound/unbound.conf"),
        DIG + "12 +++ exited with 0 +++\n" + COMM,
        DIG + "12 +++ killed by SIGKILL +++\n" + COMM,
        DIG + '12 openat(AT_FDCWD, "/tmp/staging", O_WRONLY|O_CREAT, 0600) = 3',
    ],
)
def test_other_mutations_are_not_thread_naming(fixture_module: Any, trace: str) -> None:
    with pytest.raises(AssertionError):
        fixture_module.assert_trace(trace)
