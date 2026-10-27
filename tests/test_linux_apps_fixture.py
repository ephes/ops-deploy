"""The owned encrypted_volume/open_webui fixture: runner admission, trace classifier, workflow guard."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).parents[1]
HARNESS = ROOT / "tests/integration/linux_apps/harness.py"
WORKFLOW = ROOT / ".github/workflows/linux-apps-integration.yml"


def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("owned_linux_apps_fixture", HARNESS)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "line",
    [
        '1 openat(AT_FDCWD, "/etc/fstab", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3',
        '1 rename("/etc/.ops-deploy-fstab.x", "/etc/fstab") = 0',
        '1 mount("/dev/mapper/cryptdata", "/mnt/cryptdata", NULL, MS_REMOUNT, NULL) = 0',
        '1 umount2("/mnt/cryptdata", 0) = 0',
        '1 chmod("/root/.luks-key-cryptdata", 0400) = 0',
        '1 openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = 3',
    ],
)
def test_trace_reports_writes(line: str) -> None:
    assert harness().trace_writes(line) == [line]


def test_trace_accepts_reads_null_and_absent_tty() -> None:
    assert (
        harness().trace_writes(
            '1 openat(AT_FDCWD, "/etc/fstab", O_RDONLY|O_CLOEXEC) = 3\n'
            '1 openat(AT_FDCWD, "/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3\n'
            '1 openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = -1 ENXIO (No such device or address)\n'
            '1 execve("/usr/bin/python3", ["python3", "-c", "os.chmod(x)"], 0x0 /* 3 vars */) = 0'
        )
        == []
    )


def test_executed_argv_is_parsed() -> None:
    line = '12 execve("/usr/bin/mount", ["mount", "-o", "remount", "/mnt/cryptdata"], 0x55 /* 20 vars */) = 0'
    assert harness().executed(line + '\n13 execve("/x", ["x"], 0x0) = -1 ENOENT') == [
        ["mount", "-o", "remount", "/mnt/cryptdata"]
    ]


def test_executed_argv_survives_split_calls() -> None:
    trace = (
        '7 execve("/usr/sbin/mount", ["mount", "/mnt/cryptdata"], 0x1 /* 9 vars */ <unfinished ...>\n'
        '8 execve("/usr/sbin/findmnt", ["findmnt"], 0x1 /* 9 vars */ <unfinished ...>\n'
        "7 <... execve resumed>) = 0\n"
        "8 <... execve resumed>) = -1 ENOENT (No such file or directory)\n"
    )
    assert harness().executed(trace) == [["mount", "/mnt/cryptdata"]]


def test_runner_refuses_outside_owned_github_before_commands() -> None:
    result = subprocess.run(
        ["bash", str(HARNESS.with_name("run.sh"))], env={"PATH": "/usr/bin:/bin"}, capture_output=True
    )
    assert result.returncode != 0
    assert result.stdout == b""


def test_runner_syntax() -> None:
    subprocess.run(["bash", "-n", str(HARNESS.with_name("run.sh"))], check=True)


def test_workflow_is_guarded_and_pinned() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    triggers = workflow[True]  # YAML 1.1 reads ``on`` as true
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["pyinfra-linux-apps-20261027"]
    assert workflow["permissions"] == {"contents": "read"}
    [job] = workflow["jobs"].values()
    assert job["runs-on"] == "ubuntu-24.04"
    for step in job["steps"]:
        if "uses" in step:
            assert "@" in step["uses"]
            assert len(step["uses"].split("@")[1].split()[0]) == 40, step["uses"]
        if step.get("uses", "").startswith("actions/checkout"):
            assert step["with"]["persist-credentials"] is False
    text = WORKFLOW.read_text()
    assert "pull_request_target" not in text
    assert "secrets." not in text
    assert 'git+https://github.com/ephes/ops-deploy.git@$IMPLEMENTATION_SHA"' in text
