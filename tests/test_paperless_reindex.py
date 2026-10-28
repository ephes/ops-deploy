"""Owned execution-boundary tests; simulated systemd is not native proof."""

from __future__ import annotations

import importlib.util
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "paperless_reindex", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/reindex.py"
)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SETTINGS = {
    "username": "paperless",
    "service_name": "paperless",
    "env_file": "/home/paperless/site/.env",
    "python_bin": "/home/paperless/site/.venv/bin/python",
    "manage_dir": "/home/paperless/site/paperless-ngx/src",
    "index_dir": "/mnt/cryptdata/paperless/data/index",
}
UNITS = ("paperless.service", "paperless-worker.service", "paperless-scheduler.service", "paperless-consumer.service")


class Commands:
    def __init__(self, failure: str = "") -> None:
        self.failure = failure
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if argv[:2] == ["systemctl", "show"]:
            assert kwargs == {"capture": True}
            state = "active" if argv[-1] in {UNITS[0], UNITS[3]} else "inactive"
            if self.failure == "unstable":
                state = "activating"
            return subprocess.CompletedProcess(argv, 0, state + "\n", "")
        if argv[0] == "runuser":
            assert kwargs == {"cwd": SETTINGS["manage_dir"]}
            if self.failure == "exception":
                raise OSError("synthetic private content must not reach CLI")
            return subprocess.CompletedProcess(argv, 2 if self.failure in {"reindex", "both"} else 0, "", "")
        failed = (self.failure == "stop" and argv == ["systemctl", "stop", UNITS[1]]) or (
            self.failure in {"resume", "both"} and argv == ["systemctl", "start", UNITS[0]]
        )
        return subprocess.CompletedProcess(argv, int(failed), "", "")


def test_success_stops_all_and_resumes_only_previously_running(monkeypatch: pytest.MonkeyPatch) -> None:
    commands = Commands()
    monkeypatch.setattr(MODULE, "call", commands)
    assert MODULE.reindex(SETTINGS) == {"reindexed": True, "resumed_units": 2}
    assert commands.calls[4:8] == [["systemctl", "stop", unit] for unit in UNITS]
    assert commands.calls[-2:] == [["systemctl", "start", UNITS[0]], ["systemctl", "start", UNITS[3]]]
    assert commands.calls[8] == [
        "runuser",
        "-u",
        "paperless",
        "--",
        "bash",
        "-euc",
        "set -a; . /home/paperless/site/.env; set +a; exec "
        + shlex.join([SETTINGS["python_bin"], "-c", MODULE.PREPARE_AND_REINDEX, SETTINGS["index_dir"]]),
    ]


@pytest.mark.parametrize("failure", ["stop", "reindex", "resume", "both", "exception"])
def test_failure_resumes_every_previous_unit_and_normal_retry(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    commands = Commands(failure)
    monkeypatch.setattr(MODULE, "call", commands)
    with pytest.raises((MODULE.ReindexFailure, OSError)):
        MODULE.reindex(SETTINGS)
    assert commands.calls[-2:] == [["systemctl", "start", UNITS[0]], ["systemctl", "start", UNITS[3]]]
    if failure == "stop":
        assert not any(argv[0] == "runuser" for argv in commands.calls)
    commands.failure = ""
    assert MODULE.reindex(SETTINGS)["reindexed"]


def test_unstable_state_refuses_before_service_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    commands = Commands("unstable")
    monkeypatch.setattr(MODULE, "call", commands)
    with pytest.raises(MODULE.ReindexFailure, match="stable"):
        MODULE.reindex(SETTINGS)
    assert all(argv[:2] == ["systemctl", "show"] for argv in commands.calls)


@pytest.mark.parametrize(
    ("key", "value"), [("username", "root"), ("manage_dir", "/srv/../etc"), ("env_file", "/tmp/a;id")]
)
def test_invalid_settings_refuse_before_command(key: str, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    commands = Commands()
    monkeypatch.setattr(MODULE, "call", commands)
    with pytest.raises(ValueError, match=r"invalid|non-root"):
        MODULE.reindex(dict(SETTINGS, **{key: value}))
    assert not commands.calls


def test_application_output_never_enters_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 2, "", "")

    monkeypatch.setattr(MODULE.subprocess, "run", run)
    MODULE.call(["synthetic-application"])
    assert seen["stdout"] == subprocess.DEVNULL
    assert seen["stderr"] == subprocess.DEVNULL
    assert seen["stdin"] == subprocess.DEVNULL


@pytest.fixture
def ensure_index() -> Any:
    namespace: dict[str, Any] = {"__name__": "owned_local_test"}
    exec(compile(MODULE.PREPARE_AND_REINDEX, "<service-user index preparation>", "exec"), namespace)
    return namespace["ensure_index"]


def test_missing_entire_index_is_created_and_existing_directory_untouched(tmp_path: Path, ensure_index: Any) -> None:
    data = tmp_path.resolve() / "data"
    data.mkdir()
    index = data / "index"
    assert not index.exists()
    ensure_index(str(index))
    assert index.is_dir()
    assert index.stat().st_uid == os.getuid()
    assert index.stat().st_gid == os.getgid()
    sentinel = index / "synthetic-metadata"
    sentinel.write_text("owned")
    before = (index.stat(), sentinel.stat(), sentinel.read_bytes())
    ensure_index(str(index))
    after = (index.stat(), sentinel.stat(), sentinel.read_bytes())
    # atime may advance on reads; every other stat field and nanosecond write
    # timestamps remain exact, including the existing directory inode/mode/owner.
    for old, new in zip(before[:2], after[:2], strict=True):
        assert tuple(old[:7]) + tuple(old[8:]) == tuple(new[:7]) + tuple(new[8:])
        assert (old.st_mtime_ns, old.st_ctime_ns) == (new.st_mtime_ns, new.st_ctime_ns)
    assert before[2] == after[2]


@pytest.mark.parametrize("kind", ["leaf-link", "parent-link", "file", "missing-parent"])
def test_index_creation_refuses_unsafe_or_missing_parents_without_repair(
    tmp_path: Path, ensure_index: Any, kind: str
) -> None:
    root = tmp_path.resolve()
    foreign = root / "foreign"
    foreign.mkdir()
    (foreign / "sentinel").write_text("untouched")
    data = root / "data"
    if kind == "parent-link":
        data.symlink_to(foreign, target_is_directory=True)
    elif kind != "missing-parent":
        data.mkdir()
    index = data / "index"
    if kind == "leaf-link":
        index.symlink_to(foreign, target_is_directory=True)
    elif kind == "file":
        index.write_text("not a directory")
    before = {path.name: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()) for path in foreign.iterdir()}
    with pytest.raises(
        (FileNotFoundError, NotADirectoryError, OSError), match=r"No such file|Not a directory|Too many levels"
    ):
        ensure_index(str(index))
    assert {
        path.name: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()) for path in foreign.iterdir()
    } == before
    if kind == "missing-parent":
        assert not data.exists()


def test_actual_child_prepares_missing_leaf_before_unchanged_manage_command(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    data = root / "data"
    data.mkdir()
    index = data / "index"
    # The original upstream wipe_index starts by iterating this missing path.
    # An actual child command demonstrates that prerequisite failure, then the
    # exact service-user bootstrap executes the same management argv successfully.
    (root / "manage.py").write_text(
        "import pathlib,sys\n"
        "assert sys.argv[1:]==['document_index','reindex']\n"
        + "list(pathlib.Path("
        + repr(str(index))
        + ").iterdir())\n"
    )
    old = subprocess.run([sys.executable, "manage.py", "document_index", "reindex"], cwd=root, capture_output=True)
    assert old.returncode != 0
    assert b"FileNotFoundError" in old.stderr
    fixed = subprocess.run(
        [sys.executable, "-c", MODULE.PREPARE_AND_REINDEX, str(index)], cwd=root, capture_output=True
    )
    assert fixed.returncode == 0, fixed.stderr.decode()
    assert index.stat().st_uid == os.getuid()


def test_payload_binds_configured_data_index() -> None:
    import json

    from ops_deploy.services.paperless.commands import reindex_payload
    from ops_deploy.services.paperless.config import PaperlessConfig

    cfg = PaperlessConfig(traefik_domain="example.invalid", external_storage_root="/srv/owned-paperless")
    assert json.loads(reindex_payload(cfg))["index_dir"] == "/srv/owned-paperless/data/index"
