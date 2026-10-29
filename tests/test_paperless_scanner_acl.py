"""Scanner default ACL command parity; real ACL/mask behavior needs Linux."""

from __future__ import annotations

import importlib.util
import io
import subprocess
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "paperless_scanner_acl", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/scanner_acl.py"
)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Process:
    def __init__(self, body: bytes, code: int = 0) -> None:
        self.stdout = io.BytesIO(body)
        self.code = code

    def __enter__(self) -> Process:
        return self

    def __exit__(self, *args: Any) -> None:
        self.stdout.close()

    def wait(self) -> int:
        return self.code

    def kill(self) -> None:
        self.code = -9


@pytest.mark.parametrize(
    ("body", "changed"),
    [(b"/synthetic/consume: *,*\n", False), (b"/synthetic/consume: *,user::rwx,user:123:rwx,mask::rwx\n", True)],
)
def test_original_ansible_setfacl_test_predicate(body: bytes, changed: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def popen(argv: list[str], **kwargs: Any) -> Process:
        seen.append(argv)
        assert kwargs["stderr"] == subprocess.DEVNULL
        return Process(body)

    monkeypatch.setattr(MODULE.subprocess, "Popen", popen)
    argv = MODULE.command({"directory": "/synthetic/consume", "username": "scanner", "apply": False})
    assert MODULE.would_change(argv) is changed
    assert seen == [["setfacl", "--test", "-d", "-m", "user:scanner:rwx", "--recursive", "/synthetic/consume"]]


@pytest.mark.parametrize(("body", "code"), [(b"", 0), (b"/synthetic: *,*\n", 1), (b"x" * (1024 * 1024 + 1), 0)])
def test_failed_or_malformed_probe_does_not_become_current(
    body: bytes, code: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MODULE.subprocess, "Popen", lambda *args, **kwargs: Process(body, code))
    with pytest.raises(MODULE.Refusal, match=r"probe failed|exceeds limit"):
        MODULE.would_change(["setfacl", "/synthetic/consume"])


def test_one_change_and_healthy_repeat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    states = iter([True, False, False])
    monkeypatch.setattr(MODULE, "would_change", lambda argv: next(states))
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(MODULE.subprocess, "run", run)
    payload = {"directory": str(tmp_path), "username": "scanner", "apply": True}
    assert MODULE.reconcile(payload) == "changed"
    assert MODULE.reconcile(payload) == "current"
    assert len(calls) == 1


def test_symlink_root_refuses_before_acl_command(tmp_path: Path) -> None:
    link = tmp_path / "consume"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(MODULE.Refusal, match="real directory"):
        MODULE.reconcile({"directory": str(link), "username": "scanner", "apply": True})


def test_missing_root_is_planned_but_apply_refuses(tmp_path: Path) -> None:
    payload = {"directory": str(tmp_path / "consume"), "username": "scanner", "apply": False}
    assert MODULE.reconcile(payload) == "missing"
    with pytest.raises(MODULE.Refusal, match="must exist"):
        MODULE.reconcile(dict(payload, apply=True))
