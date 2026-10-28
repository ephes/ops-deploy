"""Scanner credential flow on synthetic inputs, without reading local shadow."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

SOURCE = Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/scanner_password.py"
SPEC = importlib.util.spec_from_file_location("paperless_scanner_password", SOURCE)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize("stored", [None, "!", "*", "old-synthetic-verifier"])
def test_probe_is_status_only_and_never_updates(stored: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(MODULE, "read_verifier", lambda username: stored)
    monkeypatch.setattr(MODULE, "matches", lambda password, verifier: False)
    assert MODULE.reconcile({"username": "scanner", "password": "synthetic:@;&", "apply": False}) == (
        "missing" if stored is None else "pending"
    )


def test_current_password_and_empty_do_not_call_chpasswd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(MODULE, "read_verifier", lambda username: "synthetic-current")
    monkeypatch.setattr(MODULE, "matches", lambda password, verifier: True)
    assert MODULE.reconcile({"username": "scanner", "password": "synthetic", "apply": True}) == "current"
    assert MODULE.reconcile({"username": "scanner", "password": "", "apply": True}) == "unmanaged"


def test_change_uses_only_stdin_verifies_and_repeat_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {"verifier": "synthetic-old"}
    calls: list[tuple[list[str], dict[str, Any]]] = []
    monkeypatch.setattr(MODULE, "read_verifier", lambda username: state["verifier"])
    monkeypatch.setattr(MODULE, "matches", lambda password, verifier: verifier == "synthetic-new")

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((argv, kwargs))
        state["verifier"] = "synthetic-new"
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(MODULE.subprocess, "run", run)
    payload = {"username": "scanner", "password": "synthetic:@;&", "apply": True}
    assert MODULE.reconcile(payload) == "changed"
    assert MODULE.reconcile(payload) == "current"
    assert len(calls) == 1
    assert calls[0][0] == ["chpasswd"]
    assert calls[0][1]["input"] == "scanner:synthetic:@;&\n"
    assert calls[0][1]["stdout"] == subprocess.DEVNULL
    assert calls[0][1]["stderr"] == subprocess.DEVNULL


def test_missing_account_is_not_silently_created(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(MODULE, "read_verifier", lambda username: None)
    with pytest.raises(MODULE.Refusal, match="must exist"):
        MODULE.reconcile({"username": "scanner", "password": "synthetic", "apply": True})


@pytest.mark.parametrize("answer", [None, b"*0"])
def test_libcrypt_error_refuses_instead_of_approving_rotation(
    answer: bytes | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Crypt:
        def __call__(self, password: bytes, stored: bytes) -> bytes | None:
            assert password == b"synthetic"
            assert stored == b"$y$synthetic-verifier"
            return answer

    monkeypatch.setattr(MODULE.ctypes, "CDLL", lambda name: SimpleNamespace(crypt=Crypt()))
    with pytest.raises(MODULE.Refusal, match="libcrypt"):
        MODULE.matches("synthetic", "$y$synthetic-verifier")


def test_bad_payload_never_prints_synthetic_password() -> None:
    secret = "synthetic-must-not-appear"
    result = subprocess.run(
        [sys.executable, str(SOURCE)],
        input=json.dumps({"username": "root", "password": secret, "apply": True}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert secret not in result.stderr
    assert "Traceback" not in result.stderr
