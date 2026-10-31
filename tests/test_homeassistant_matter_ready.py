"""Owned startup diagnostics, real subprocess bounds and phase admission."""

from __future__ import annotations

import contextlib
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from tests.integration.homeassistant import diagnose_matter, matrix, matter_ready


def unit(pid: str = "42", restarts: str = "0", active: str = "active") -> dict[str, Any]:
    return {
        "command": {"exit": 0, "truncated": False, "timed_out": False},
        "properties": {
            "Id": "matter-server.service",
            "LoadState": "loaded",
            "ActiveState": active,
            "SubState": "running",
            "MainPID": pid,
            "NRestarts": restarts,
        },
    }


@pytest.mark.parametrize("failure", [None, "port", "state", "pid", "restarts", "command"])
def test_ready_requires_continuous_stable_identity_and_port(
    monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    clock = [0.0]
    receipts: dict[str, Any] = {}
    collected = []
    monkeypatch.setattr("tests.integration.homeassistant.matter_ready.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "tests.integration.homeassistant.matter_ready.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )

    def observe(**kwargs: Any) -> dict[str, Any]:
        assert 0 < kwargs["timeout"] <= 5
        result = unit()
        if failure == "state":
            result["properties"]["ActiveState"] = "activating"
        if failure == "pid":
            result["properties"]["MainPID"] = str(42 + int(clock[0]))
        if failure == "restarts":
            result["properties"]["NRestarts"] = str(int(clock[0]))
        if failure == "command":
            result["command"]["timed_out"] = True
        return result

    def connect(address: tuple[str, int], **kwargs: Any) -> Any:
        assert address == ("127.0.0.1", 5580)
        assert 0 < kwargs["timeout"] <= 1
        if failure == "port":
            raise ConnectionRefusedError
        return contextlib.nullcontext()

    monkeypatch.setattr(matter_ready, "observe", observe)
    monkeypatch.setattr("tests.integration.homeassistant.matter_ready.socket.create_connection", connect)
    monkeypatch.setattr(matter_ready, "write", lambda name, body: receipts.update({name: body}))
    monkeypatch.setattr(matter_ready, "diagnostics", lambda: collected.append(True))
    if failure:
        with pytest.raises(RuntimeError, match="stably ready"):
            matter_ready.wait_ready(timeout=8, stable_seconds=4)
    else:
        matter_ready.wait_ready(timeout=8, stable_seconds=4)
        assert clock[0] == 4
    assert collected == [True]
    assert receipts["matter-readiness.json"]["ready"] is (failure is None)
    assert 3 <= len(receipts["matter-readiness.json"]["samples"]) <= 4


def test_interrupted_health_resets_stability_window(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    monkeypatch.setattr("tests.integration.homeassistant.matter_ready.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "tests.integration.homeassistant.matter_ready.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    monkeypatch.setattr(
        matter_ready, "observe", lambda **kwargs: unit(active="activating" if clock[0] == 2 else "active")
    )
    monkeypatch.setattr(
        "tests.integration.homeassistant.matter_ready.socket.create_connection",
        lambda *args, **kwargs: contextlib.nullcontext(),
    )
    monkeypatch.setattr(matter_ready, "write", lambda *args: None)
    monkeypatch.setattr(matter_ready, "diagnostics", lambda: None)
    matter_ready.wait_ready(timeout=10, stable_seconds=4)
    assert clock[0] == 8


@pytest.mark.parametrize(("timeout", "stable"), [(float("inf"), 20), (91, 20), (0, 0), (5, 6), (5, float("nan"))])
def test_invalid_bounds_never_spawn(monkeypatch: pytest.MonkeyPatch, timeout: float, stable: float) -> None:
    monkeypatch.setattr(matter_ready, "observe", lambda **kwargs: pytest.fail("must refuse before spawn"))
    with pytest.raises(ValueError, match="bounds"):
        matter_ready.wait_ready(timeout=timeout, stable_seconds=stable)


@pytest.mark.parametrize("mode", ["success", "limit", "timeout"])
def test_actual_command_output_timeout_bounds_and_reaping(mode: str) -> None:
    script = {
        "success": "print('owned diagnostic')",
        "limit": "import os; os.write(1,b'x'*2000000)",
        "timeout": "import time; time.sleep(20)",
    }[mode]
    started = time.monotonic()
    result = matter_ready.bounded_command(
        [sys.executable, "-I", "-B", "-c", script], timeout=0.2 if mode == "timeout" else 5
    )
    assert time.monotonic() - started < 8
    assert result["truncated"] is (mode == "limit")
    assert result["timed_out"] is (mode == "timeout")
    assert len(result["output"].encode()) <= matter_ready.LIMIT
    assert result["exit"] == 0 if mode == "success" else result["exit"] is not None


@pytest.mark.parametrize("timeout", [False, True])
def test_signalling_precedes_reaping_and_never_follows_normal_completion(
    monkeypatch: pytest.MonkeyPatch, timeout: bool
) -> None:
    original_killpg = os.killpg
    signalled = []

    def killpg(pid: int, selected: int) -> None:
        assert selected == signal.SIGKILL
        # waitpid(WNOHANG) would reap a zombie, so use waitid's WNOWAIT probe.
        # A live child gives None; a zombie stays held. ECHILD would expose
        # the old implementation's post-reap signal before calling killpg.
        waitid = getattr(os, "waitid", None)
        if waitid is not None and hasattr(os, "WNOWAIT"):
            waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        signalled.append(pid)
        original_killpg(pid, selected)

    monkeypatch.setattr("tests.integration.homeassistant.matter_ready.os.killpg", killpg)
    script = "import time; time.sleep(20)" if timeout else "print('owned')"
    result = matter_ready.bounded_command([sys.executable, "-I", "-B", "-c", script], timeout=0.2 if timeout else 5)
    assert result["timed_out"] is timeout
    assert len(signalled) == (1 if timeout else 0)


@pytest.mark.parametrize("kind", ["regular", "missing", "symlink", "fifo"])
def test_diagnostics_bound_log_and_refuse_nonregular_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str
) -> None:
    log = tmp_path / "matter.log"
    if kind == "regular":
        log.write_bytes(b"prefix" + b"x" * matter_ready.LIMIT)
    elif kind == "symlink":
        target = tmp_path / "unread-target"
        target.write_text("must not export")
        log.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(log)
    monkeypatch.setattr(matter_ready, "LOG", log)
    monkeypatch.setattr(matter_ready, "observe", unit)
    calls: list[Any] = []

    def command(argv: list[str], **kwargs: Any) -> dict[str, Any]:
        calls.append(argv)
        assert argv == ["journalctl", "--no-pager", "--unit=matter-server.service", "--lines=200", "--output=short-iso"]
        assert kwargs["timeout"] == 10
        return {"output": "owned startup traceback", "exit": 0, "truncated": False, "timed_out": False}

    monkeypatch.setattr(matter_ready, "bounded_command", command)
    receipts: dict[str, Any] = {}
    monkeypatch.setattr(matter_ready, "write", lambda name, body: receipts.update({name: body}))
    matter_ready.diagnostics()
    result = receipts["matter-startup-diagnostics.json"]
    assert len(calls) == 1
    assert result["journal"]["output"] == "owned startup traceback"
    if kind == "regular":
        assert result["log"] == {"output": "x" * matter_ready.LIMIT, "truncated": True}
    else:
        assert result["log"] == ({"absent": True} if kind == "missing" else {"collection_failed": True})


@pytest.mark.parametrize("case", ["current", "upgrade"])
@pytest.mark.parametrize("failure", ["native", "ready"])
def test_original_bootstrap_cannot_reach_selected_or_typed_with_unready_matter(
    monkeypatch: pytest.MonkeyPatch, case: str, failure: str
) -> None:
    calls: list[Any] = []
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", case)
    monkeypatch.setattr(matrix, "seed", lambda *args: calls.append("seed"))
    monkeypatch.setattr(matrix, "original_vars", lambda *args: {})
    monkeypatch.setattr(matrix, "original", lambda name, variables: calls.append(name))

    def refuse() -> None:
        raise RuntimeError("owned unready")

    def native() -> None:
        calls.append("native")
        if failure == "native":
            refuse()

    monkeypatch.setattr(matrix, "verify_native_dependencies", native)
    monkeypatch.setattr(matrix, "diagnostics", lambda: calls.append("diagnostics"))
    monkeypatch.setattr(matrix, "wait_ready", refuse)
    monkeypatch.setattr(matrix, "wait_http", lambda: pytest.fail("must not reach onboarding or later matrix"))
    with pytest.raises(RuntimeError, match="owned unready"):
        matrix.run()
    assert calls == ["seed", "00-original-existing-host-bootstrap", "native"] + (
        ["diagnostics"] if failure == "native" else []
    )


@pytest.mark.parametrize("failure", [None, "bootstrap", "native", "ready"])
def test_diagnostic_is_only_admitted_seed_original_and_readiness(
    monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    calls: list[Any] = []
    receipts = {}
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "current")
    monkeypatch.setattr(diagnose_matter, "admit", lambda: calls.append("admit"))
    monkeypatch.setattr(diagnose_matter, "seed", lambda version: calls.append(("seed", version)))
    monkeypatch.setattr(diagnose_matter, "original_vars", lambda version: {"version": version})

    def original(label: str, variables: dict[str, str]) -> None:
        calls.append((label, variables))
        if failure == "bootstrap":
            raise RuntimeError("owned failure")

    def ready() -> None:
        calls.append("ready")
        if failure == "ready":
            raise RuntimeError("owned failure")

    def native() -> None:
        calls.append("native")
        if failure == "native":
            raise RuntimeError("owned failure")

    monkeypatch.setattr(diagnose_matter, "verify_native_dependencies", native)
    monkeypatch.setattr(diagnose_matter, "original", original)
    monkeypatch.setattr(diagnose_matter, "wait_ready", ready)
    monkeypatch.setattr(diagnose_matter, "diagnostics", lambda: calls.append("diagnostics"))
    monkeypatch.setattr(diagnose_matter, "write", lambda name, body: receipts.update({name: body}))
    if failure:
        with pytest.raises(RuntimeError, match="owned failure"):
            diagnose_matter.run()
    else:
        diagnose_matter.run()
    assert calls[:3] == [
        "admit",
        ("seed", "2026.10.2"),
        ("00-original-existing-host-bootstrap", {"version": "2026.10.2"}),
    ]
    assert calls[3:] == (
        ["diagnostics"] if failure == "bootstrap" else ["native", "diagnostics" if failure == "native" else "ready"]
    )
    assert receipts["summary.json"]["completed"] is (failure is None)
    assert receipts["summary.json"]["typed_phases_executed"] == 0


def test_full_matrix_entry_keeps_corrected_library_and_both_cases() -> None:
    from tests.integration.homeassistant.harness import ORIGINAL_LIBRARY_SHA

    script = Path("tests/integration/homeassistant/run-guest.sh").read_text()
    assert script.endswith(".venv/bin/python -m tests.integration.homeassistant.harness\n")
    assert "[[ ${HOMEASSISTANT_FIXTURE_CASE:?} == current || ${HOMEASSISTANT_FIXTURE_CASE:?} == upgrade ]]" in script
    assert "== upgrade" in script
    assert "checkout --detach " + ORIGINAL_LIBRARY_SHA + "\n" in script
    assert '[[ $(git -C "$OPS_LIBRARY_PATH" rev-parse HEAD) == ' + ORIGINAL_LIBRARY_SHA + " ]]\n" in script
    assert "tests.integration.homeassistant.diagnose_interpreter\n" not in script
    assert "tests.integration.homeassistant.diagnose_matter\n" not in script


def test_rejected_upgrade_keeps_actual_case_and_performs_no_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "upgrade")
    monkeypatch.setattr(diagnose_matter, "admit", lambda: None)
    monkeypatch.setattr(diagnose_matter, "seed", lambda *args: pytest.fail("diagnostic is current-only"))
    receipts: dict[str, Any] = {}
    monkeypatch.setattr(diagnose_matter, "write", lambda name, body: receipts.update({name: body}))
    with pytest.raises(AssertionError):
        diagnose_matter.run()
    assert receipts["summary.json"]["case"] == "upgrade"
    assert receipts["summary.json"]["completed"] is False
