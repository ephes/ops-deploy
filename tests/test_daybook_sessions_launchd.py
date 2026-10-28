"""Exact timer ordering/failure semantics using owned synthetic launchctl."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.test_daybook_sessions_controls import RESOURCES, load_module
from tests.test_daybook_sessions_resources import config

with patch.dict(sys.modules, {"ops_sessions_resources": RESOURCES}):
    LAUNCHD = load_module("ops_sessions_launchd", "files/launchd_host.py")


def command_backend(
    *, loaded: bool, disabled: bool, running: bool = False
) -> tuple[Callable[..., subprocess.CompletedProcess[bytes]], list[tuple[str, ...]]]:
    state = {"loaded": loaded, "disabled": disabled}
    mutations: list[tuple[str, ...]] = []

    def command(*argv: str) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "print":
            return subprocess.CompletedProcess(
                argv, 0 if state["loaded"] else 113, b"state = running\n" if running else b"state = waiting\n", b""
            )
        if argv[0] == "print-disabled":
            value = b"true" if state["disabled"] else b"false"
            return subprocess.CompletedProcess(argv, 0, b'{"owned.timer" => ' + value + b"}", b"")
        mutations.append(argv)
        if argv[0] == "bootout":
            state["loaded"] = False
        elif argv[0] == "disable":
            state["disabled"] = True
        elif argv[0] == "enable":
            state["disabled"] = False
        elif argv[0] == "bootstrap":
            state["loaded"] = True
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    return command, mutations


def test_retired_idle_timer_unload_disable_remove_and_repeat_zero_mutations(tmp_path: Path) -> None:
    plist = tmp_path.resolve() / "owned.plist"
    plist.write_text("owned timer definition")
    launchd = LAUNCHD.Launchd("gui/98765")
    backend, mutations = command_backend(loaded=True, disabled=False)
    with patch.object(launchd, "command", side_effect=backend):
        launchd.retire("owned.timer", str(plist))
        assert mutations == [("bootout", "gui/98765/owned.timer"), ("disable", "gui/98765/owned.timer")]
        assert not plist.exists()
        mutations.clear()
        launchd.retire("owned.timer", str(plist))
        assert mutations == []


@pytest.mark.parametrize("state", ["running", "spawning"])
def test_in_flight_retired_timer_refuses_before_unload_or_plist_change(tmp_path: Path, state: str) -> None:
    plist = tmp_path.resolve() / "owned.plist"
    plist.write_text("protected owned timer")
    before = plist.stat()
    launchd = LAUNCHD.Launchd("gui/98765")
    backend, mutations = command_backend(loaded=True, disabled=False)

    def command(*argv: str) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "print":
            return subprocess.CompletedProcess(argv, 0, ("state = " + state).encode(), b"")
        return backend(*argv)

    with (
        patch.object(launchd, "command", side_effect=command),
        pytest.raises(RuntimeError, match="sessions_timer_in_flight"),
    ):
        launchd.retire("owned.timer", str(plist))
    assert mutations == []
    assert plist.stat() == before


def test_enabled_timer_reload_only_when_resource_changes_without_kickstart(tmp_path: Path) -> None:
    launchd = LAUNCHD.Launchd("gui/98765")
    backend, mutations = command_backend(loaded=True, disabled=False)
    with patch.object(launchd, "command", side_effect=backend):
        launchd.enable("owned.timer", str(tmp_path / "owned.plist"), changed=False)
        assert mutations == []
        launchd.enable("owned.timer", str(tmp_path / "owned.plist"), changed=True)
        assert mutations == [
            ("bootout", "gui/98765", str(tmp_path / "owned.plist")),
            ("bootstrap", "gui/98765", str(tmp_path / "owned.plist")),
        ]
        assert all(row[0] != "kickstart" for row in mutations)


def test_unknown_launchctl_failure_cannot_be_treated_as_unloaded() -> None:
    launchd = LAUNCHD.Launchd("gui/98765")
    with (
        patch.object(launchd, "command", return_value=subprocess.CompletedProcess([], 1, b"private stderr", b"")),
        pytest.raises(RuntimeError, match="sessions_launchd_unavailable"),
    ):
        launchd.state("owned.timer")


@pytest.mark.parametrize(
    ("word", "expected"), [("true", True), ("disabled", True), ("false", False), ("enabled", False)]
)
def test_actual_and_legacy_disabled_state_spellings(word: str, expected: bool) -> None:
    launchd = LAUNCHD.Launchd("gui/98765")

    def command(*argv: str) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "print":
            return subprocess.CompletedProcess(argv, 113, b"", b"")
        return subprocess.CompletedProcess(argv, 0, ('{"owned.timer" => ' + word + "}").encode(), b"")

    with patch.object(launchd, "command", side_effect=command):
        assert launchd.state("owned.timer")["disabled"] is expected


def test_original_early_quiescence_is_system_manage_only_with_no_arbitrary_unit() -> None:
    for declaration in (
        config(daybook_sessions_launchd_manage_state=False),
        config(daybook_sessions_launchd_scope="user"),
    ):
        with patch.object(LAUNCHD, "Launchd", side_effect=AssertionError("not applicable")):
            LAUNCHD.quiesce_reconcile(declaration.model_dump(mode="json"))
    cfg = config().model_dump(mode="json")
    calls: list[tuple[str, ...]] = []
    states = iter([{"loaded": True, "disabled": False}, {"loaded": False, "disabled": True}])
    with (
        patch.object(LAUNCHD.Launchd, "state", side_effect=lambda _label: next(states)),
        patch.object(LAUNCHD.Launchd, "mutate", side_effect=lambda *argv: calls.append(argv)),
    ):
        LAUNCHD.quiesce_reconcile(cfg)
    label = "de.wersdoerfer.daybook.weeknotes-reconcile"
    assert calls == [
        ("disable", "system/" + label),
        ("bootout", "system/" + label),
    ]
    cfg["daybook_weeknotes_reconcile_launchd_label"] = "another.unit"
    with (
        patch.object(LAUNCHD, "Launchd", side_effect=AssertionError("wrong identity cannot execute")),
        pytest.raises(RuntimeError, match="sessions_reconcile_identity_invalid"),
    ):
        LAUNCHD.quiesce_reconcile(cfg)


def test_exact_system_quiesce_recovers_loaded_unit_without_relying_on_a_plist() -> None:
    cfg = config().model_dump(mode="json")
    label = "de.wersdoerfer.daybook.weeknotes-reconcile"
    states = iter([{"loaded": True, "disabled": False}, {"loaded": False, "disabled": True}])
    calls: list[tuple[str, ...]] = []

    def mutate(*argv: str) -> None:
        assert cfg["daybook_weeknotes_reconcile_launchd_plist_path"] not in argv
        calls.append(argv)

    with (
        patch.object(LAUNCHD.Launchd, "state", side_effect=lambda name: next(states)),
        patch.object(LAUNCHD.Launchd, "mutate", side_effect=mutate),
    ):
        LAUNCHD.quiesce_reconcile(cfg)
    assert calls == [("disable", "system/" + label), ("bootout", "system/" + label)]
