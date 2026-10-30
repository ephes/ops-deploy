"""Original two-lane ordering, failure proofs and no private-body access."""

from __future__ import annotations

import importlib.resources
import os
import subprocess
import types
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.daybook_controls import DaybookControlConfig
from ops_deploy.services.daybook_controls import deploy as api
from ops_deploy.testing import run_deploy_fake


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    module = types.ModuleType("owned_inbox_emergency")
    body = (
        importlib.resources.files("ops_deploy.services.daybook_controls")
        .joinpath("files/inbox_emergency_host.py")
        .read_text()
    )
    exec(compile(body, "owned_inbox_emergency", "exec"), module.__dict__)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    return module


class Launchd:
    def __init__(
        self, *, quiet: bool = False, broken_disable: bool = False, broken_bootout: bool = False, gui: bool = True
    ):
        self.labels = ("owned.normal", "owned.long")
        self.disabled = {label: quiet for label in self.labels}
        self.loaded = {label: not quiet for label in self.labels}
        self.broken_disable, self.broken_bootout, self.gui = broken_disable, broken_bootout, gui
        self.calls: list[tuple[str, str]] = []

    def run(self, argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        assert argv[0] == "/bin/launchctl"
        action, target = argv[1:]
        self.calls.append((action, target))
        rc, out, err = 0, b"", b""
        if action == "print-disabled":
            out = (
                b"{\n"
                + b"".join((f'   "{label}"   =>   true\n').encode() for label, value in self.disabled.items() if value)
                + b"}"
            )
        elif action == "print" and target == "gui/501":
            rc = 0 if self.gui else 112
        else:
            assert target.startswith("gui/501/")
            label = target.removeprefix("gui/501/")
            assert label in self.labels
            if action == "print":
                if not self.loaded[label]:
                    rc, err = 113, b"Could not find service"
            elif action == "disable":
                if self.broken_disable and label == self.labels[0]:
                    rc = 9
                else:
                    self.disabled[label] = True
            elif action == "bootout":
                if self.broken_bootout and label == self.labels[0]:
                    rc = 9
                else:
                    self.loaded[label] = False
            else:
                raise AssertionError(action)
        return subprocess.CompletedProcess(argv, rc, out, err)


def request() -> dict[str, Any]:
    # Mechanism only: original production label validation is separate below.
    return {"service": "inbox", "action": "disable", "uid": 501, "label": "owned.normal", "long_label": "owned.long"}


def mutations(ctl: Launchd) -> list[tuple[str, str]]:
    return [call for call in ctl.calls if call[0] in {"disable", "bootout"}]


@pytest.mark.parametrize("quiet", [False, True])
def test_both_overrides_before_either_bootout_even_on_repeat(
    helper: Any, quiet: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctl = Launchd(quiet=quiet)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Emergency operator must not open files")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    result = helper.execute(request(), run=ctl.run)
    assert result["both_disabled_unloaded"] is True
    assert result["previously_disabled_unloaded"] is quiet
    assert mutations(ctl) == [(action, "gui/501/" + label) for action in ("disable", "bootout") for label in ctl.labels]


@pytest.mark.parametrize("failure", ["broken_disable", "broken_bootout"])
def test_mutation_failure_does_not_skip_second_lane_but_final_proof_refuses(helper: Any, failure: str) -> None:
    ctl = Launchd(**{failure: True})
    with pytest.raises(helper.InboxControlError):
        helper.execute(request(), run=ctl.run)
    assert len(mutations(ctl)) == 4


def test_missing_gui_refuses_before_mutation(helper: Any) -> None:
    ctl = Launchd(gui=False)
    with pytest.raises(helper.InboxControlError):
        helper.execute(request(), run=ctl.run)
    assert not mutations(ctl)


def test_lost_final_gui_refuses_instead_of_claiming_quiet(helper: Any) -> None:
    ctl = Launchd()
    original = ctl.run

    def run(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        if argv[1] == "bootout":
            ctl.gui = False
        return original(argv)

    with pytest.raises(helper.InboxControlError):
        helper.execute(request(), run=run)
    assert len(mutations(ctl)) == 4


def test_exact_original_two_label_declaration() -> None:
    cfg = DaybookControlConfig(service="inbox", action="disable", owner="jochen")
    assert cfg.label == "de.wersdoerfer.daybook.voice-memo-inbox"
    assert cfg.long_label == cfg.label + "-long"
    for change in ({"long_label": "unrelated"}, {"label": "unrelated"}, {"action": "remove"}):
        with pytest.raises(ValidationError):
            DaybookControlConfig(**{"service": "inbox", "action": "disable", "owner": "jochen", **change})
    with pytest.raises(ValidationError):
        DaybookControlConfig(service="photos", action="disable", owner="jochen", long_label=cfg.long_label)


def test_actual_sdk_one_managed_zero_upload_and_root_admission() -> None:
    cfg = DaybookControlConfig(service="inbox", action="disable", owner="fixture")
    for uid in ("0", "501"):
        result = run_deploy_fake(
            api.run_daybook_control,
            cfg,
            responses={"uname -s": ["Darwin"], "/usr/bin/id -u fixture": ["501"], "/usr/bin/id -u": [uid]},
        )
        assert result.succeeded is (uid == "0")
        assert len(result.mutating_changed_ops) == (1 if uid == "0" else 0)
        assert result.uploaded_paths == []
