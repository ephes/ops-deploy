"""Owned filesystem first/repeat; launchd is synthetic and no app is imported."""

from __future__ import annotations

import grp
import os
import pwd
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tests import test_daybook_sessions_controls as control_cases
from tests.test_daybook_sessions_controls import CONTROLS, RESOURCES, load_module, snapshot
from tests.test_daybook_sessions_launchd import LAUNCHD
from tests.test_daybook_sessions_resources import config

with patch.dict(
    sys.modules,
    {"ops_sessions_resources": RESOURCES, "ops_sessions_controls": CONTROLS, "ops_sessions_launchd": LAUNCHD},
):
    STAGE = load_module("ops_sessions_resource_stage", "files/resource_stage.py")

controls = control_cases.controls


class Timers:
    domain = "gui/98765"

    def __init__(self) -> None:
        self.states: dict[str, dict[str, bool]] = {}
        self.mutations: list[tuple[Any, ...]] = []

    def state(self, label: str) -> dict[str, bool]:
        return self.states.setdefault(label, {"loaded": False, "disabled": True, "running": False})

    def require_quiet(self, label: str) -> dict[str, bool]:
        state = self.state(label)
        if state["running"]:
            raise RESOURCES.ResourceError("sessions_timer_in_flight")
        return state

    def retire(self, label: str, plist: str) -> None:
        state = self.require_quiet(label)
        if state["loaded"] or not state["disabled"]:
            self.mutations.append(("retire", label))
        state.update(loaded=False, disabled=True)
        RESOURCES.remove_declared_file(plist)

    def enable(self, label: str, plist: str, *, changed: bool, restart: bool = False) -> None:
        state = self.state(label)
        if changed or not state["loaded"] or state["disabled"]:
            self.mutations.append(("enable", label, changed))
        state.update(loaded=True, disabled=False)
        if restart:
            self.mutations.append(("kickstart", label))

    def mutate(self, *args: str) -> None:
        self.mutations.append(args)
        label = args[-1].rsplit("/", 1)[-1]
        if args[0] == "disable":
            self.state(label)["disabled"] = True
        elif args[0] == "bootout":
            self.state(label)["loaded"] = False


@pytest.fixture
def stage(tmp_path: Path) -> tuple[dict[str, Any], Timers]:
    root = tmp_path.resolve()
    account, group = pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name
    cfg = config(
        daybook_sessions_launchd_scope="user",
        daybook_sessions_service_user=account,
        daybook_sessions_service_group=group,
        daybook_sessions_launchd_enabled=False,
    ).model_dump(mode="json")
    cfg.update(
        daybook_sessions_env_file=str(root / "config/sessions.env"),
        daybook_sessions_launcher_path=str(root / "config/ship.sh"),
        daybook_sessions_launchd_plist_path=str(root / "agents/sessions.plist"),
    )
    owned = {"owner": account, "group": group}
    data = {
        "config": cfg,
        "identity": {"required": False},
        "directories": [{**owned, "path": str(root / path), "mode": 0o750} for path in ("config", "agents", "logs")],
        "logs": [{**owned, "path": str(root / "logs/stdout"), "mode": 0o644}],
        "remove_files": [],
        "resources": [
            {**owned, "path": cfg["daybook_sessions_env_file"], "mode": 0o600, "content": "OWNED-SYNTHETIC=1\n"},
            {**owned, "path": cfg["daybook_sessions_launcher_path"], "mode": 0o755, "content": "#!/bin/sh\nexit 0\n"},
        ],
    }
    return data, Timers()


def test_owned_resource_first_and_repeat_preserve_logs_and_have_no_launch_mutations(
    stage: tuple[dict[str, Any], Timers], tmp_path: Path
) -> None:
    data, timers = stage
    with patch.object(STAGE, "controller", return_value=timers):
        assert STAGE.inspect(data, "unused") == {"current": False, "identity_verified": False}
        assert STAGE.apply(data, "unused") == {"schema_version": 1, "identity_verified": False}
        assert STAGE.inspect(data, "unused") == {"current": True, "identity_verified": False}
        before = snapshot(tmp_path.resolve())
        STAGE.apply(data, "unused")
        assert snapshot(tmp_path.resolve()) == before
    assert timers.mutations == []


def test_retired_inflight_refuses_before_any_directories_or_resources(
    stage: tuple[dict[str, Any], Timers], tmp_path: Path
) -> None:
    data, timers = stage
    timers.state(data["config"]["daybook_sessions_launchd_label"]).update(loaded=True, running=True)
    before = snapshot(tmp_path.resolve())
    with (
        patch.object(STAGE, "controller", return_value=timers),
        pytest.raises(RuntimeError, match="sessions_timer_in_flight"),
    ):
        STAGE.apply(data, "unused")
    assert snapshot(tmp_path.resolve()) == before
    assert timers.mutations == []


def test_enabled_original_schedule_retains_conditional_start_and_zero_change_repeat(
    stage: tuple[dict[str, Any], Timers], tmp_path: Path
) -> None:
    data, timers = stage
    cfg = data["config"]
    cfg["daybook_sessions_launchd_enabled"] = True
    declaration = data["resources"][0]
    data["resources"].append(
        {
            **declaration,
            "path": cfg["daybook_sessions_launchd_plist_path"],
            "mode": 0o644,
            "content": "owned synthetic plist",
        }
    )
    with patch.object(STAGE, "controller", return_value=timers):
        STAGE.apply(data, "unused")
        assert timers.mutations == [
            ("enable", cfg["daybook_sessions_launchd_label"], True),
            ("kickstart", cfg["daybook_sessions_launchd_label"]),
        ]
        timers.mutations.clear()
        before = snapshot(tmp_path.resolve())
        STAGE.apply(data, "unused")
        assert timers.mutations == []
        assert snapshot(tmp_path.resolve()) == before


def test_identity_failure_preserves_environment_and_auth_with_only_rail_preparation_reportable(
    stage: tuple[dict[str, Any], Timers], tmp_path: Path
) -> None:
    data, timers = stage
    cfg = data["config"]
    data["identity"]["required"] = True
    cfg["daybook_weeknotes_identity_helper_path"] = str(tmp_path.resolve() / "config/helper.py")
    data["resources"].append(
        {
            **data["resources"][0],
            "path": cfg["daybook_weeknotes_identity_helper_path"],
            "content": "# owned rail code",
            "mode": 0o755,
        }
    )
    with (
        patch.object(STAGE, "controller", return_value=timers),
        patch.object(STAGE, "identity_gate", side_effect=RuntimeError("sessions_identity_verification_failed")),
        patch.object(STAGE, "seed_auth", side_effect=AssertionError("auth must follow identity gate")),
        pytest.raises(RuntimeError, match="sessions_identity_verification_failed"),
    ):
        STAGE.apply(data, "unused")
    assert Path(cfg["daybook_weeknotes_identity_helper_path"]).is_file()
    assert not Path(cfg["daybook_sessions_env_file"]).exists()
    assert not Path(data["logs"][0]["path"]).exists()
    assert timers.mutations == []


def test_unsafe_log_and_removal_objects_refuse_before_other_resources(
    stage: tuple[dict[str, Any], Timers], tmp_path: Path
) -> None:
    data, timers = stage
    bad = tmp_path.resolve() / "undeclared-directory"
    bad.mkdir()
    data["remove_files"].append(str(bad))
    before = snapshot(tmp_path.resolve())
    with (
        patch.object(STAGE, "controller", return_value=timers),
        pytest.raises(RuntimeError, match="sessions_resource_remove_type_invalid"),
    ):
        STAGE.apply(data, "unused")
    assert snapshot(tmp_path.resolve()) == before
    assert timers.mutations == []


def test_rotation_is_pending_for_planning_but_postapply_verification_accepts_safe_auth(
    controls: dict[str, Any],
) -> None:
    data = {
        **controls,
        "identity": {"required": False},
        "resources": [],
        "directories": [],
        "logs": [],
        "remove_files": [],
    }
    data["config"]["daybook_sessions_launchd_manage_state"] = False
    data["config"]["daybook_weeknotes_reconcile_pi_auth_rotate"] = True
    with patch.object(STAGE, "identity_source_ready", return_value=True), patch.object(STAGE, "policy_gate"):
        assert STAGE.inspect(data, "unused")["current"] is False
        assert STAGE.inspect(data, "unused", planning=False)["current"] is True


def test_disabled_classifier_bootout_uses_label_after_plist_removal(
    stage: tuple[dict[str, Any], Timers], tmp_path: Path
) -> None:
    data, timers = stage
    cfg = data["config"]
    path = tmp_path.resolve() / "owned-classifier.plist"
    path.write_text("owned old classifier plist")
    cfg["daybook_archive_quote_classifier_launchd_plist_path"] = str(path)
    label = cfg["daybook_archive_quote_classifier_launchd_label"]
    timers.state(label).update(loaded=True)
    data["remove_files"].append(str(path))
    with patch.object(STAGE, "controller", return_value=timers):
        STAGE.apply(data, "unused")
        assert STAGE.inspect(data, "unused")["current"] is True
    assert not path.exists()
    assert ("bootout", timers.domain + "/" + label) in timers.mutations
    assert all(str(path) not in args for args in timers.mutations)


def test_pending_source_defers_old_application_code_until_managed_apply(controls: dict[str, Any]) -> None:
    data = {
        **controls,
        "identity": {"required": True},
        "resources": [],
        "directories": [],
        "logs": [],
        "remove_files": [],
        "source_changed": True,
    }
    data["config"]["daybook_sessions_launchd_manage_state"] = False
    with (
        patch.object(STAGE, "identity_source_ready", side_effect=AssertionError("old code not inspected")),
        patch.object(STAGE, "policy_gate", side_effect=AssertionError("no app call while source pending")),
        patch.object(STAGE, "identity_gate", side_effect=AssertionError("no app call while source pending")),
    ):
        assert STAGE.inspect(data, "unused")["current"] is False
