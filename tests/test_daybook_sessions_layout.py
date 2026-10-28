"""Filesystem declarations compared with the actual original role, no host I/O."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.daybook_sessions import DaybookSessionsConfig
from ops_deploy.services.daybook_sessions.layout import layout
from tests.test_daybook_sessions_resources import config, studio


def test_disabled_sessions_has_no_filesystem_declarations() -> None:
    result = layout(DaybookSessionsConfig(daybook_sessions_enabled=False))
    assert (result.directories, result.logs, result.retired_timers, result.remove_files) == ((), (), (), ())


@pytest.mark.parametrize("bad", ["relative", "/", "/owned/../other", "/owned/bad\nname"])
def test_legacy_removals_cannot_escape_absolute_declared_file_contract(bad: str) -> None:
    with pytest.raises(ValueError, match="absolute without traversal"):
        layout(config(daybook_sessions_remove_legacy_runner_paths=[bad]))


@pytest.mark.parametrize("profile", ["default", "user", "studio", "unmanaged"])
def test_original_role_filesystem_declarations_match_exact_paths_modes_owners(profile: str) -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Paired original role oracle is run explicitly for qualification")
    import yaml
    from jinja2 import StrictUndefined
    from jinja2.nativetypes import NativeEnvironment

    cfg = (
        studio(daybook_sessions_launchd_manage_state=profile != "unmanaged")
        if profile in {"studio", "unmanaged"}
        else config(daybook_sessions_launchd_scope="user" if profile == "user" else "system")
    )
    role = Path(source) / "roles/daybook_sessions_deploy/tasks"
    main = yaml.safe_load((role / "main.yml").read_text())
    weeknotes = yaml.safe_load((role / "weeknotes_reconcile.yml").read_text())
    env = NativeEnvironment(undefined=StrictUndefined)
    env.filters.update(importlib.import_module("ansible.plugins.filter.core").FilterModule().filters())
    values = cfg.model_dump(mode="json")

    def render(value: Any, **extra: Any) -> Any:
        if isinstance(value, str):
            return env.from_string(value).render({**values, **extra})
        if isinstance(value, list):
            return [render(v, **extra) for v in value]
        if isinstance(value, dict):
            return {k: render(v, **extra) for k, v in value.items()}
        return value

    def task(name: str, tasks: list[dict[str, Any]] = main) -> dict[str, Any]:
        return next(t for t in tasks if t.get("name") == name)

    expected: dict[str, tuple[str, str, int]] = {}

    def add_file_task(selected: dict[str, Any]) -> None:
        loop = render(selected.get("loop", [None]))
        for item in loop:
            spec = render(selected["ansible.builtin.file"], item=item)
            expected[spec["path"]] = (spec["owner"], spec["group"], int(str(spec["mode"]), 8))

    # The main role's source/state/config parents, plus each conditional block.
    add_file_task(task("runtime | Ensure Daybook sessions directories exist"))
    if cfg.daybook_archive_quote_classifier_enabled:
        for name in (
            "runtime | Ensure archive quote classifier launchd directory exists",
            "runtime | Ensure Daybook state parent for the browser profile exists",
            "runtime | Ensure dedicated Archive browser profile directory exists",
        ):
            add_file_task(task(name))
    if cfg.daybook_weeknotes_reconcile_enabled:
        add_file_task(task("weeknotes_reconcile | Ensure private runtime directories exist", weeknotes))
    result = layout(cfg)
    assert {p.path: (p.owner, p.group, p.mode) for p in result.directories} == expected
    expected.clear()
    logs = task("runtime | Ensure launchd log files exist")
    assert logs["ansible.builtin.file"]["modification_time"] == "preserve"
    assert logs["ansible.builtin.file"]["access_time"] == "preserve"
    add_file_task(logs)
    if cfg.daybook_weeknotes_reconcile_enabled:
        add_file_task(task("weeknotes_reconcile | Ensure separate launchd log files exist", weeknotes))
    assert {p.path: (p.owner, p.group, p.mode) for p in result.logs} == expected
    retired = render(task("launchd | Retire timers whose work now runs under the operations supervisor")["loop"])
    selected = {(t["label"], t["plist"]) for t in retired if t["retire"] and cfg.daybook_sessions_launchd_manage_state}
    if (
        cfg.daybook_weeknotes_reconcile_enabled
        and cfg.daybook_weeknotes_reconcile_launchd_retired
        and cfg.daybook_sessions_launchd_manage_state
    ):
        selected.add(
            (cfg.daybook_weeknotes_reconcile_launchd_label, cfg.daybook_weeknotes_reconcile_launchd_plist_path)
        )
    assert {(t.label, t.plist) for t in result.retired_timers} == selected
