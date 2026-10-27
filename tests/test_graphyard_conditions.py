"""graphyard conditions: config validation, read-before-seed planning, and the probe's agreement with the seed."""

from __future__ import annotations

import io
import json
import sqlite3
import sys
import types
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.graphyard import GraphyardConditionsConfig, deploy_graphyard_conditions
from ops_deploy.services.graphyard import conditions as module
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

PREFIX = "Seed graphyard conditions | "
ENTRIES: list[dict[str, Any]] = [
    {"host": "macmini", "mountpoint": "/", "warning_threshold": 0.80, "critical_threshold": 0.90},
    {"host": "studio", "mountpoint": "/System/Volumes/Data", "warning_threshold": 0.85, "critical_threshold": 0.92},
    {
        "host": "atlas",
        "mountpoint": "/System/Volumes/Data",
        "warning_threshold": 0.85,
        "critical_threshold": 0.92,
        "enabled": False,
    },
]
PROBE_KEY = "pending = False"


def config(**changes: Any) -> GraphyardConditionsConfig:
    return GraphyardConditionsConfig.model_validate({"conditions": ENTRIES, **changes})


def run(cfg: GraphyardConditionsConfig, probe: list[str] | None) -> FakeRun:
    responses: dict[str, Any] = dict(fakehost.LINUX)
    if probe is not None:
        responses[PROBE_KEY] = probe
    return run_deploy_fake(deploy_graphyard_conditions, cfg, responses=responses)


def changed(result: FakeRun) -> list[str]:
    return [name.removeprefix(PREFIX) for name in result.mutating_changed_ops]


def test_converged_conditions_seed_nothing() -> None:
    result = run(config(), ["condition 0 current", "condition 1 current", "current"])

    assert result.succeeded
    assert changed(result) == []
    # No Django management command ran; the summary read is read-only.
    assert not any("call_command" in command for command in result.executed_commands)
    assert result.op(PREFIX + "Read Graphyard conditions summary").read_only


def test_only_missing_or_changed_conditions_are_seeded_with_the_spec_on_stdin() -> None:
    result = run(config(), ["condition 0 current", "condition 1 warning_threshold", "pending"])

    assert changed(result) == ["Seed Graphyard disk-usage condition studio /System/Volumes/Data"]
    seeds = [(command, stdin) for command, stdin in result.stdin if "call_command" in command]
    assert len(seeds) == 1
    assert json.loads(seeds[0][1])["host"] == "studio"
    # The spec stays off the command line and out of the environment.
    assert "0.85" not in seeds[0][0]


def test_disabled_entries_are_neither_probed_nor_seeded_nor_required() -> None:
    result = run(config(), ["condition 0 missing", "condition 1 missing", "pending"])

    assert [n for n in changed(result) if "atlas" in n] == []
    probed = next(stdin for command, stdin in result.stdin if PROBE_KEY in command)
    assert [spec["host"] for spec in json.loads(probed)] == ["macmini", "studio"]
    summary = next(c for c in result.executed_commands if "X-Forwarded-Proto" in c)
    assert "atlas" not in summary
    assert "Host filesystem usage (studio /System/Volumes/Data)" in summary


def test_a_failed_probe_seeds_every_enabled_condition_and_probes_again() -> None:
    result = run(config(), ["ops-deploy-probe-failed"])

    assert changed(result) == [
        "Seed Graphyard disk-usage condition macmini /",
        "Seed Graphyard disk-usage condition studio /System/Volumes/Data",
    ]
    assert PREFIX + "Probe again: graphyard conditions" in [op.name for op in result.ops]


def test_manage_runs_the_playbook_wrapper_as_the_graphyard_user() -> None:
    command = module.manage(config(), "shell", "-c", "pass")

    assert command.startswith("cd /opt/apps/graphyard/site/src/django && runuser -u graphyard -- env HOME=")
    assert "GRAPHYARD_CONDITIONS_ENV_FILE=/etc/graphyard/graphyard.env" in command
    assert "DJANGO_SETTINGS_MODULE is not set in" in command
    assert "graphyard-manage /opt/apps/graphyard/site/.venv/bin/python" in command
    assert "/opt/apps/graphyard/site/src/django/manage.py shell -c pass" in command


@pytest.mark.parametrize(
    ("entries", "why"),
    [
        ([], "the playbook requires a non-empty list"),
        ([{**ENTRIES[0], "host": ""}], "host must be set"),
        ([{**ENTRIES[0], "mountpoint": "data"}], "absolute mountpoint"),
        ([{**ENTRIES[0], "warning_threshold": 0.95}], "warning above critical"),
        ([{**ENTRIES[0], "critical_threshold": 1.5}], "critical above 1"),
        ([{**ENTRIES[0], "warning_threshold": 0}], "warning must be above 0"),
        ([{**ENTRIES[0], "warning_threshold": "0.8"}], "a ratio is a number, not text"),
        ([{**ENTRIES[0], "warning": 0.8}], "unknown key"),
    ],
)
def test_invalid_entries_are_refused_before_connecting(entries: list[dict[str, Any]], why: str) -> None:
    with pytest.raises(ValidationError):
        GraphyardConditionsConfig.model_validate({"conditions": entries})


def test_listed_name_keeps_an_explicit_name() -> None:
    cfg = config(conditions=[{**ENTRIES[0], "name": "Root disk"}])

    assert cfg.enabled[0].listed_name == "Root disk"
    assert config().enabled[0].listed_name == "Host filesystem usage (macmini /)"


@pytest.mark.parametrize(
    ("row", "expected_seed_change"),
    [
        (None, True),
        ({}, False),
        ({"warning_threshold": 0.7}, True),
        ({"tags_filter": {"mountpoint": "/data"}}, True),
        ({"enabled": False}, True),
        ({"alert_when_stale": False}, False),
        ({"warning_threshold": 0.7, "alert_when_stale": False, "stale_after_seconds": 1800}, True),
        ({"warning_threshold": 0.7, "alert_when_stale": True, "stale_after_seconds": 1800}, True),
    ],
)
def test_the_probe_agrees_with_the_seed_script(
    row: dict[str, Any] | None, expected_seed_change: bool, tmp_path: Path
) -> None:
    """Both scripts against the same stub ``ConditionDefinition``: the probe says pending iff the seed changes."""

    spec = ENTRIES[1]
    stored = None
    if row is not None:
        stored = types.SimpleNamespace(
            id=7,
            name="Host filesystem usage (studio /System/Volumes/Data)",
            enabled=True,
            metric_name="host.filesystem_used_ratio",
            host_filter="studio",
            subject_type_filter="host",
            subject_id_filter="studio",
            service_filter="",
            tags_filter={"mountpoint": "/System/Volumes/Data"},
            operator="gte",
            warning_threshold=0.85,
            critical_threshold=0.92,
            window_minutes=30,
            breach_minutes=5,
            alert_when_stale=True,
            stale_after_seconds=None,
        )
        for key, value in row.items():
            setattr(stored, key, value)
    calls: list[tuple[Any, ...]] = []

    class Objects:
        def filter(self, name: str) -> Any:
            return types.SimpleNamespace(first=lambda: stored if stored and stored.name == name else None)

        def get(self, name: str) -> Any:
            return stored or types.SimpleNamespace(id=8, name=name)

    models = types.ModuleType("graphyard.models")
    models.ConditionDefinition = types.SimpleNamespace(objects=Objects())  # type: ignore[attr-defined]
    management = types.ModuleType("django.core.management")
    management.call_command = lambda *args, **kwargs: calls.append(args)  # type: ignore[attr-defined]
    stubs = {
        "graphyard": types.ModuleType("graphyard"),
        "graphyard.models": models,
        "django": types.ModuleType("django"),
        "django.core": types.ModuleType("django.core"),
        "django.core.management": management,
    }

    db_path = tmp_path / "conditions.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE condition_definition (name TEXT, enabled INTEGER, metric_name TEXT, "
            "host_filter TEXT, subject_type_filter TEXT, subject_id_filter TEXT, service_filter TEXT, "
            "tags_filter TEXT, operator TEXT, warning_threshold REAL, critical_threshold REAL, "
            "window_minutes INTEGER, breach_minutes INTEGER)"
        )
        if stored is not None:
            columns = [x[1] for x in db.execute("PRAGMA table_info(condition_definition)")]
            values = [json.dumps(stored.tags_filter) if n == "tags_filter" else getattr(stored, n) for n in columns]
            db.execute("INSERT INTO condition_definition VALUES (" + ",".join("?" for _ in columns) + ")", values)

    def execute(script: str, stdin: str) -> str:
        out = io.StringIO()
        old = dict(sys.modules), sys.stdin, sys.argv
        sys.modules.update(stubs)
        sys.stdin = io.StringIO(stdin)
        sys.argv = ["probe", str(db_path)]
        try:
            with redirect_stdout(out):
                exec(compile(script, "<script>", "exec"), {"__name__": "__main__"})
        finally:
            sys.modules.clear()
            sys.modules.update(old[0])
            sys.stdin = old[1]
            sys.argv = old[2]
        return out.getvalue()

    probe_out = execute(module.CONDITIONS_PROBE, json.dumps([spec]))
    seed_out = execute(module.SEED_SCRIPT, json.dumps(spec))

    assert probe_out.splitlines()[-1] == ("pending" if expected_seed_change else "current")
    assert ("changed=true" in seed_out) is expected_seed_change
    assert bool(calls) is expected_seed_change

    if row is not None and expected_seed_change:
        assert stored is not None
        assert ("--intermittent" in calls[0]) is (not stored.alert_when_stale)
        assert ("--stale-after-seconds" in calls[0]) is (stored.stale_after_seconds is not None)
        if stored.stale_after_seconds is not None:
            assert calls[0][calls[0].index("--stale-after-seconds") + 1] == str(stored.stale_after_seconds)
