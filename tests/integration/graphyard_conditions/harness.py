"""Real pinned Graphyard/Django/SQLite/API fixture on an owned Ubuntu VM."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import signal
import sqlite3
import subprocess
import sys
import time
import traceback
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest.mock import patch

from pyinfra.api import Config, Inventory, State
from pyinfra.api.command import QuoteString, StringCommand
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.connectors.local import LocalConnector

from ops_deploy.services.graphyard import GraphyardConditionsConfig, deploy_graphyard_conditions
from ops_deploy.services.graphyard.conditions import CONDITIONS_PROBE, manage, with_environment
from ops_deploy.testing.harness import collect_ops

HERE = Path(__file__).parent
EVIDENCE = Path(sys.argv[1])
ROOT = Path("/opt/graphyard-conditions-fixture")
SOURCE = ROOT / "source"
DJANGO = SOURCE / "src/django"
DB = DJANGO / "db.sqlite3"
ENV = ROOT / "service.env"
PYTHON = SOURCE / ".venv/bin/python"
USER = "graphyard-fixture"
UNIT = "graphyard-conditions-fixture.service"
URL = "http://127.0.0.1:18051/v1/conditions"
PHASES: list[dict[str, Any]] = []
KEEPER: subprocess.Popen[str] | None = None
ENTRIES = [
    {"host": "fixture-one", "mountpoint": "/", "warning_threshold": 0.8, "critical_threshold": 0.9},
    {"host": "fixture-two", "mountpoint": "/data", "warning_threshold": 0.85, "critical_threshold": 0.95},
    {
        "host": "fixture-disabled",
        "mountpoint": "/",
        "warning_threshold": 0.8,
        "critical_threshold": 0.9,
        "enabled": False,
    },
]


def shell(*args: str, stdin: str | None = None) -> str:
    return subprocess.check_output(args, input=stdin, text=True, stderr=subprocess.STDOUT).strip()


def cfg(entries: list[dict[str, Any]] | None = None, **overrides: Any) -> GraphyardConditionsConfig:
    return GraphyardConditionsConfig.model_validate(
        {
            "conditions": ENTRIES if entries is None else entries,
            "python": str(PYTHON),
            "manage_py": str(DJANGO / "manage.py"),
            "workdir": str(DJANGO),
            "system_user": USER,
            "home": str(ROOT),
            "env_file": str(ENV),
            "conditions_url": URL,
            **overrides,
        }
    )


def management(code: str) -> str:
    return shell("bash", "-c", manage(cfg(), "shell", "-c", code))


def rows() -> list[dict[str, Any]]:
    with closing(sqlite3.connect(f"file:{DB}?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute("SELECT * FROM condition_definition ORDER BY name")]


def snapshot() -> dict[str, Any]:
    result: dict[str, Any] = {"rows": rows(), "pid": shell("systemctl", "show", UNIT, "-p", "MainPID", "--value")}
    for path in (DB, Path(str(DB) + "-wal"), Path(str(DB) + "-shm"), ENV):
        if not path.exists():
            result[str(path)] = None
            continue
        st = path.stat()
        result[str(path)] = [
            st.st_mode,
            st.st_uid,
            st.st_gid,
            st.st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        ]
    return result


def deploy(
    label: str, config: GraphyardConditionsConfig, *, zero: bool = False, failure: bool = False, fish: bool = False
) -> None:
    assert KEEPER is not None
    assert KEEPER.poll() is None, "fixture connection keeper exited"
    before = snapshot()
    original = LocalConnector.run_shell_command
    commands: list[str] = []
    uploads: list[bool] = []

    def traced(connector: Any, command: Any, **kwargs: Any) -> Any:
        raw = command if isinstance(command, str) else str(command.get_raw_value())
        commands.append(raw)
        trace = EVIDENCE / f"{label}-{len(commands)}.strace"
        target = ["fish", "-c", shlex.join(["sh", "-c", raw])] if fish else ["sh", "-c", raw]
        wrapped = StringCommand(
            "strace",
            "-f",
            "-s",
            "4096",
            "-e",
            "trace=file,process,fchmod,fchown,ftruncate",
            "-o",
            str(trace),
            *[QuoteString(arg) for arg in target],
        )
        return original(connector, wrapped, **kwargs)

    def no_upload(*args: Any, **kwargs: Any) -> None:
        uploads.append(True)
        raise AssertionError("conditions deploy must never upload files")

    state = State(Inventory(([("@local", {})], {})), Config())
    error = None
    with patch.object(LocalConnector, "run_shell_command", traced), patch.object(LocalConnector, "put_file", no_upload):
        try:
            connect_all(state)
            add_deploy(state, deploy_graphyard_conditions, cfg=config)
            run_ops(state)
        except Exception:
            error = traceback.format_exc()
        finally:
            operations = collect_ops(state, "@local")
            disconnect_all(state)
    after = snapshot()
    assert KEEPER.poll() is None, "fixture connection keeper exited"
    mutations = [op.name for op in operations if op.changed and not op.read_only]
    result = {
        "label": label,
        "error": error,
        "operations": [asdict(op) for op in operations],
        "mutations": mutations,
        "uploads": len(uploads),
        "unchanged": before == after,
        "fish_transport": fish,
        "before": before,
        "after": after,
        "commands": len(commands),
    }
    (EVIDENCE / f"{label}.json").write_text(json.dumps(result, indent=2))
    PHASES.append({k: result[k] for k in ("label", "mutations", "unchanged", "uploads", "fish_transport")})
    assert bool(error) is failure, result
    if not failure:
        assert operations, result
        assert all(op.succeeded for op in operations), result
    if zero or failure:
        assert before == after, result
    if zero:
        assert not mutations, result
        assert not uploads, result
        # A repeat uses stdlib SQLite and HTTP only, never Django or a seed command.
        assert all("call_command" not in command and "manage.py shell" not in command for command in commands)
    print(label, "expected failure" if failure else "passed", len(mutations), "managed", flush=True)


def ansible_repeat(config: GraphyardConditionsConfig) -> None:
    """Original private seed bytes through a real Ansible command task, owned inputs only."""
    import yaml

    before = snapshot()
    command = manage(config, "shell", "-c", (HERE / "ansible_seed.py.txt").read_text())
    play = [
        {
            "hosts": "localhost",
            "gather_facts": False,
            "tasks": [
                {
                    "name": "Original Ansible seed",
                    "ansible.builtin.command": {"argv": ["bash", "-c", command], "stdin": "{{ item | to_json }}"},
                    "loop": [json.loads(entry.spec()) for entry in config.enabled],
                    "register": "seed",
                    "changed_when": "'changed=true' in seed.stdout",
                }
            ],
        }
    ]
    path = EVIDENCE / "ansible-repeat.yml"
    path.write_text(yaml.safe_dump(play))
    output = shell(str(Path(sys.executable).parent / "ansible-playbook"), "-i", "localhost,", "-c", "local", str(path))
    (EVIDENCE / "ansible-repeat.log").write_text(output)
    assert "changed=0" in output, output
    assert "failed=0" in output, output
    assert snapshot() == before
    PHASES.append({"label": "ansible-after-pyinfra", "mutations": [], "unchanged": True})


def main() -> None:
    global KEEPER
    ENV.write_text("DJANGO_SETTINGS_MODULE=config.settings.test\nPYTHONDONTWRITEBYTECODE=1\n")
    ENV.chmod(0o644)
    shell("bash", "-c", manage(cfg(), "migrate", "--noinput"))
    unit = Path("/etc/systemd/system") / UNIT
    unit.write_text(
        f"[Unit]\nDescription=Owned Graphyard conditions fixture\n[Service]\nUser={USER}\n"
        f"WorkingDirectory={DJANGO}\nEnvironmentFile={ENV}\n"
        f"ExecStart={PYTHON} {DJANGO}/manage.py runserver 127.0.0.1:18051 --noreload --nothreading\n"
    )
    shell("systemctl", "daemon-reload")
    shell("systemctl", "start", UNIT)
    for _ in range(50):
        try:
            shell("curl", "--fail", "--silent", URL)
            break
        except subprocess.CalledProcessError:
            time.sleep(0.2)
    else:
        raise AssertionError("fixture API did not start")
    # Retain isolated observations to distinguish SQLite bookkeeping caused by
    # the direct read-only probe from the real HTTP request. The snapshot reader
    # explicitly closes its own connection too (a sqlite context manager does not).
    direct = with_environment(cfg(), ["python3", "-I", "-c", CONDITIONS_PROBE, str(DB)])
    probes = [
        ("direct-probe", ["bash", "-c", direct], json.dumps([json.loads(c.spec()) for c in cfg().enabled])),
        ("http-read", ["curl", "--fail", "--silent", "-H", "X-Forwarded-Proto: https", URL], None),
    ]
    for label, command, stdin in probes:
        before = snapshot()
        shell(*command, stdin=stdin)
        after = snapshot()
        observation = {
            "before": before,
            "after": after,
            "changed_sections": [k for k in before if before[k] != after[k]],
        }
        (EVIDENCE / f"isolated-{label}.json").write_text(json.dumps(observation, indent=2))
        for key in ("rows", "pid", str(DB), str(ENV)):
            assert before[key] == after[key], (label, key)
    # Hold one real service-user connection for strict repeated comparisons of
    # every sidecar. This bounds the fixture's zero-change claim to a stable WAL
    # lifecycle; no production host connection keeper is part of the deployment.
    keeper_code = (
        "from django.db import connection; import time; "
        "connection.cursor().execute('SELECT COUNT(*) FROM condition_definition').fetchall(); "
        "print('fixture-reader-ready', flush=True); time.sleep(1800)"
    )
    KEEPER = subprocess.Popen(
        ["bash", "-c", manage(cfg(), "shell", "-c", keeper_code)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    assert KEEPER.stdout is not None
    while True:
        line = KEEPER.stdout.readline()
        assert line, "fixture connection keeper exited before ready"
        if line.strip() == "fixture-reader-ready":
            break
    management(
        "from graphyard.models import ConditionDefinition; ConditionDefinition.objects.create("
        "name='Unrelated synthetic condition', metric_name='fixture', warning_threshold=1, status='warning', "
        "message='synthetic evaluation state', stale_after_seconds=987, alert_when_stale=False)"
    )
    unrelated = rows()[-1]
    deploy("fresh", cfg())
    deploy("repeat", cfg(), zero=True)
    deploy("fish-repeat", cfg(), zero=True, fish=True)
    assert len(rows()) == 3
    for row in rows():
        if row["host_filter"].startswith("fixture-"):
            assert row["stale_after_seconds"] is None
            assert row["alert_when_stale"] == 1
    assert [row for row in rows() if row["name"] == unrelated["name"]] == [unrelated]
    for allowance, flag in ((1800, False), (1800, True), (None, False)):
        case = f"{allowance}-{flag}"
        management(
            "from graphyard.models import ConditionDefinition; "
            "ConditionDefinition.objects.filter(host_filter='fixture-one').update("
            f"stale_after_seconds={allowance!r}, alert_when_stale={flag!r}, status='warning', "
            "message='owned fixture evaluation', last_value=0.25)"
        )
        config = cfg()
        deploy(f"nondefault-{case}-repeat", config, zero=True)
        original = next(row for row in rows() if row["host_filter"] == "fixture-one")
        updated = [{**ENTRIES[0], "warning_threshold": 0.81 if not flag else 0.82}, *ENTRIES[1:]]
        deploy(f"nondefault-{case}-threshold", cfg(updated))
        actual = next(row for row in rows() if row["host_filter"] == "fixture-one")
        assert actual["warning_threshold"] == updated[0]["warning_threshold"]
        for key in original:
            if key not in ("warning_threshold", "updated_at"):
                assert actual[key] == original[key], key
        deploy(f"nondefault-{case}-updated-repeat", cfg(updated), zero=True)
        # Restore desired threshold between matrix legs using the same production deploy.
        deploy(f"nondefault-{case}-restore", cfg())
    deploy("api-missing-name", cfg([{**ENTRIES[0], "name": ""}]), failure=True)
    old = ENV.read_text()
    ENV.write_text("PYTHONDONTWRITEBYTECODE=1\n")
    deploy("missing-settings", cfg(), failure=True)
    ENV.write_text(old)
    deploy("settings-recovery", cfg(), zero=True)
    # Ansible compares only its owned fields and therefore does not reset staleness on a repeat.
    ansible_repeat(cfg())
    deploy("pyinfra-after-ansible", cfg(), zero=True)
    assert KEEPER.poll() is None, "fixture connection keeper exited"
    (EVIDENCE / "summary.json").write_text(
        json.dumps(
            {
                "implementation": os.environ["IMPLEMENTATION_SHA"],
                "harness": os.environ["HARNESS_SHA"],
                "graphyard": shell("git", "-C", str(SOURCE), "rev-parse", "HEAD"),
                "seed_sha256": hashlib.sha256(
                    (SOURCE / "src/graphyard/management/commands/seed_disk_usage_condition.py").read_bytes()
                ).hexdigest(),
                "phases": PHASES,
                "limits": (
                    "Real Graphyard/Django/SQLite/API on owned Ubuntu VM; local pyinfra connector plus fish "
                    "command transport, not inventory SSH. Synthetic rows only. Traces retained; zero managed "
                    "repeats asserted via row/file/PID snapshots, not a blanket syscall-zero claim. "
                    "A real service-user connection stays open to stabilize WAL/SHM lifetime; no sidecars are excluded."
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    finally:
        if KEEPER is not None and KEEPER.poll() is None:
            os.killpg(KEEPER.pid, signal.SIGTERM)
            try:
                KEEPER.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(KEEPER.pid, signal.SIGKILL)
                KEEPER.wait()
