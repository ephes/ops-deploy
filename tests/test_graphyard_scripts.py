"""The graphyard probes and host scripts, run for real through the login shells the hosts use."""

import hashlib
import json
import os
import shlex
import sqlite3
import sys
from pathlib import Path

import pytest

from ops_deploy.services.graphyard import auth as auth_module
from ops_deploy.services.graphyard import core as core_module
from tests.test_remote_shell_execution import LOGIN_SHELLS, run_remote


def python_command(script: str, *args: str) -> str:
    # The deploys run ``python3 -I -c``; the test interpreter stands in for the host's.
    return shlex.join([sys.executable, "-I", "-c", script, *args])


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_specs_probe_reads_what_specs_current_expects(tmp_path: Path, login_shell: str) -> None:
    db = tmp_path / "db.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "create table metric_collection_spec"
            "(name text, enabled bool, spec_type text, interval_seconds int, config text)"
        )
        conn.execute(
            "insert into metric_collection_spec values (?, ?, ?, ?, ?)",
            ("a", 1, "http_json_metric", 60, json.dumps({"url": "x", "scale": 0.001, "tags": {"b": 1, "a": 2}})),
        )
    rendered = json.dumps(
        {
            "metric_collection_specs": [
                {
                    "name": "a",
                    "spec_type": "http_json_metric",
                    "config": {"tags": {"a": 2, "b": 1}, "scale": 0.001, "url": "x"},
                }
            ]
        }
    )

    result = run_remote(python_command(core_module.SPECS_PROBE, str(db)), login_shell, os.environ["PATH"])

    assert result.returncode == 0, result.stderr
    assert core_module.specs_current(result.stdout, rendered, prune=True)


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_grafana_probe_and_match_agree_with_the_controller(tmp_path: Path, login_shell: str) -> None:
    db = tmp_path / "grafana.db"
    stored = hashlib.pbkdf2_hmac("sha256", b"s3cret", b"saltysalt1", 10000, dklen=50).hex()
    with sqlite3.connect(db) as conn:
        conn.executescript(
            "create table user(login text, password text, salt text);"
            "create table data_source(uid text, url text);"
            "create table login_attempt(username text);"
        )
        conn.execute("insert into user values ('admin', ?, 'saltysalt1')", (stored,))
        conn.execute("insert into data_source values ('graphyard-influxdb', 'http://graphyard-influxdb:8086')")
        conn.execute("insert into login_attempt values ('admin')")
    path = os.environ["PATH"]

    probe = run_remote(
        python_command(auth_module.GRAFANA_PROBE, str(db), "admin", "graphyard-influxdb"), login_shell, path
    )
    state = auth_module.grafana_state(probe.stdout)
    match = run_remote(
        f"printf '%s\\n' s3cret | {python_command(auth_module.GRAFANA_MATCH, str(db), 'admin')}", login_shell, path
    )

    assert probe.returncode == 0, probe.stderr
    assert auth_module.grafana_password_matches(state["admin"], "s3cret")
    assert not auth_module.grafana_password_matches(state["admin"], "other")
    assert state["datasource"] == ["http://graphyard-influxdb:8086"]
    assert state["lockouts"] == ["1"]
    assert match.stdout.strip() == "MATCH"


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_provisioning_url_check_reports_and_apply_rewrites(tmp_path: Path, login_shell: str) -> None:
    provisioning = tmp_path / "graphyard.yaml"
    provisioning.write_text("datasources:\n  - name: x\n    access: proxy\n    url: http://172.18.0.3:8086\n")
    target = "http://graphyard-influxdb:8086"
    path = os.environ["PATH"]

    def run(mode: str) -> str:
        result = run_remote(
            python_command(auth_module.PROVISIONING_URL, mode, str(provisioning), target), login_shell, path
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    assert run("check") == "CHANGED"
    assert "172.18.0.3" in provisioning.read_text()
    assert run("apply") == "CHANGED"
    assert provisioning.read_text().endswith(f"    url: {target}\n")
    assert run("check") == "UNCHANGED"
