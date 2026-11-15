"""The Traefik transaction engine as a program.

``test_traefik_tx_scenarios`` and ``test_traefik_tx_config`` cover its actions; this
module covers that it runs as a standalone standard-library program on the hosts'
Python, its size, its actions, and the state and lock paths the hosts already have.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from ops_deploy.infra import traefik_deploy
from ops_deploy.infra.traefik_tx import engine
from tests.traefik_tx_fixtures import FakeHost, base_setup

ENGINE_PATH = Path(engine.__file__)
POLICY = {
    "host": "canary",
    "binary_path": "/usr/local/bin/traefik",
    "config_path": "/etc/traefik/traefik.toml",
    "dynamic_path": "/etc/traefik/dynamic",
}
WRITING = ("enroll", "binary", "alias", "metrics_bind", "acme_storage", "resume")


@pytest.mark.parametrize("action", WRITING)
def test_writing_actions_need_root_as_a_standalone_script(action: str, tmp_path: Path) -> None:
    """``python3 -I engine.py``: no package, no site directory, no script directory on the path."""

    request = tmp_path / "request.json"
    request.write_text(json.dumps({"action": action, "policy": POLICY}))

    result = subprocess.run(
        [sys.executable, "-I", str(ENGINE_PATH), "--request", str(request)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=tmp_path,
    )

    assert (result.returncode, result.stderr) == (2, "")
    assert json.loads(result.stdout) == {"failed": True, "error": "root is required"}


@pytest.mark.parametrize("action", WRITING)
def test_writing_actions_refuse_a_non_root_caller_before_anything_is_touched(action: str, tmp_path: Path) -> None:
    host = FakeHost(engine, tmp_path)
    host.install()
    host.euid = 1000
    with host.patched():
        request = base_setup(host, action).request
        with (
            patch.object(engine, "identity", side_effect=AssertionError("identity read")),
            pytest.raises(engine.Refused, match=r"^root is required$"),
        ):
            engine.execute(request)

    assert not host.state_root.exists()
    assert not (tmp_path / "lock").exists()
    assert host.calls == []


def test_main_takes_its_arguments(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"action": "rollback", "policy": POLICY}))
    previous = os.umask(0o022)
    try:
        code = engine.main(["--request", str(request)])
    finally:
        os.umask(previous)

    assert code == 2
    assert json.loads(capsys.readouterr().out) == {"failed": True, "error": "unknown action"}


def test_the_actions() -> None:
    assert engine.PORTED == engine.ACTIONS
    assert set(engine.ACTIONS) == {*WRITING, "inspect"}


def test_state_and_lock_are_where_the_hosts_have_them() -> None:
    assert Path(traefik_deploy.TRANSACTION_STATE) == engine.STATE_ROOT
    assert Path("/run/lock/traefik-transaction.lock") == engine.LOCK


def test_engine_uses_the_standard_library_only() -> None:
    tree = ast.parse(ENGINE_PATH.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            assert node.module is not None
            imported.add(node.module.partition(".")[0])

    assert imported - {"__future__"} <= sys.stdlib_module_names


def test_engine_runs_on_the_hosts_python() -> None:
    """Hosts run 3.12 and 3.13; the engine asks for 3.11, so the grammar stays at 3.11."""

    ast.parse(ENGINE_PATH.read_text(), feature_version=(3, 11))


def test_engine_stays_below_1500_lines() -> None:
    assert len(ENGINE_PATH.read_text().splitlines()) <= 1500
