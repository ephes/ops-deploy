"""What the ported Traefik transaction engine adds to, or leaves out of, ops-library's.

``test_traefik_tx_parity`` compares the two engines; this module covers the port on
its own: the actions it refuses, that it runs as a standalone standard-library
program, its size, and that it shares the reference engine's state, lock and actions.
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
from tests.traefik_tx_fixtures import (
    REFERENCE_COMMIT,
    REFERENCE_PATH,
    REFERENCE_SHA256,
    FakeHost,
    base_setup,
    reference,
    sha256,
)

ENGINE_PATH = Path(engine.__file__)
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
POLICY = {
    "host": "canary",
    "binary_path": "/usr/local/bin/traefik",
    "config_path": "/etc/traefik/traefik.toml",
    "dynamic_path": "/etc/traefik/dynamic",
}
NOT_PORTED = ("enroll", "alias", "metrics_bind", "acme_storage")


@pytest.mark.parametrize("action", NOT_PORTED)
def test_actions_left_to_ansible_are_refused_before_anything_is_touched(action: str, tmp_path: Path) -> None:
    host = FakeHost(engine, tmp_path)
    host.install()
    with host.patched():
        request = base_setup(host, action).request
        with (
            patch.object(engine, "identity", side_effect=AssertionError("identity read")),
            pytest.raises(engine.Refused, match=f"^action not ported to ops-deploy, .*: {action}$"),
        ):
            engine.execute(request)

    assert not host.state_root.exists()
    assert not (tmp_path / "lock").exists()
    assert host.calls == []


@pytest.mark.parametrize("action", NOT_PORTED)
def test_refused_actions_exit_2_as_a_standalone_script(action: str, tmp_path: Path) -> None:
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
    assert json.loads(result.stdout) == {
        "failed": True,
        "error": f"action not ported to ops-deploy, use the Ansible transaction path: {action}",
    }


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


def test_the_reference_engine_knows_exactly_these_actions() -> None:
    """Every action of the port's ``ACTIONS`` gets past the reference engine's action check."""

    with (
        patch.object(reference, "identity", side_effect=RuntimeError("identity")),
        patch("os.geteuid", return_value=1000),
    ):
        for action in [*engine.ACTIONS, "rollback"]:
            with pytest.raises(RuntimeError) as raised:
                reference.execute({"action": action, "policy": POLICY})
            assert (str(raised.value) == "unknown action") is (action == "rollback")
    assert set(engine.PORTED) < set(engine.ACTIONS)
    assert set(engine.ACTIONS) - set(engine.PORTED) == set(NOT_PORTED)


def test_state_and_lock_are_the_reference_engines_and_the_guards() -> None:
    assert engine.STATE_ROOT == reference.STATE_ROOT == Path(traefik_deploy.TRANSACTION_STATE)
    assert engine.LOCK == reference.LOCK == Path("/run/lock/traefik-transaction.lock")


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
    """Hosts run 3.12 and 3.13; the reference engine asks for 3.11, so the grammar stays at 3.11."""

    ast.parse(ENGINE_PATH.read_text(), feature_version=(3, 11))


def test_engine_stays_below_1500_lines() -> None:
    assert len(ENGINE_PATH.read_text().splitlines()) <= 1500


def test_vendored_reference_is_ops_library_3110a0f1() -> None:
    assert REFERENCE_COMMIT.startswith("3110a0f1")
    assert sha256(REFERENCE_PATH.read_bytes()) == REFERENCE_SHA256


@pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
def test_vendored_reference_matches_ops_library() -> None:
    assert OPS_LIBRARY is not None
    source = Path(OPS_LIBRARY, "roles", "traefik_deploy", "files", "traefik_transaction.py")

    assert source.is_file(), f"{source} is gone; the port follows it"
    assert source.read_bytes() == REFERENCE_PATH.read_bytes(), (
        f"{source} changed since ops-library {REFERENCE_COMMIT[:8]}: port the change, re-run the parity tests, "
        "then re-vendor it and update REFERENCE_SHA256 and REFERENCE_COMMIT"
    )
