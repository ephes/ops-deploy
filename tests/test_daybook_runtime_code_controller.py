"""Real SDK planning of user-owned runtime code, no inventory or app calls."""

from __future__ import annotations

import io
import re
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig
from ops_deploy.services.daybook_operations_runtime import code as api
from ops_deploy.testing import run_deploy_fake
from tests.test_daybook_inbox_deploy import source  # noqa: F401 - fixture


@pytest.fixture(autouse=True)
def record_owned_metadata_stream(monkeypatch: Any) -> None:
    # The production privacy boundary intentionally uses StringIO. The generic
    # fake recorder accepts only raw strings/lists; extend it for this owned
    # metadata-only test rather than weakening production stdin privacy.
    from ops_deploy.testing import harness

    original = harness._read_stdin

    def read(value: Any) -> str:
        return value.getvalue() if isinstance(value, io.StringIO) else original(value)

    monkeypatch.setattr(harness, "_read_stdin", read)


@pytest.mark.parametrize("current", [True, False])
def test_actual_sdk_context_clears_all_inherited_escalation_fields(
    source: tuple[SourceTree, Path],  # noqa: F811
    current: bool,
    monkeypatch: Any,
) -> None:
    from pyinfra.connectors.fake import FakeConnector

    handoffs: list[dict[str, Any]] = []
    original_shell, original_put = FakeConnector.run_shell_command, FakeConnector.put_file

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        handoffs.append(kwargs)
        return original_shell(connector, *args, **kwargs)

    def put(connector: Any, *args: Any, **kwargs: Any) -> Any:
        handoffs.append(kwargs)
        return original_put(connector, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", shell)
    monkeypatch.setattr(FakeConnector, "put_file", put)
    tree, bundle = source
    cfg = DaybookRuntimeConfig(user="fixture", owner="user", revision=tree.commit)
    run = run_deploy_fake(
        api.install_daybook_runtime_code,
        cfg,
        tree,
        bundle,
        host_data={
            "_sudo": True,
            "_sudo_user": "root",
            "_doas": True,
            "_doas_user": "root",
            "_dzdo": True,
            "_dzdo_user": "root",
            "_su_user": "root",
        },
        responses={"uname -s": ["Darwin"], api.code_command("status"): ["current" if current else "change"]},
    )
    assert run.succeeded, run.error
    assert run.ops[0].read_only is True
    assert run.ops[-1].read_only is True
    assert len(run.uploaded_paths) == (0 if current else 1)
    assert all(not re.search(r"(^|\s)(sudo|doas|dzdo|su)(\s|$)", event.value) for event in run.events)
    assert not run.fish_unsafe_commands
    assert handoffs
    for values in handoffs:
        assert all(values[key] is False for key in ("_sudo", "_doas", "_dzdo"))
        assert all(values[key] in {None, ""} for key in ("_sudo_user", "_doas_user", "_dzdo_user", "_su_user"))
    assert not any("operations status" in command for command in run.fact_commands)
    assert not any("sessions_source" in command for command in run.fact_commands)
    if not current:
        names = [op.name.rsplit(" | ", 1)[-1] for op in run.ops]
        assert names.index("Verify original runtime code is current or quiescent") < names.index(
            "Prepare private existing-identity runtime code transfer"
        )
        assert names.index("Prepare private existing-identity runtime code transfer") < names.index(
            "Upload exact original runtime Main bundle"
        )


def test_actual_queued_guard_failure_prevents_directory_transfer_and_source_work(
    source: tuple[SourceTree, Path],  # noqa: F811
) -> None:
    tree, bundle = source
    cfg = DaybookRuntimeConfig(user="fixture", owner="user", revision=tree.commit)
    run = run_deploy_fake(
        api.install_daybook_runtime_code,
        cfg,
        tree,
        bundle,
        responses={
            "uname -s": ["Darwin"],
            api.code_command("status"): ["change"],
            api.code_command("guard"): {"success": False, "stderr": ["runtime_code_or_environment_in_use"]},
        },
    )
    assert not run.succeeded
    assert not run.uploaded_paths
    assert not run.mutating_changed_ops


def test_studio_root_code_retains_separate_original_importer_dependency(
    source: tuple[SourceTree, Path],  # noqa: F811
) -> None:
    tree, _bundle = source
    with pytest.raises(ValueError, match="User-owned runtime code"):
        api.source_config(DaybookRuntimeConfig(user="fixture", revision=tree.commit))


def test_owned_source_fixture_refuses_local_host_before_any_identity_or_connection(tmp_path: Path) -> None:
    import json
    import os
    import subprocess
    import sys

    evidence = tmp_path / "evidence"
    script = Path(__file__).resolve().parents[1] / "smoke/daybook_runtime_code_native_fixture.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        timeout=20,
        env={
            **os.environ,
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "local",
            "GITHUB_RUN_ID": "1",
            "IMPLEMENTATION_SHA": "a" * 40,
            "MAC_APPS_EVIDENCE_DIR": str(evidence),
        },
    )
    assert result.returncode != 0
    receipts = list(evidence.glob("*.json"))
    assert len(receipts) == 1
    proof = json.loads(receipts[0].read_text())
    assert proof["failure_type"] == "RefusedHost"
    assert "installed_resources" not in proof
    assert "user_transport" not in proof
    assert not list(tmp_path.glob("**/actor"))


def test_uncleared_positive_control_proves_canonical_host_data_reaches_sdk(monkeypatch: Any) -> None:
    from pyinfra.api import deploy
    from pyinfra.connectors.fake import FakeConnector
    from pyinfra.operations import server

    from ops_deploy.testing.harness import wire_command

    handoffs: list[dict[str, Any]] = []
    wires: list[str] = []
    original = FakeConnector.run_shell_command

    def observe(connector: Any, command: Any, *args: Any, **kwargs: Any) -> Any:
        handoffs.append(kwargs)
        wires.append(wire_command(connector.state, connector.host, command, kwargs))
        return original(connector, command, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", observe)

    @deploy("Owned no-clearing positive control")
    def control() -> None:
        server.shell(commands="/usr/bin/true")

    run = run_deploy_fake(
        control,
        host_data={
            "_sudo": True,
            "_sudo_user": "root",
            "_doas": True,
            "_doas_user": "root",
            "_dzdo": True,
            "_dzdo_user": "root",
            "_su_user": "root",
        },
    )
    assert run.succeeded, run.error
    assert handoffs
    for values in handoffs:
        assert all(values[key] is True for key in ("_sudo", "_doas", "_dzdo"))
        assert all(values[key] == "root" for key in ("_sudo_user", "_doas_user", "_dzdo_user", "_su_user"))
    wire = "\n".join(wires)
    for command in ("sudo", "doas", "dzdo", "su"):
        assert re.search(r"(^|\s)" + command + r"(\s|$)", wire), wire
