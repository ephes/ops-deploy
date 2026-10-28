"""Actual embedded CLI on owned synthetic files, no launchctl/app/inventory."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api.command import StringCommand
from pyinfra.connectors.util import make_unix_command

from ops_deploy.services.daybook_sessions.deploy import resource_command
from ops_deploy.testing import fish_unsafe
from tests import test_daybook_sessions_resource_stage as resource_cases
from tests.test_daybook_sessions_controls import snapshot

stage = resource_cases.stage
SHELLS = ["bash", pytest.param("fish", marks=pytest.mark.skipif(not shutil.which("fish"), reason="no fish"))]


def invoke(action: str, data: Any) -> subprocess.CompletedProcess[str]:
    argv = shlex.split(resource_command(action))
    argv[0] = sys.executable
    return subprocess.run(argv, input=json.dumps(data), text=True, capture_output=True, timeout=10)


def test_actual_cli_first_and_repeat_are_private_and_metadata_stable(
    stage: tuple[dict[str, Any], resource_cases.Timers], tmp_path: Path
) -> None:
    data, _timers = stage
    data["config"]["daybook_sessions_launchd_manage_state"] = False
    private = data["resources"][0]["content"]
    for action in ("status", "apply", "verify"):
        result = invoke(action, data)
        assert result.returncode == 0, result.stderr
        assert private not in result.stdout + result.stderr
        assert private not in resource_command(action)
    stable = snapshot(tmp_path.resolve())
    for action in ("status", "apply", "verify"):
        result = invoke(action, data)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["identity_verified"] is False
        assert snapshot(tmp_path.resolve()) == stable


def test_actual_cli_never_echoes_malformed_private_payload_or_exception() -> None:
    private = "UNUSABLE-PRIVATE-CONTENT"
    result = invoke("status", {"config": private})
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "sessions_resources_failed\n"
    assert private not in result.stdout + result.stderr


def test_controller_refuses_unknown_resource_action() -> None:
    with pytest.raises(ValueError, match="Unsupported Sessions resource action"):
        resource_command("activate")


@pytest.mark.parametrize("shell", SHELLS)
def test_composed_resource_cli_and_managed_synthetic_probe_through_real_login_shells(
    stage: tuple[dict[str, Any], resource_cases.Timers], tmp_path: Path, shell: str
) -> None:
    data, _timers = stage
    data["config"]["daybook_sessions_launchd_manage_state"] = False
    private = "UNUSABLE-OWNED-'\\\\-PRIVATE-$HOME-`x`\n"
    data["resources"][0]["content"] = private

    def call(action: str) -> subprocess.CompletedProcess[str]:
        argv = shlex.split(resource_command(action))
        argv[0] = sys.executable
        command = shlex.join(argv)
        line = make_unix_command(StringCommand(command)).get_raw_value()
        assert not fish_unsafe(line)
        assert private not in line
        result = subprocess.run([shell, "-c", line], input=json.dumps(data), text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert private not in result.stdout + result.stderr
        return result

    call("apply")
    call("verify")
    assert Path(data["resources"][0]["path"]).read_text() == private
    before = snapshot(tmp_path.resolve())
    data["config"].update(
        daybook_archive_quote_classifier_enabled=True,
        daybook_archive_quote_classifier_probe_enabled=True,
        daybook_archive_quote_classifier_probe_timeout_seconds=5,
        daybook_archive_quote_classifier_cmd=shlex.join(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import sys;assert sys.stdin.read()=='Return exactly OK.\\n';print('OK')",
            ]
        ),
    )
    call("classifier-probe")
    assert snapshot(tmp_path.resolve()) == before
