"""Exercise native-fixture admission before any privileged Docker operation."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent / "integration/minio/run-owned.sh"


@pytest.mark.parametrize(
    "overrides",
    [
        {},  # Positive control reaches the first stubbed repository command.
        {"GITHUB_ACTIONS": "false"},
        {"RUNNER_ENVIRONMENT": "self-hosted"},
        {"IMPLEMENTATION_SHA": "$(touch unsafe)"},
        {"GITHUB_RUN_ID": "1; touch unsafe"},
        {"GH_TOKEN": "synthetic-credential-must-not-enter"},
        {"GITHUB_TOKEN": "synthetic-credential-must-not-enter"},
    ],
)
def test_native_admission_rejects_unsafe_context_before_git_or_docker(
    tmp_path: Path, overrides: dict[str, str]
) -> None:
    commands = tmp_path / "bin"
    commands.mkdir()
    uname = commands / "uname"
    uname.write_text("#!/bin/sh\nprintf '%s\\n' x86_64\n")
    uname.chmod(0o700)
    for name in ("git", "docker"):
        command = commands / name
        command.write_text("#!/bin/sh\ntouch premature-operation\nexit 99\n")
        command.chmod(0o700)
    env = {
        "PATH": str(commands) + os.pathsep + os.environ["PATH"],
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "IMPLEMENTATION_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123",
        **overrides,
    }
    result = subprocess.run(["bash", str(SCRIPT)], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == (1 if overrides else 99)
    assert (tmp_path / "premature-operation").exists() == (not overrides)
    assert not (tmp_path / "unsafe").exists()
