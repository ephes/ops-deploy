"""The destructive root fixture refuses ordinary machines before doing any work."""

import os
import subprocess
from pathlib import Path


def test_native_fixture_refuses_non_runner_environment(tmp_path: Path) -> None:
    script = Path(__file__).parent / "integration/mailgun_relay/run.sh"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=tmp_path,
        env={
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "GITHUB_ACTIONS",
                "RUNNER_ENVIRONMENT",
                "GITHUB_RUN_ID",
                "RUNNER_TEMP",
            }
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "Refusing Mailgun fixture" in result.stderr
    assert list(tmp_path.iterdir()) == []
