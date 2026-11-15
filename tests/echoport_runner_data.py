"""The Echoport runners' synthetic inputs and the recorded renders of their scripts.

``tests/fixtures/echoport_runner/inputs.json`` holds the template variables
of every runner (``runners``) and RunnerConfig inputs for ``config.json`` and
the sudoers rule (``service_cases``). The scripts are 20 to 80 kB each, so
``tests/golden/echoport_runner/runner-sha256.json`` records the sha256 of
each rendered script instead of the script (``test_echoport_runner_golden``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures" / "echoport_runner"
GOLDEN = Path(__file__).parent / "golden" / "echoport_runner"
_DATA: dict[str, Any] = json.loads((FIXTURES / "inputs.json").read_text())
INPUTS: dict[str, Any] = _DATA["runners"]
SERVICE_CASES: dict[str, Any] = _DATA["service_cases"]
RUNNER_SHA256_PATH = GOLDEN / "runner-sha256.json"


def runner_sha256() -> dict[str, str]:
    """The recorded sha256 of each runner's rendered script."""

    recorded: dict[str, str] = json.loads(RUNNER_SHA256_PATH.read_text())
    return recorded
