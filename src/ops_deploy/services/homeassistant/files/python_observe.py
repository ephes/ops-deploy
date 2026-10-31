"""Original service-user Python/package probes with bounded, status-only output.

The controller must execute this as the declared service user, never as root.
No installation, application management, unit control or credential read occurs.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    # Package probes may import modules; keep bytecode out of the environment.
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=30, env=env)
    except OSError:
        # Original command tasks use failed_when:false. Preserve failed status
        # without exporting OS diagnostics; missing Python still fails its
        # version parser before a replacement decision can be made.
        return subprocess.CompletedProcess(argv, 127, "", "")


def observe(venv: str, kind: str, phase: str) -> dict[str, bool | str | int]:
    path = Path(venv)
    if (kind not in ("homeassistant", "matter") or phase not in ("environment", "application")
            or not path.is_absolute() or path == Path("/") or ".." in path.parts):
        raise ValueError("invalid declared environment")
    python = path / "bin/python"
    app = path / ("bin/hass" if kind == "homeassistant" else "bin/matter-server")
    # Original ansible.stat defaults follow:false, including dangling symlinks.
    state: dict[str, bool | str | int] = {"python_exists": os.path.lexists(python), "python_stdout": "", "pip_status": 0,
             "application_exists": os.path.lexists(app), "installed_version": "",
             "legacy_matter_status": 1, "chip_status": 0}
    if phase == "environment" and state["python_exists"]:
        python_version = run([str(python), "--version"])
        # The original aborts on a missing version token. Keep unexpected output
        # host-local rather than returning arbitrary diagnostics in a receipt.
        match = re.fullmatch(r"Python ([0-9]+(?:\.[0-9]+)+(?:[a-zA-Z0-9.+-]*)?)\s*", python_version.stdout)
        if match is None:
            raise ValueError("existing virtualenv returned no recognised Python version")
        state["python_stdout"] = "Python " + match.group(1)
        state["pip_status"] = run([str(python), "-m", "pip", "--version"]).returncode
        if kind == "homeassistant":
            state["legacy_matter_status"] = run([str(python), "-m", "pip", "show", "python-matter-server"]).returncode
    if phase == "application" and state["application_exists"]:
        if kind == "homeassistant":
            result = run([str(app), "--version"])
            parts = result.stdout.split()
            version = parts[0] if parts else ""
        else:
            state["chip_status"] = run([str(python), "-c", "import chip.exceptions"]).returncode
            result = run([str(python), "-m", "pip", "show", "python-matter-server"])
            matches = re.findall(r"^Version: (.+)$", result.stdout, re.MULTILINE)
            version = matches[0] if matches else ""
        if version and not re.fullmatch(r"[0-9][a-zA-Z0-9.+!-]*", version):
            raise ValueError("application returned an unrecognised version")
        state["installed_version"] = version
    return state


def main() -> None:
    payload = json.load(sys.stdin)
    if not isinstance(payload, dict) or set(payload) != {"venv", "kind", "phase"}:
        raise ValueError("invalid observation payload")
    print(json.dumps(observe(payload["venv"], payload["kind"], payload["phase"])))


if __name__ == "__main__":
    main()
