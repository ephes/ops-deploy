"""Validate the real native fixture inputs through the original program's validator.

Since S12 the Python program is not deployed; its exact copy is the test oracle.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core.secrets import SecretRef
from ops_deploy.services.software_live import SoftwareLiveConfig

HARNESS = Path(__file__).parent / "integration/software_live/harness.py"
ORACLE = Path(__file__).parent / "parity/software_live/software_live.py"


@pytest.mark.parametrize(("platform", "version"), [("ubuntu", "24.04"), ("debian", "13")])
def test_native_fixture_actual_cfg_passes_original_policy_validator(
    tmp_path: Path, platform: str, version: str
) -> None:
    # Extract only the real cfg function: never import/run the root-only native harness.
    module = ast.parse(HARNESS.read_text())
    node = next(item for item in module.body if isinstance(item, ast.FunctionDef) and item.name == "cfg")
    namespace: dict[str, Any] = {
        "Path": Path,
        "Any": Any,
        "SoftwareLiveConfig": SoftwareLiveConfig,
        "REF": SecretRef("fixture.yml"),
        "os": os,
        "SHA": {},
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(HARNESS), "exec"), namespace)
    release = tmp_path / "os-release"
    release.write_text(f'ID={platform}\nVERSION_ID="{version}"\n')
    config = namespace["cfg"](os_release=release)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(config.policy))
    result = subprocess.run(
        [sys.executable, str(ORACLE), "validate", "--config", str(policy)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    # The prior native policy truly failed; this is repair evidence, not only preservation.
    del config.policy["traefik"]["binary_path"]
    policy.write_text(json.dumps(config.policy))
    rejected = subprocess.run(
        [sys.executable, str(ORACLE), "validate", "--config", str(policy)],
        capture_output=True,
        text=True,
    )
    assert rejected.returncode != 0
    assert "binary_path" in rejected.stderr
