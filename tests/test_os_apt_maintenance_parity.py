"""Actual Ansible template output from ops-library cf3a0c74, with independent inputs.

The committed weekly/custom files were rendered by ansible.builtin.template,
not by the public renderer. source.json records the exact template hashes and
Ansible version. No role tasks, apt commands or services were run to capture it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from ops_deploy.services.os_apt_maintenance import OsAptMaintenanceConfig
from ops_deploy.services.os_apt_maintenance.deploy import render_role

CASES = Path(__file__).parent / "parity/os_apt_maintenance"
PACKAGE = Path(__file__).parents[1] / "src/ops_deploy/services/os_apt_maintenance/templates"
SOURCE = json.loads((CASES / "source.json").read_text())
TEMPLATES = sorted(SOURCE["templates"])


@pytest.mark.parametrize("case", ["weekly", "custom"])
@pytest.mark.parametrize("template", TEMPLATES)
def test_rendered_files_match_actual_ansible(case: str, template: str) -> None:
    directory = CASES / case
    config = OsAptMaintenanceConfig.model_validate(
        {"secrets": "secrets/fixture.yml", **json.loads((directory / "config.json").read_text())}
    )
    assert render_role(template, config, "100.64.0.7") == (directory / (template + ".rendered")).read_text()


@pytest.mark.parametrize("template", TEMPLATES)
def test_packaged_templates_match_captured_role_source(template: str) -> None:
    assert hashlib.sha256((PACKAGE / template).read_bytes()).hexdigest() == SOURCE["templates"][template]


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
@pytest.mark.parametrize("template", TEMPLATES)
def test_current_library_matches_captured_role_source(template: str) -> None:
    role = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles/os_apt_maintenance/templates"
    assert hashlib.sha256((role / template).read_bytes()).hexdigest() == SOURCE["templates"][template]
