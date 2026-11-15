"""The Echoport runners' host files stay what hosts have (``tests/golden/echoport_runner``).

Each runner script (root-owned under ``/usr/local/libexec/fastdeploy``), its
``config.json`` and its sudoers rule are rendered from synthetic inputs
(``tests/echoport_runner_data.py``) and compared with the recorded renders:
identical bytes mean the next registration rewrites nothing. The scripts are
recorded as sha256 (``runner-sha256.json``); a changed digest names the runner.
See ``tests/goldens.py`` for re-recording an intended change.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from ops_deploy.services._echoport_runner import RunnerConfig, service_config, sudoers_rule
from ops_deploy.services._echoport_runner.render import render_runner, runner_templates
from tests.echoport_runner_data import GOLDEN, INPUTS, RUNNER_SHA256_PATH, SERVICE_CASES
from tests.goldens import assert_golden


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_runner_scripts() -> None:
    digests = {runner: _sha(render_runner(spec["template"], spec["inputs"])) for runner, spec in INPUTS.items()}

    assert_golden(RUNNER_SHA256_PATH, json.dumps(digests, indent=2, sort_keys=True) + "\n")


def test_every_runner_template_is_rendered_by_a_fixture() -> None:
    assert {spec["template"] for spec in INPUTS.values()} == set(runner_templates())


def test_includes_are_not_runner_templates() -> None:
    with pytest.raises(ValueError, match="not a vendored runner template"):
        render_runner("_work_dir.py.j2", {})


def test_an_undefined_template_variable_fails() -> None:
    spec = INPUTS["paperless-backup"]
    inputs = {key: value for key, value in spec["inputs"].items() if key != "paperless_echoport_backup_db_name"}

    with pytest.raises(Exception, match="paperless_echoport_backup_db_name"):
        render_runner(spec["template"], inputs)


def _config(case: dict[str, Any]) -> RunnerConfig:
    return RunnerConfig.model_validate({**case, "steps": tuple(case["steps"])})


@pytest.mark.parametrize("case", sorted(SERVICE_CASES))
def test_config_json_and_sudoers(case: str) -> None:
    cfg = _config(SERVICE_CASES[case])

    assert_golden(GOLDEN / case / "config.json", service_config(cfg))
    assert_golden(GOLDEN / case / "sudoers", sudoers_rule(cfg))
