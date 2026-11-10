"""The Echoport runner parts render what ops-library's roles render (``tests/parity/echoport_runner``).

``expected.json`` was written by ``tests/parity/echoport_runner/generate.py``
with ``ansible-playbook``: the sha256 of every runner script the register
playbooks render (from ``inputs.json``), and ``config.json`` and the sudoers
rule of the ``fastdeploy_runner`` role for a few settings. The tests here
need no Ansible. With ``OPS_LIBRARY_PATH`` and ``ansible-playbook`` (plus
``community.general``) the oracle test renders everything again and compares.

The templates in ``render.FORKED`` moved on from ops-library's: their
runners' recorded sha256 is ops-deploy's own rendering, and the oracle test
checks only that ops-library's copy (the Ansible rollback's) is still the one
recorded in ``forked_from``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services._echoport_runner import RunnerConfig, service_config, sudoers_rule
from ops_deploy.services._echoport_runner.render import FORKED, INCLUDES, PACKAGE, render_runner, runner_templates

HERE = Path(__file__).parent / "parity" / "echoport_runner"
INPUTS: dict[str, Any] = json.loads((HERE / "inputs.json").read_text())["runners"]
EXPECTED: dict[str, Any] = json.loads((HERE / "expected.json").read_text())
TEMPLATES = Path(__file__).parents[1] / "src" / PACKAGE.replace(".", "/") / "templates"
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.mark.parametrize("runner", sorted(INPUTS))
def test_runner_scripts_match_the_ansible_rendering(runner: str) -> None:
    spec = INPUTS[runner]

    assert _sha(render_runner(spec["template"], spec["inputs"])) == EXPECTED["runners"][runner]


def test_vendored_templates_are_the_recorded_ones() -> None:
    vendored = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in TEMPLATES.glob("*.j2")}

    assert vendored == EXPECTED["source_sha256"]


def test_every_runner_template_is_rendered_by_a_fixture() -> None:
    assert {spec["template"] for spec in INPUTS.values()} == set(runner_templates())
    assert set(EXPECTED["source_sha256"]) >= INCLUDES


def test_the_forked_templates_record_ops_librarys_copy() -> None:
    assert set(EXPECTED["forked_from"]) == FORKED
    assert set(runner_templates()) >= FORKED
    for name in FORKED:
        assert EXPECTED["forked_from"][name] != EXPECTED["source_sha256"][name], name


def test_includes_are_not_runner_templates() -> None:
    with pytest.raises(ValueError, match="not a vendored runner template"):
        render_runner("_work_dir.py.j2", {})


def test_an_undefined_template_variable_fails() -> None:
    spec = INPUTS["paperless-backup"]
    inputs = {key: value for key, value in spec["inputs"].items() if key != "paperless_echoport_backup_db_name"}

    with pytest.raises(Exception, match="paperless_echoport_backup_db_name"):
        render_runner(spec["template"], inputs)


def _role_config(case: dict[str, Any]) -> RunnerConfig:
    return RunnerConfig.model_validate({**case, "steps": tuple(case["steps"])})


@pytest.mark.parametrize("case", sorted(EXPECTED["role_cases"]))
def test_config_json_and_sudoers_match_the_role(case: str) -> None:
    cfg = _role_config(EXPECTED["role_cases"][case])

    assert service_config(cfg) == EXPECTED["role"][case]["config.json"]
    assert sudoers_rule(cfg) == EXPECTED["role"][case]["sudoers"]


def _oracle_ready() -> bool:
    if not OPS_LIBRARY or shutil.which("ansible-playbook") is None:
        return False
    probe = subprocess.run(
        ["ansible-doc", "-t", "filter", "community.general.dict_kv"], capture_output=True, text=True, check=False
    )
    return probe.returncode == 0


@pytest.mark.skipif(not _oracle_ready(), reason="OPS_LIBRARY_PATH, ansible-playbook or community.general missing")
def test_ansible_renders_the_recorded_expectations(tmp_path: Path) -> None:
    sys.path.insert(0, str(HERE))
    try:
        import generate  # type: ignore[import-not-found]
    finally:
        sys.path.remove(str(HERE))
    assert OPS_LIBRARY is not None
    library = Path(OPS_LIBRARY).resolve()
    own = {runner: spec for runner, spec in INPUTS.items() if spec["template"] not in FORKED}
    rendered = generate.render_templates(library, own, tmp_path)
    for runner, spec in own.items():
        assert render_runner(spec["template"], spec["inputs"]) == rendered[runner], runner
    role = generate.render_role(library, tmp_path)
    assert role == EXPECTED["role"]
    for name, digest in {**EXPECTED["source_sha256"], **EXPECTED["forked_from"]}.items():
        source = library / "roles/echoport_backup/templates" / name
        assert hashlib.sha256(source.read_bytes()).hexdigest() == digest, name
