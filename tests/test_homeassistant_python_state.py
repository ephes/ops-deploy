"""Evaluate the bound original task predicates against prepared typed decisions."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml

from ops_deploy.services.homeassistant.python_state import (
    EnvironmentState,
    homeassistant_decision,
    matter_decision,
)
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

FIXTURE = Path(__file__).parent / "parity/homeassistant"


def original(file: str, name: str) -> dict[str, Any]:
    tasks = yaml.safe_load((FIXTURE / file).read_text())
    return next(task for task in tasks if task["name"] == name)


def evaluate(expression: str, values: dict[str, Any]) -> bool:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters["bool"] = bool
    expression = expression.strip().removeprefix("{{").removesuffix("}}").strip()
    return bool(env.compile_expression(expression)(**values))


@pytest.mark.parametrize("matter", [False, True])
def test_exact_original_replacement_and_install_predicates(matter: bool) -> None:
    file = "matter_server.yml" if matter else "python.yml"
    replacement_name = "Set Matter server virtualenv replacement fact" if matter else "Set virtualenv replacement fact"
    replacement = next(iter(original(file, replacement_name)["ansible.builtin.set_fact"].values()))
    mismatch_name = "Set Matter server Python version mismatch fact" if matter else "Set Python version mismatch fact"
    mismatch = next(iter(original(file, mismatch_name)["ansible.builtin.set_fact"].values()))
    install_name = "Install Matter server via uv pip" if matter else "Install Home Assistant via uv pip"
    install = original(file, install_name)["when"]
    # All combinations include absence, mismatched interpreter, broken pip,
    # legacy contamination/chip failure, force and rebuild independently.
    cases = itertools.product((False, True), repeat=9)
    for exists, wrong_python, broken_pip, bad_dependency, force, rebuild, app_exists, unit, matter_unit in cases:
        cfg = HomeAssistantRuntimeConfig(
            force_reinstall=force,
            package_spec="homeassistant==2026.10.2",
            matter_server_package_spec="python-matter-server[server]==8.1.2",
        )
        version = "8.1.2" if matter else "2026.10.2"
        for wrong_application in (False, True):
            state = EnvironmentState(
                python_exists=exists,
                python_stdout="Python 3.13.0" if wrong_python else "Python 3.14.8",
                pip_status=int(broken_pip),
                application_exists=app_exists,
                installed_version="old" if wrong_application else version,
                legacy_matter_status=0 if bad_dependency else 1,
                chip_status=int(bad_dependency),
            )
            prefix = "_ha_matter" if matter else "_ha"
            values: dict[str, Any] = {
                "homeassistant_force_reinstall": force,
                "_ha_llama_cpp_rebuild": rebuild,
                prefix + "_venv_python_stat": {"stat": {"exists": exists}},
                "homeassistant_python_version": cfg.python_version,
                prefix + "_current_python_version": {"stdout": state.python_stdout},
                prefix + "_current_pip_check": {"rc": int(broken_pip)},
                "_ha_legacy_matter_server_package_check": {"rc": state.legacy_matter_status},
            }
            values[prefix + "_python_mismatch"] = evaluate(mismatch, values) if exists else False
            expected_replace = evaluate(replacement, values)
            values.update(
                {
                    ("_ha_matter_binary" if matter else "_ha_hass_binary"): {
                        "stat": {"exists": app_exists and not expected_replace}
                    },
                    prefix + "_version_mismatch": wrong_application,
                    "_ha_matter_chip_ok": not bad_dependency,
                }
            )
            expected_install = evaluate(install, values)
            actual = (
                matter_decision(cfg, state, unit_exists=unit)
                if matter
                else homeassistant_decision(
                    cfg, state, llama_cpp_rebuild=rebuild, unit_exists=unit, matter_unit_exists=matter_unit
                )
            )
            assert actual.replace is expected_replace
            assert actual.install_application is expected_install
            expected_stops = []
            if expected_replace and exists:
                if matter and unit:
                    expected_stops.append("matter-server")
                elif not matter:
                    if matter_unit:
                        expected_stops.append("matter-server")
                    if unit:
                        expected_stops.append("homeassistant")
            assert actual.stop_services == tuple(expected_stops)


def test_stop_original_legacy_matter_even_when_management_disabled() -> None:
    cfg = HomeAssistantRuntimeConfig(manage_matter_server=False)
    state = EnvironmentState(True, "Python 3.14.8", legacy_matter_status=0)
    actual = homeassistant_decision(cfg, state, unit_exists=True, matter_unit_exists=True)
    assert actual.stop_services == ("matter-server", "homeassistant")
    task = original("python.yml", "Stop Matter server before replacing Home Assistant virtualenv")
    assert all("manage_matter_server" not in clause for clause in task["when"])
    assert task["ansible.builtin.systemd"]["state"] == "stopped"


@pytest.mark.parametrize("spec", ["homeassistant", "homeassistant>=2026.10.2"])
def test_unpinned_original_does_not_implicitly_upgrade(spec: str) -> None:
    cfg = HomeAssistantRuntimeConfig(package_spec=spec)
    state = EnvironmentState(True, "Python 3.14.8", application_exists=True, installed_version="2026.9.0")
    assert not homeassistant_decision(cfg, state).install_application


@pytest.mark.parametrize("stdout", ["", "not-a-version"])
def test_failed_version_response_is_not_hidden_as_replacement(stdout: str) -> None:
    with pytest.raises(ValueError, match="no Python version"):
        homeassistant_decision(HomeAssistantRuntimeConfig(force_reinstall=True), EnvironmentState(True, stdout))


def test_original_sources_exact() -> None:
    source = json.loads((FIXTURE / "python-source.json").read_text())
    for path, digest in source["files"].items():
        assert hashlib.sha256((FIXTURE / Path(path).name).read_bytes()).hexdigest() == digest
        if os.environ.get("OPS_LIBRARY_PATH"):
            assert hashlib.sha256((Path(os.environ["OPS_LIBRARY_PATH"]) / path).read_bytes()).hexdigest() == digest
