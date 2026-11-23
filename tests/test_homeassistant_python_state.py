"""Virtualenv replacement, install and stop decisions from the observed environment."""

from __future__ import annotations

import itertools

import pytest

from ops_deploy.services.homeassistant.python_state import (
    EnvironmentState,
    homeassistant_decision,
    matter_decision,
)
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig


@pytest.mark.parametrize("matter", [False, True])
def test_replacement_and_install_predicates(matter: bool) -> None:
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
                python_stdout="Python 3.13.0" if wrong_python else "Python 3.14.10",
                pip_status=int(broken_pip),
                application_exists=app_exists,
                installed_version="old" if wrong_application else version,
                legacy_matter_status=0 if bad_dependency else 1,
                chip_status=int(bad_dependency),
            )
            # The virtualenv is rebuilt when it is missing, on another Python, has a broken pip,
            # is forced, or (Home Assistant only) a llama.cpp rebuild or legacy Matter package needs it.
            expected_replace = (
                force or not exists or wrong_python or broken_pip or (not matter and (rebuild or bad_dependency))
            )
            # The application is installed when forced, missing (or about to be with its
            # virtualenv), at another version, or (Matter) its CHIP dependency is broken.
            expected_install = (
                force
                or not (app_exists and not expected_replace)
                or wrong_application
                or (rebuild if not matter else bad_dependency)
            )
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


def test_stop_legacy_matter_even_when_management_disabled() -> None:
    cfg = HomeAssistantRuntimeConfig(manage_matter_server=False)
    state = EnvironmentState(True, "Python 3.14.10", legacy_matter_status=0)
    actual = homeassistant_decision(cfg, state, unit_exists=True, matter_unit_exists=True)
    assert actual.stop_services == ("matter-server", "homeassistant")


@pytest.mark.parametrize("spec", ["homeassistant", "homeassistant>=2026.10.2"])
def test_unpinned_spec_does_not_implicitly_upgrade(spec: str) -> None:
    cfg = HomeAssistantRuntimeConfig(package_spec=spec)
    state = EnvironmentState(True, "Python 3.14.10", application_exists=True, installed_version="2026.9.0")
    assert not homeassistant_decision(cfg, state).install_application


@pytest.mark.parametrize("stdout", ["", "not-a-version"])
def test_failed_version_response_is_not_hidden_as_replacement(stdout: str) -> None:
    with pytest.raises(ValueError, match="no Python version"):
        homeassistant_decision(HomeAssistantRuntimeConfig(force_reinstall=True), EnvironmentState(True, stdout))
