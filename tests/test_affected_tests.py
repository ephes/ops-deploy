"""``scripts/affected_tests.py`` (``just test-changed``) on this tree: its rules, and failing open.

It keeps its parse cache in ``~/.cache/ops-deploy`` (keyed by file size and mtime), here as in use.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "affected_tests.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("affected_tests", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AT = _load()
SWEEPS = set(AT.ALWAYS)


def select(*paths: str) -> set[str] | None:
    selected: set[str] | None = AT.select(paths)
    return selected


def test_a_test_file_selects_itself_and_the_sweeps() -> None:
    assert select("tests/test_toy.py") == {"tests/test_toy.py", *SWEEPS}


def test_a_module_selects_the_test_files_that_import_it_directly_or_not() -> None:
    selected = select("src/ops_deploy/services/thermal_monitoring/fan_control.py")
    assert selected is not None
    # test_drive_fan_control imports it only through tests/drive_fan_control_fixtures.py.
    assert {"tests/test_fan_control.py", "tests/test_drive_fan_control.py"} <= selected
    assert {*SWEEPS, *AT.SOURCE_SWEEPS} <= selected
    assert "tests/test_toy.py" not in selected


def test_a_host_script_selects_the_tests_of_its_package_and_those_naming_it() -> None:
    selected = select("src/ops_deploy/services/thermal_monitoring/files/drive_fan_control.py")
    assert selected is not None
    assert {"tests/test_drive_fan_control.py", "tests/test_fan_control.py"} <= selected


def test_a_data_file_under_tests_selects_the_tests_that_name_it() -> None:
    selected = select("tests/golden/toy.conf")
    assert selected is not None
    assert "tests/test_toy.py" in selected


@pytest.mark.parametrize(
    "path",
    [
        "src/ops_deploy/core/config.py",
        "src/ops_deploy/ops/__init__.py",
        "src/ops_deploy/helpers/systemd.py",
        "src/ops_deploy/base/hostname.py",
        "src/ops_deploy/testing/__init__.py",
        "tests/conftest.py",
        "tests/fakehost.py",
        "pyproject.toml",
        "uv.lock",
        "justfile",
        # Built at run time: spelled out here, this file would name it and so select itself.
        "/".join(["somewhere", "-".join(["new", "and", "unknown"]) + ".cfg"]),
    ],
)
def test_core_widely_used_project_and_unmappable_files_select_the_whole_suite(path: str) -> None:
    assert select(path) is None


def test_documentation_no_module_names_runs_only_the_sweeps() -> None:
    assert select("/".join(["docs", "-".join(["never", "named"]) + ".md"])) == SWEEPS


def test_the_sweeps_exist() -> None:
    for test in (*AT.ALWAYS, *AT.SOURCE_SWEEPS):
        assert (ROOT / test).is_file(), test


def test_the_command_line_prints_the_selection_and_explains_it() -> None:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "--explain", "tests/test_toy.py"], capture_output=True, text=True, check=True
    )
    assert done.stdout.split() == sorted({"tests/test_toy.py", *SWEEPS})
    assert "tests/test_toy.py: test file: itself" in done.stderr
