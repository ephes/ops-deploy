"""Independent actual Ansible renders, vendored operational source and the test oracle."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from ops_deploy.services.software_live.common import RESOURCE, render
from tests.test_software_live import config

CASES = Path(__file__).parent / "parity/software_live"
SOURCE = json.loads((CASES / "source.json").read_text())


@pytest.mark.parametrize("case", ["defaults", "custom-shadow"])
@pytest.mark.parametrize("template", sorted(SOURCE["templates"]))
def test_actual_ansible_render(case: str, template: str) -> None:
    directory = CASES / case
    cfg = config(**json.loads((directory / "config.json").read_text()))
    assert render(template, cfg) == (directory / (template + ".rendered")).read_text()


@pytest.mark.parametrize("name", [*("templates/" + name for name in SOURCE["templates"]), *SOURCE["files"]])
def test_vendored_sources_are_exact_library(name: str) -> None:
    expected = SOURCE["files"].get(name) or SOURCE["templates"][name.removeprefix("templates/")]
    assert hashlib.sha256(RESOURCE.joinpath(name).read_bytes()).hexdigest() == expected


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
@pytest.mark.parametrize("name", [*("templates/" + name for name in SOURCE["templates"]), *SOURCE["files"]])
def test_actual_current_library_source(name: str) -> None:
    library = Path(os.environ["OPS_LIBRARY_PATH"])
    path = library / (
        "plugins/filter/software_live_impl.py"
        if name == "files/software_live_impl.py"
        else "roles/software_live/" + name
    )
    assert path.read_bytes() == RESOURCE.joinpath(name).read_bytes()


ORACLE = CASES / "software_live.py"


def test_python_oracle_is_exact_and_not_deployed() -> None:
    # S12: the retired Python program is only the policy-validation oracle of the
    # tests, as in ops-library; nothing in the package installs it.
    assert hashlib.sha256(ORACLE.read_bytes()).hexdigest() == SOURCE["oracle"]["software_live.py"]
    assert not RESOURCE.joinpath("files/software_live.py").is_file()
    assert not RESOURCE.joinpath("templates/impl-endpoint.conf.j2").is_file()
    assert not RESOURCE.joinpath("templates/impl-collector.conf.j2").is_file()


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_actual_current_library_oracle() -> None:
    library = Path(os.environ["OPS_LIBRARY_PATH"])
    assert (library / "roles/software_live/files/software_live.py").read_bytes() == ORACLE.read_bytes()
