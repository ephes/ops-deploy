"""Independent actual cf3 Ansible renders and vendored operational source."""

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
def test_vendored_sources_are_exact_cf3(name: str) -> None:
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
