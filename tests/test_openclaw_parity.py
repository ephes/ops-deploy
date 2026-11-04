"""OpenClaw writes what the openclaw_deploy role writes, byte for byte.

``tests/parity/openclaw_deploy/<case>/expected.json`` is what ansible-core
2.21 computed from the role (ops-library main 44a532ba) for the case's
variables (``generate.py`` there): every file's sha256, owner, group and mode,
every directory, the resulting ``openclaw.json`` and the ``.env``. The cases:
``production`` (the playbook's values with synthetic secrets and an existing
gateway config with legacy keys), ``audio-disabled`` (the managed audio
transcription switched off over a config that holds it) and ``seed`` (a
first deploy that builds the config itself).

With ``OPS_LIBRARY_PATH`` set, the vendored templates, defaults and
``validate.yml`` are compared with the role's.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ops_deploy.services._metrics_httpd import HttpdSwitchFields
from ops_deploy.services.openclaw import OpenClawConfig, OpenClawSecrets, layout
from ops_deploy.services.openclaw.config import SECRET_VARIABLES
from ops_deploy.services.openclaw.deploy import config_request
from ops_deploy.services.openclaw.variables import ansible_bool

CASES = Path(__file__).parent / "parity" / "openclaw_deploy"
PACKAGE = Path(__file__).parents[1] / "src" / "ops_deploy" / "services" / "openclaw"
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
NAMES = sorted(path.name for path in CASES.iterdir() if (path / "vars.json").exists())


def load_vars(case: Path) -> dict[str, Any]:
    """``vars.json`` with workspace skill sources (``./...``) relative to the case (as generate.py reads it)."""

    inputs: dict[str, Any] = json.loads((case / "vars.json").read_text())
    for skill in inputs.get("openclaw_workspace_skills", []):
        for item in skill["files"]:
            item["src"] = str((case / item["src"]).resolve())
    return inputs


def inputs(name: str) -> tuple[OpenClawConfig, OpenClawSecrets]:
    variables = load_vars(CASES / name)
    impl = variables.pop("metrics_httpd_impl", "python")
    public = {key: value for key, value in variables.items() if key not in SECRET_VARIABLES}
    secret = {key: value for key, value in variables.items() if key in SECRET_VARIABLES}
    return OpenClawConfig(variables=public, httpd=HttpdSwitchFields(httpd_impl=impl)), OpenClawSecrets(variables=secret)


def expected(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((CASES / name / "expected.json").read_text())
    return loaded


def role_variables(name: str) -> dict[str, Any]:
    cfg, secrets = inputs(name)
    return cfg.role_variables(secrets)


def planned_files(v: dict[str, Any], *, existing: bool, present: set[str]) -> list[layout.FileSpec]:
    """Every file the deploy writes, as the role's task files would (main.yml's conditions)."""

    specs = [layout.env_file(v)]
    if not existing:
        specs.append(layout.seed_file(v))
    specs += layout.workspace_prompts(v)
    if ansible_bool(v["openclaw_audio_transcription_enabled"]):
        specs.append(layout.audio_plan(v))
    specs += [layout.compose_file(v), layout.unit_file(v)]
    if ansible_bool(v["openclaw_traefik_enabled"]):
        specs.append(layout.route_file(v))
    specs.append(layout.logrotate_file(v))
    if ansible_bool(v["openclaw_weeknotes_enabled"]):
        specs += layout.weeknotes_files(v)
    specs += [spec for spec in layout.feature_files(v) if not (spec.create_only and spec.path in present)]
    specs += layout.workspace_skill_files(v)
    if ansible_bool(v["openclaw_metrics_endpoint_enabled"]):
        specs += layout.metrics_files(v).values()
    specs.append(layout.manifest_file(v))
    return specs


def host_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("openclaw_host", PACKAGE / "files" / "openclaw_host.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cases_cover_the_interesting_inputs() -> None:
    assert NAMES == ["audio-disabled", "production", "seed"]


@pytest.mark.parametrize("name", NAMES)
def test_files_match_ansible(name: str) -> None:
    v = role_variables(name)
    case = CASES / name
    existing = (case / "openclaw.json").exists()
    present = set(json.loads((case / "present.json").read_text())) if (case / "present.json").exists() else set()
    files = {
        spec.path: {
            "sha256": hashlib.sha256(spec.content).hexdigest(),
            "owner": spec.owner,
            "group": spec.group,
            "mode": spec.mode,
        }
        for spec in planned_files(v, existing=existing, present=present)
    }
    want = dict(expected(name)["files"])
    if existing:
        # The host step patches the existing file; test_config_patch_matches_ansible compares it.
        want.pop(f"{v['openclaw_data_dir']}/openclaw.json")

    assert files == want


@pytest.mark.parametrize("name", NAMES)
def test_directories_match_ansible(name: str) -> None:
    v = role_variables(name)
    specs = layout.directories(v)
    if v["openclaw_workspace_skills"]:
        specs += layout.workspace_directories(v)
    directories = {spec.path: {"owner": spec.owner, "group": spec.group, "mode": spec.mode} for spec in specs}
    # Created by the deploy directly (traefik.yml and metrics.yml).
    if ansible_bool(v["openclaw_traefik_enabled"]):
        directories["/etc/traefik/dynamic"] = {"owner": "root", "group": "root", "mode": "0755"}
    if ansible_bool(v["openclaw_metrics_endpoint_enabled"]):
        for path in ("/var/lib/openclaw-metrics", "/etc/openclaw-metrics-endpoint"):
            directories[path] = {"owner": "root", "group": "metrics", "mode": "0750"}

    assert directories == expected(name)["directories"]


@pytest.mark.parametrize("name", NAMES)
def test_env_matches_ansible(name: str) -> None:
    assert layout.env_file(role_variables(name)).content.decode() == expected(name)["env"]


def test_seed_matches_ansible() -> None:
    v = role_variables("seed")

    assert layout.seed_file(v).content.decode() == expected("seed")["openclaw_json"]


@pytest.mark.parametrize("name", [name for name in NAMES if (CASES / name / "openclaw.json").exists()])
def test_config_patch_matches_ansible(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    script = host_script()
    # The host writes the patched file as 1000:1000; the test runs unprivileged.
    monkeypatch.setattr(script.os, "fchown", lambda *_: None)
    path = tmp_path / "openclaw.json"
    shutil.copy(CASES / name / "openclaw.json", path)
    path.chmod(0o600)
    request = {**config_request(role_variables(name)), "path": str(path)}

    assert script.config(request, False) is True
    assert path.read_bytes() == (CASES / name / "openclaw.json").read_bytes()
    assert script.config(request, True) is True
    assert path.read_text() == expected(name)["openclaw_json"]
    # A converged file: the check answers current and nothing is written.
    assert script.config(request, False) is False
    assert script.config(request, True) is False


TEMPLATES = sorted(path.name for path in (PACKAGE / "templates").iterdir())


@needs_ops_library
@pytest.mark.parametrize("template", TEMPLATES)
def test_vendored_templates_match_ops_library(template: str) -> None:
    assert OPS_LIBRARY is not None
    role = Path(OPS_LIBRARY, "roles", "openclaw_deploy", "templates", template)

    assert (PACKAGE / "templates" / template).read_bytes() == role.read_bytes()


@needs_ops_library
def test_every_role_template_is_vendored() -> None:
    assert OPS_LIBRARY is not None
    role = Path(OPS_LIBRARY, "roles", "openclaw_deploy", "templates")

    assert sorted(path.name for path in role.iterdir()) == TEMPLATES


@needs_ops_library
@pytest.mark.parametrize(
    ("vendored", "role_file"),
    [
        ("deploy_defaults.yml", "openclaw_deploy/defaults/main.yml"),
        ("remove_defaults.yml", "openclaw_remove/defaults/main.yml"),
        ("validate.yml", "openclaw_deploy/tasks/validate.yml"),
    ],
)
def test_vendored_role_files_match_ops_library(vendored: str, role_file: str) -> None:
    assert OPS_LIBRARY is not None

    assert (PACKAGE / "files" / vendored).read_bytes() == Path(OPS_LIBRARY, "roles", role_file).read_bytes()
