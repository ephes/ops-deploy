"""OpenClaw writes the files, directories and gateway config hosts have, byte for byte.

``tests/golden/openclaw/<case>.json`` records, for each case's inputs
(``tests/fixtures/openclaw/<case>``), every file the deploy writes (sha256,
owner, group, mode), every directory, the ``.env`` and the resulting
``openclaw.json``. It was first recorded when these equalled what the
openclaw_deploy role computed. The cases: ``production`` (production-shaped
values with synthetic secrets and an existing gateway config with legacy
keys), ``audio-disabled`` (the managed audio transcription switched off over
a config that holds it) and ``seed`` (a first deploy that builds the config
itself).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
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
from tests.goldens import assert_golden

CASES = Path(__file__).parent / "fixtures" / "openclaw"
GOLDEN = Path(__file__).parent / "golden" / "openclaw"
PACKAGE = Path(__file__).parents[1] / "src" / "ops_deploy" / "services" / "openclaw"
NAMES = sorted(path.name for path in CASES.iterdir() if (path / "vars.json").exists())


def load_vars(case: Path) -> dict[str, Any]:
    """``vars.json`` with workspace skill sources (``./...``) relative to the case."""

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


def role_variables(name: str) -> dict[str, Any]:
    cfg, secrets = inputs(name)
    return cfg.role_variables(secrets)


def planned_files(v: dict[str, Any], *, existing: bool, present: set[str]) -> list[layout.FileSpec]:
    """Every file the deploy writes, under main.yml's conditions."""

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


def directories(v: dict[str, Any]) -> dict[str, dict[str, str]]:
    specs = layout.directories(v)
    if v["openclaw_workspace_skills"]:
        specs += layout.workspace_directories(v)
    found = {spec.path: {"owner": spec.owner, "group": spec.group, "mode": spec.mode} for spec in specs}
    # Created by the deploy directly (traefik.yml and metrics.yml).
    if ansible_bool(v["openclaw_traefik_enabled"]):
        found["/etc/traefik/dynamic"] = {"owner": "root", "group": "root", "mode": "0755"}
    if ansible_bool(v["openclaw_metrics_endpoint_enabled"]):
        for path in ("/var/lib/openclaw-metrics", "/etc/openclaw-metrics-endpoint"):
            found[path] = {"owner": "root", "group": "metrics", "mode": "0750"}
    return found


def patched_config(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """The existing ``openclaw.json`` after the host step patched it (checked to converge)."""

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
    # A converged file: the check answers current and nothing is written.
    assert script.config(request, False) is False
    assert script.config(request, True) is False
    return path.read_text()


def test_cases_cover_the_interesting_inputs() -> None:
    assert NAMES == ["audio-disabled", "production", "seed"]


@pytest.mark.parametrize("name", NAMES)
def test_host_state_matches_golden(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    config = patched_config(name, tmp_path, monkeypatch) if existing else layout.seed_file(v).content.decode()
    recorded = {
        "files": dict(sorted(files.items())),
        "directories": dict(sorted(directories(v).items())),
        "env": layout.env_file(v).content.decode(),
        "openclaw_json": config,
    }
    assert_golden(GOLDEN / f"{name}.json", json.dumps(recorded, indent=2) + "\n")


def test_a_seeded_override_is_only_normalized(tmp_path: Path) -> None:
    script = host_script()
    path = tmp_path / "openclaw.json"
    path.write_text(json.dumps({"channels": {"telegram": {"enabled": True, "streamMode": "partial"}}}))
    request = {**config_request(role_variables("seed")), "path": str(path), "force": True}

    assert script.config(request, True) is True
    assert json.loads(path.read_text()) == {
        "channels": {"telegram": {"enabled": True, "streaming": {"mode": "partial"}}}
    }
    assert script.config(request, False) is False
