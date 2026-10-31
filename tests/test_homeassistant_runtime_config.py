"""Original default interpolation and rendered service units, without a target."""

from __future__ import annotations

import hashlib
import json
import os
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

import jinja2
import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.services.homeassistant.render import render_unit
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"user": "ha_test"},
        {"site_path": "/srv/ha", "data_path": "/data/ha", "service_name": "custom-ha"},
        {
            "virtualenv_path": "/opt/ha-venv",
            "matter_server_virtualenv_path": "/opt/matter",
            "matter_server_log_file": "",
        },
    ],
)
def test_default_interpolation_and_round_trip(overrides: dict[str, Any]) -> None:
    cfg = HomeAssistantRuntimeConfig.model_validate(overrides)
    assert cfg.group == overrides.get("user", "homeassistant")
    assert cfg.config_path == cfg.site_path + "/config"
    assert cfg.virtualenv_version_file == cfg.virtualenv_path + "/.ansible-python-version"
    assert cfg.matter_server_virtualenv_version_file == cfg.matter_server_virtualenv_path + "/.ansible-python-version"
    assert cfg.matter_server_storage_path == cfg.data_path + "/matter-server"
    assert HomeAssistantRuntimeConfig.model_validate_json(cfg.model_dump_json()) == cfg


@pytest.mark.parametrize("unit", ["homeassistant", "matter-server"])
@pytest.mark.parametrize("manage", [True, False])
def test_unit_preserves_exact_source_render(unit: Literal["homeassistant", "matter-server"], manage: bool) -> None:
    cfg = HomeAssistantRuntimeConfig(
        user="ha_test",
        site_path="/srv/ha",
        manage_matter_server=manage,
        matter_server_service_name="matter-test",
        matter_server_log_file="",
    )
    fixture = Path(__file__).parent / "parity/homeassistant" / (unit + ".service.j2")
    original = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True, undefined=jinja2.StrictUndefined)
    expected = original.from_string(fixture.read_text()).render(
        **{f"homeassistant_{key}": value for key, value in cfg.model_dump().items()}
    )
    assert render_unit(cfg, unit) == expected
    assert (
        files("ops_deploy.services.homeassistant").joinpath("templates", fixture.name).read_bytes()
        == fixture.read_bytes()
    )


def test_bound_original_defaults_and_templates() -> None:
    fixture = Path(__file__).parent / "parity/homeassistant"
    source = json.loads((fixture / "runtime-source.json").read_text())
    defaults = yaml.safe_load((fixture / "defaults.yml").read_text())
    assert (
        hashlib.sha256((fixture / "defaults.yml").read_bytes()).hexdigest()
        == source["files"]["roles/homeassistant_deploy/defaults/main.yml"]
    )
    cfg = HomeAssistantRuntimeConfig()
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    resolved = dict(defaults)
    for _ in range(10):
        for key, value in resolved.items():
            if (
                isinstance(value, str)
                and "{{" in value
                and key
                in {
                    "homeassistant_" + k
                    for k in HomeAssistantRuntimeConfig.model_fields
                    if k
                    not in {
                        "security",
                        "python_security_environments",
                        "python_security_constraint_argv",
                        "python_security_constraint_args",
                    }
                }
            ):
                resolved[key] = env.from_string(value).render(**resolved)
    # Nested dependency defaults/precedence have their own exact role oracle.
    for key, value in cfg.model_dump(
        exclude={
            "uv",
            "security",
            "python_security_environments",
            "python_security_constraint_argv",
            "python_security_constraint_args",
        }
    ).items():
        expected = resolved["homeassistant_" + key]
        assert value == (tuple(expected) if isinstance(expected, list) else expected), key
    for name in ("homeassistant.service.j2", "matter-server.service.j2"):
        assert (fixture / name).read_bytes() == files("ops_deploy.services.homeassistant").joinpath(
            "templates", name
        ).read_bytes()


@pytest.mark.parametrize("key", ["site_path", "virtualenv_path", "matter_server_storage_path"])
@pytest.mark.parametrize("bad", ["/", "/srv/../etc", "/srv/ha\nExecStart=/bin/false"])
def test_dangerous_paths_rejected(key: str, bad: str) -> None:
    with pytest.raises(ValidationError):
        HomeAssistantRuntimeConfig.model_validate({key: bad})


def test_matter_original_guards() -> None:
    with pytest.raises(ValidationError, match="Matter package"):
        HomeAssistantRuntimeConfig(manage_matter_server=True, matter_server_package_spec="python-matter-server")
    with pytest.raises(ValidationError, match=r"Python 3\.12"):
        HomeAssistantRuntimeConfig(manage_matter_server=True, python_version="3.11.9")


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_actual_current_runtime_sources() -> None:
    fixture = Path(__file__).parent / "parity/homeassistant"
    source = json.loads((fixture / "runtime-source.json").read_text())
    for name, digest in source["files"].items():
        body = (Path(os.environ["OPS_LIBRARY_PATH"]) / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == digest, name


@pytest.mark.parametrize("path", ["/", "/etc/systemd/system/../../foreign.conf"])
def test_trust_allowlist_rejects_root_and_traversal(path: str) -> None:
    with pytest.raises(ValidationError, match="runtime paths"):
        HomeAssistantRuntimeConfig(uv_system_certs_allowed_dropins=(path,))


def test_trust_allowlist_keeps_exact_declared_paths() -> None:
    path = "/etc/systemd/system/homeassistant.service.d/reviewed.conf"
    assert HomeAssistantRuntimeConfig(uv_system_certs_allowed_dropins=(path,)).uv_system_certs_allowed_dropins == (
        path,
    )
