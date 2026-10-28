"""Actual Ansible2.21 renders against library d88 (MinIO source unchanged from cf3)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import jinja2
import pytest
import yaml

from ops_deploy.services.minio import MinioConfig, MinioCredentials
from ops_deploy.services.minio.deploy import RESOURCE
from ops_deploy.services.minio.render import render

FIXTURES = Path(__file__).parent / "parity/minio"
SOURCE = json.loads((FIXTURES / "source.json").read_text())


@pytest.mark.parametrize("case", ["defaults", "custom-tls", "console-auth-off"])
@pytest.mark.parametrize("template", sorted(SOURCE["templates"]))
def test_actual_role_template_render(case: str, template: str) -> None:
    directory = FIXTURES / case
    cfg = MinioConfig.model_validate_json((directory / "config.json").read_text())
    credentials = MinioCredentials.model_validate_json((directory / "synthetic-inputs.json").read_text())
    variables = json.loads((directory / "vars.json").read_text())
    actual = render(template, cfg, credentials, variables["minio_console_basic_auth_password_hash"])
    assert actual == (directory / (template + ".rendered")).read_text()


@pytest.mark.parametrize("template", sorted(SOURCE["templates"]))
def test_vendored_template_source_is_exact(template: str) -> None:
    assert (
        hashlib.sha256(RESOURCE.joinpath("templates/" + template).read_bytes()).hexdigest()
        == SOURCE["templates"][template]
    )


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
@pytest.mark.parametrize("template", sorted(SOURCE["templates"]))
def test_actual_library_template_bytes(template: str) -> None:
    role = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles/minio_deploy"
    assert (role / "templates" / template).read_bytes() == RESOURCE.joinpath("templates/" + template).read_bytes()


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_actual_role_defaults_of_all_mapped_fields() -> None:
    role = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles/minio_deploy"
    defaults = yaml.safe_load((role / "defaults/main.yml").read_text())
    config = MinioConfig().model_dump(mode="json")
    for field, value in config.items():
        key = "minio_" + field
        if key not in defaults:
            continue  # Explicit additional IAM/fixture inputs, tested separately.
        original = defaults[key]
        if isinstance(original, str) and "{{" in original:
            original = jinja2.Template(original).render(**defaults)
        assert value == original, field
