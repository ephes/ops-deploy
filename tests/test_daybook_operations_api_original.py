"""Paired original Ansible validation/rendering with owned synthetic pins."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.services.daybook_operations_api.render import context, render_config, render_route, render_unit
from tests.test_daybook_operations_api import config, pins


def original() -> tuple[Path, Any]:
    library = os.environ.get("OPS_LIBRARY_PATH")
    if not library:
        pytest.skip("paired original-role oracle requires OPS_LIBRARY_PATH and test-interpreter ansible-core")
    template = importlib.import_module("ansible.template")
    return Path(library) / "roles/daybook_operations_api_deploy", template


def test_original_templates_are_actual_templar_byte_equal() -> None:
    role, template = original()
    cfg, private = config(), pins()
    values = context(cfg, private)
    protected = render_config(cfg, private)
    # The actual Ansible template action sets escape_backslashes=False.
    # Templar default=True is for inline play values and changes shell escaping.
    for name, content in protected.items():
        shell = name == "environment.shell"
        path = role / "templates" / (("environment" if shell else name) + ".j2")
        variables = values | {"task_shell_environment": shell}
        rendered = template.Templar(variables=variables).template(
            template.trust_as_template(path.read_text()), escape_backslashes=False
        )
        assert rendered.encode() == content.reveal()
    for kind in ("api", "reconcile"):
        rendered = template.Templar(variables=values | {"item": kind}).template(
            template.trust_as_template((role / "templates/service.j2").read_text()), escape_backslashes=False
        )
        assert rendered == render_unit(cfg, kind)
    route = template.Templar(variables=values).template(
        template.trust_as_template((role / "templates/traefik.yml.j2").read_text()), escape_backslashes=False
    )
    assert route == render_route(cfg)


@pytest.mark.parametrize("invalid", [False, True])
def test_actual_original_role_validation_and_schema(invalid: bool) -> None:
    role, template = original()
    variables = context(config(), pins()) | {"ansible_facts": {"system": "Linux"}}
    variables["daybook_operations_api_source_path"] = "/owned/source"
    tasks = {task["name"]: task for task in yaml.safe_load((role / "tasks/main.yml").read_text())}
    if invalid:
        variables["daybook_operations_api_capacity_warn_utilization"] = 0.99
    templar = template.Templar(variables=variables)
    valid = all(
        templar.evaluate_conditional(template.trust_as_template(expression))
        for expression in tasks["Validate operations service configuration"]["ansible.builtin.assert"]["that"]
    )
    assert valid is not invalid
    variables["item"] = 0
    if invalid:
        variables["daybook_operations_api_profiles"][0]["schema"] = True
    templar = template.Templar(variables=variables)
    valid = all(
        templar.evaluate_conditional(template.trust_as_template(expression))
        for expression in tasks["Validate profile shape"]["ansible.builtin.assert"]["that"]
    )
    assert valid is not invalid
