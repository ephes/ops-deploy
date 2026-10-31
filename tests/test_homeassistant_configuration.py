"""Exact original ownership and regex contracts; synthetic bodies only."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.services.homeassistant.configuration import (
    LEGACY_MET,
    OBSOLETE,
    ConfigurationPolicy,
    configuration_edits,
    include_content,
    secrets_content,
)

MET = "# Weather (you can configure your preferred weather provider)\nweather:\n  - platform: met\n    name: Home\n\n"
DISCOVERY = "# Discovery\ndiscovery:\n  ignore:\n    - sonos\n    - samsung_tv\n\n"
MONITOR = (
    "# System monitor\nsystem_monitor:\n  process:\n    - python3\n  resources:\n"
    "    - type: disk_use_percent\n      arg: /\n    - type: memory_free\n"
    "    - type: memory_use_percent\n    - type: processor_use\n"
    "    - type: processor_temperature\n    - type: last_boot\n\n"
)
USER = "# user document\ncustom: !include custom.yaml\nquoted: 'keep # exact'\n"


def test_exact_library_patterns() -> None:
    fixture = Path(__file__).parent / "parity/homeassistant"
    source = json.loads((fixture / "configuration-source.json").read_text())
    body = (fixture / "configuration.yml").read_bytes()
    assert hashlib.sha256(body).hexdigest() == source["sha256"]
    tasks = yaml.safe_load(body)
    met = next(task for task in tasks if task["name"] == "Remove legacy MET weather YAML platform")
    obsolete = next(task for task in tasks if task["name"] == "Remove obsolete role-generated YAML integration blocks")
    assert met["ansible.builtin.replace"]["regexp"] == LEGACY_MET
    assert tuple(obsolete["loop"]) == OBSOLETE


@pytest.mark.parametrize(("manage", "overwrite", "remove"), tuple(itertools.product((False, True), repeat=3)))
@pytest.mark.parametrize("existing", [None, "", USER, USER + MET + MONITOR + DISCOVERY])
def test_original_task_order_and_flags(manage: bool, overwrite: bool, remove: bool, existing: str | None) -> None:
    policy = ConfigurationPolicy(
        manage_configuration=manage, overwrite_config=overwrite, remove_legacy_met_weather_yaml=remove
    )
    rendered = "# rendered\n" + MET + DISCOVERY
    body = existing
    expected: list[tuple[str, str, bool]] = []
    if manage:
        if (overwrite or existing is None) and rendered != body:
            body = rendered
            expected.append(("template", body, False))
        if existing is not None:
            assert body is not None
            for pattern in ([LEGACY_MET] if remove else []) + list(OBSOLETE):
                updated, count = re.subn(pattern, "", body, flags=re.MULTILINE)
                if count and body != updated:
                    body = updated
                    expected.append(("replace", body, True))
    actual = configuration_edits(existing, rendered, policy)
    assert [(edit.operation, edit.content, edit.restart_on_change) for edit in actual] == expected
    assert all(edit.backup for edit in actual)
    assert all(USER not in repr(edit) for edit in actual)


@pytest.mark.parametrize("block", [MET, MONITOR, DISCOVERY])
def test_customized_near_match_is_untouched(block: str) -> None:
    custom = block.replace("# ", "# User ", 1)
    policy = ConfigurationPolicy(manage_configuration=True, remove_legacy_met_weather_yaml=True)
    assert configuration_edits(USER + custom, "replacement", policy) == ()


def test_cleanup_preserves_unrelated_bytes_and_repeat_is_empty() -> None:
    policy = ConfigurationPolicy(manage_configuration=True, remove_legacy_met_weather_yaml=True)
    edits = configuration_edits(USER + MET + MONITOR + DISCOVERY, "ignored", policy)
    assert len(edits) == 3
    assert edits[-1].content == USER
    assert configuration_edits(edits[-1].content, "ignored", policy) == ()


def test_new_file_not_eligible_for_preexisting_cleanup_until_next_call() -> None:
    policy = ConfigurationPolicy(manage_configuration=True, remove_legacy_met_weather_yaml=True)
    edits = configuration_edits(None, USER + MET, policy)
    assert len(edits) == 1
    assert edits[0].operation == "template"
    assert edits[0].content == USER + MET
    assert configuration_edits(USER + MET, "unused", policy)[0].content == USER


@pytest.mark.parametrize(("manage", "overwrite"), tuple(itertools.product((False, True), repeat=2)))
@pytest.mark.parametrize("existing", [None, "", USER, "rendered"])
def test_include_and_secret_guards(manage: bool, overwrite: bool, existing: str | None) -> None:
    policy = ConfigurationPolicy(manage_includes=manage, manage_secrets=manage, overwrite_config=overwrite)
    assert include_content(existing, "rendered", policy) == (
        "rendered" if manage and (overwrite or existing is None) and existing != "rendered" else None
    )
    assert secrets_content(existing, "rendered", policy) == ("rendered" if manage and existing != "rendered" else None)


@pytest.mark.parametrize("value", ["false", "true", 0, 1, None])
def test_policy_rejects_ambiguous_untyped_flags(value: object) -> None:
    with pytest.raises(ValidationError):
        ConfigurationPolicy.model_validate({"overwrite_config": value})


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_actual_current_library_matches_bound_original() -> None:
    fixture = Path(__file__).parent / "parity/homeassistant"
    source = json.loads((fixture / "configuration-source.json").read_text())
    body = (Path(os.environ["OPS_LIBRARY_PATH"]) / source["path"]).read_bytes()
    assert body == (fixture / "configuration.yml").read_bytes()
