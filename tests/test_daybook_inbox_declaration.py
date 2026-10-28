"""Original Inbox declaration and template contract; no app/data invocation."""

from __future__ import annotations

import importlib
import json
import os
import plistlib
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretContent
from ops_deploy.services.daybook_voice_memo_inbox.config import DEFAULTS, PACKAGE, DaybookInboxConfig
from ops_deploy.services.daybook_voice_memo_inbox.render import SECRET_DEFAULTS, resources, role_values


def config(**values: Any) -> DaybookInboxConfig:
    return DaybookInboxConfig(
        **{
            "daybook_voice_memo_inbox_enabled": True,
            "daybook_voice_memo_inbox_service_user": "fixture",
            "daybook_voice_memo_inbox_repo_ref": "a" * 40,
            "daybook_voice_memo_inbox_repo_bundle_src": "/owned/source.bundle",
            "daybook_voice_memo_inbox_bucket": "owned-bucket",
            "daybook_voice_memo_inbox_s3_endpoint_url": "https://s3.example.test",
            **values,
        }
    )


def secrets() -> dict[str, str]:
    return dict.fromkeys(SECRET_DEFAULTS, "UNUSABLE-OWNED-CREDENTIAL")


def test_fresh_disabled_declaration_needs_no_secrets_or_source() -> None:
    cfg = DaybookInboxConfig()
    assert cfg.daybook_voice_memo_inbox_enabled is False
    assert resources(cfg, {}) == ()


def test_default_disabled_first_runtime_preserves_original_versions_and_policy() -> None:
    cfg = config()
    assert cfg.daybook_voice_memo_inbox_python_version == "3.14.7"
    assert cfg.daybook_voice_memo_inbox_launchd_enabled is False
    assert cfg.daybook_voice_memo_inbox_long_lane_enabled is False
    assert cfg.daybook_voice_memo_inbox_long_label_enabled is True
    assert cfg.daybook_voice_memo_inbox_model == "gpt-4o-mini-transcribe"
    assert cfg.daybook_voice_memo_inbox_source_dir.endswith("VoiceMemos.shared/Recordings")
    result = resources(cfg, secrets())
    assert len(result) == 4
    assert all(isinstance(row.content, SecretContent) for row in result)
    assert "UNUSABLE-OWNED-CREDENTIAL" not in repr(result)
    assert "daybook_voice_memo_inbox_s3_secret_access_key" not in cfg.model_dump()
    policy = json.loads(result[0].content.reveal())
    assert policy["database_name"] == "CloudRecordings.db"
    assert policy["long_lane_enabled"] is False
    short = plistlib.loads(result[2].content.reveal())
    assert short["StartInterval"] == 300
    assert short["RunAtLoad"] is True  # remains disabled until the separate managed gate
    assert short["ProgramArguments"][-3:] == ["voice-memos", "ingest", "--summary-only"]


def test_retired_long_label_does_not_render_the_removed_plist_or_disable_lane_policy() -> None:
    cfg = config(daybook_voice_memo_inbox_long_lane_enabled=True, daybook_voice_memo_inbox_long_label_enabled=False)
    result = resources(cfg, secrets())
    assert len(result) == 3
    assert cfg.daybook_voice_memo_inbox_long_plist_path not in {row.path for row in result}
    assert json.loads(result[0].content.reveal())["long_lane_enabled"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("service_home", "/Users/different"),
        ("service_group", "wheel"),
        ("system_group", "staff"),
        ("install_root", "/owned/replacement"),
        ("source_dir", "/owned/data"),
        ("repo_ref", "main"),
        ("python_version", "3.15.1"),
        ("python", "/usr/bin/python3"),
        ("uv_bin", "/owned/uv"),
        ("launchd_label", "other"),
        ("long_launchd_label", "other"),
        ("interval_seconds", 600),
        ("activation_phrase", "different"),
        ("launchd_enabled", True),
        ("launchd_enabled", "true"),
        ("max_audio_bytes", 16777217),
        ("max_duration_seconds", 0),
        ("max_duration_seconds", 181),
        ("min_stable_seconds", 119),
        ("request_timeout_seconds", 300),
        ("duration_tolerance_seconds", 2.0),
        ("long_max_duration_seconds", 180),
        ("long_max_audio_bytes", 26214400),
        ("long_realtime_factor", 4.1),
        ("long_queue_slack_seconds", 901),
        ("long_validation_timeout_seconds", 29),
        ("long_max_attempts", 11),
        ("long_queue_per_run", 6),
        ("long_min_gap_seconds", 430),
        ("voxhelm_endpoint", "http://other/v1"),
        ("bucket", "CHANGEME"),
        ("s3_endpoint_url", "file:///owned"),
        ("long_realtime_factor", float("nan")),
    ],
)
def test_original_fixed_paths_types_and_budget_guards(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        config(**{"daybook_voice_memo_inbox_" + field: value})


def test_long_admission_deadline_is_validated_even_while_lane_is_disabled() -> None:
    with pytest.raises(ValidationError, match="admission deadline"):
        config(
            daybook_voice_memo_inbox_long_max_duration_seconds=3600, daybook_voice_memo_inbox_long_realtime_factor=1.0
        )


def test_explicit_activation_phrase_remains_distinct_from_normal_disabled_install() -> None:
    cfg = config(
        daybook_voice_memo_inbox_launchd_enabled=True,
        daybook_voice_memo_inbox_activation_confirmation="BASELINE ALL CURRENT VOICE MEMOS AS HISTORICAL",
    )
    assert cfg.daybook_voice_memo_inbox_launchd_enabled is True


@pytest.mark.parametrize("case", ["missing", "placeholder", "unknown", "nul"])
def test_original_credential_boundary_refuses_invalid_input_without_body_repr(case: str) -> None:
    values = secrets()
    field_name = "daybook_voice_memo_inbox_voxhelm_token"
    if case == "missing":
        values.pop(field_name)
    elif case == "unknown":
        values["other"] = "UNUSABLE-OWNED"
    else:
        values[field_name] = "CHANGEME" if case == "placeholder" else "UNUSABLE\x00OWNED"
    with pytest.raises(ValueError, match="Inbox"):
        resources(config(), values)


def test_all_defaults_and_template_bytes_match_actual_original_role() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Paired original role oracle is run explicitly for qualification")
    import yaml
    from jinja2 import Environment, StrictUndefined

    role = Path(source) / "roles/daybook_voice_memo_inbox_deploy"
    original = yaml.safe_load((role / "defaults/main.yml").read_text())
    original.pop("ops_library_documentation_category")
    assert original == {**DEFAULTS, **SECRET_DEFAULTS}
    assert set(DaybookInboxConfig.model_fields) == set(DEFAULTS)
    templates = files(PACKAGE).joinpath("templates")
    assert {p.name for p in templates.iterdir()} == {p.name for p in (role / "templates").iterdir()}
    for path in (role / "templates").iterdir():
        assert templates.joinpath(path.name).read_bytes() == path.read_bytes()
    env = Environment(undefined=StrictUndefined, trim_blocks=True, keep_trailing_newline=True)
    env.filters.update(importlib.import_module("ansible.plugins.filter.core").FilterModule().filters())
    cfg = config()
    values = role_values(cfg, secrets())
    for row, template in zip(
        resources(cfg, secrets()),
        [
            "policy.json.j2",
            "credentials.json.j2",
            "voice-memo-inbox.launchd.plist.j2",
            "voice-memo-inbox-long.launchd.plist.j2",
        ],
        strict=True,
    ):
        assert row.content.reveal().decode() == env.from_string((role / "templates" / template).read_text()).render(
            values
        )
