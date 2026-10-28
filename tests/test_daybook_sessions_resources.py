"""Exact original role resources with retired timers and separate activation."""

from __future__ import annotations

import hashlib
import importlib
import os
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretContent
from ops_deploy.services.daybook_sessions import DaybookSessionsConfig
from ops_deploy.services.daybook_sessions.config import DEFAULTS, PACKAGE
from ops_deploy.services.daybook_sessions.render import SECRET_DEFAULTS, render_template, resources, role_values


def config(**values: Any) -> DaybookSessionsConfig:
    return DaybookSessionsConfig(
        **{
            "daybook_sessions_service_user": "fixture",
            "daybook_sessions_repo_ref": "a" * 40,
            "daybook_sessions_aws_endpoint_url_s3": "https://s3.example.test",
            **values,
        }
    )


def secrets() -> dict[str, str]:
    return {
        "daybook_sessions_aws_access_key_id": "fixture-access",
        "daybook_sessions_aws_secret_access_key": "fixture-secret",
        "daybook_archive_token": "fixture-archive",
        "daybook_weeknotes_cast_token": "fixture-cast",
        "daybook_weeknotes_home_token": "fixture-home",
        "daybook_weeknotes_public_repositories_json": '{"fixture":"https://example.test/repo.git"}',
        "daybook_weeknotes_confidential_names_json": '["fixture-private"]',
    }


def studio(**values: Any) -> DaybookSessionsConfig:
    return config(
        **{
            "daybook_sessions_repo_update": False,
            "daybook_sessions_launchd_enabled": False,
            "daybook_archive_quote_classifier_enabled": True,
            "daybook_archive_quote_classifier_launchd_enabled": False,
            "daybook_archive_quote_classifier_cmd": "fixture-model --exact-original-profile",
            "daybook_archive_url": "https://archive.example.test",
            "daybook_quotes_unused_path": "s3://fixture/unused.json",
            "daybook_quotes_used_path": "s3://fixture/used.json",
            "daybook_weeknotes_reconcile_enabled": True,
            "daybook_weeknotes_reconcile_launchd_retired": True,
            "daybook_weeknotes_path": "s3://fixture/weeknotes",
            "daybook_weeknotes_cast_base_url": "https://cast.example.test",
            "daybook_weeknotes_home_url": "https://notes.example.test",
            "daybook_weeknotes_public_blog_id": "1",
            "daybook_weeknotes_family_blog_id": "2",
            **values,
        }
    )


def test_default_disabled_declaration_does_not_require_secrets_or_render_resources() -> None:
    assert resources(DaybookSessionsConfig(daybook_sessions_enabled=False), {}) == ()


def test_default_resolves_original_paths_python_and_separate_auth() -> None:
    cfg = config()
    assert cfg.daybook_sessions_service_home == "/Users/fixture"
    assert cfg.daybook_sessions_checkout_path == "/Users/fixture/.local/share/daybook/sessions/daybook"
    assert cfg.daybook_sessions_python_version == "3.14.7"
    assert cfg.daybook_sessions_uv_sync_args == ["sync", "--frozen", "--no-dev", "--python", "3.14.7"]
    assert cfg.daybook_weeknotes_reconcile_pi_auth_rotate is False
    assert (
        cfg.daybook_weeknotes_reconcile_pi_auth_source == "/Users/fixture/.config/daybook-weeknotes-reconcile/auth.json"
    )
    assert cfg.daybook_weeknotes_reconcile_pi_agent_dir == "/Users/fixture/.daybook/weeknotes-reconcile/pi-agent"


def test_retired_timers_keep_original_component_configuration_without_activation() -> None:
    cfg = studio()
    result = resources(cfg, secrets())
    assert not any(resource.path.endswith(".plist") for resource in result)
    assert cfg.daybook_archive_quote_classifier_cmd == "fixture-model --exact-original-profile"
    assert cfg.daybook_sessions_launcher_path in {r.path for r in result}
    assert cfg.daybook_archive_quote_classifier_launcher_path in {r.path for r in result}
    assert cfg.daybook_weeknotes_reconcile_launcher_path in {r.path for r in result}
    for resource in result:
        if resource.path.endswith((".env", ".sha256")):
            assert isinstance(resource.content, SecretContent)
    assert "fixture-secret" not in repr(result)
    assert "fixture-private" not in repr(result)


def test_existing_identity_epoch_cannot_be_removed_by_unverified_render() -> None:
    cfg = studio(
        daybook_weeknotes_post_identity_epoch="monday-after-v1", daybook_weeknotes_identity_required_repo_ref="a" * 40
    )
    with pytest.raises(ValueError, match="proof"):
        resources(cfg, secrets())
    rendered = resources(cfg, secrets(), identity_verified=True)
    env = next(r for r in rendered if r.path == cfg.daybook_weeknotes_reconcile_env_file)
    assert isinstance(env.content, SecretContent)
    assert b"DAYBOOK_WEEKNOTES_POST_IDENTITY_EPOCH=monday-after-v1" in env.content.reveal()


def test_original_managed_checksum_guard_is_sha256_and_stays_secret_wrapped() -> None:
    cfg = studio()
    rendered = resources(cfg, secrets())
    env = next(r for r in rendered if r.path == cfg.daybook_weeknotes_reconcile_env_file)
    checksum = next(r for r in rendered if r.path == cfg.daybook_weeknotes_reconcile_env_checksum_file)
    assert isinstance(env.content, SecretContent)
    assert isinstance(checksum.content, SecretContent)
    assert (
        checksum.content.reveal()
        == (
            hashlib.sha256(env.content.reveal()).hexdigest() + "  " + cfg.daybook_weeknotes_reconcile_env_file + "\n"
        ).encode()
    )
    assert hashlib.sha256(env.content.reveal()).hexdigest() not in repr(rendered)


@pytest.mark.parametrize(
    "overrides",
    [
        {"daybook_sessions_repo_ref": "main"},
        {"daybook_sessions_service_user": "CHANGEME"},
        {"daybook_sessions_repo_url": "https://user:private@example.test/daybook.git"},
        {"daybook_sessions_launchd_enabled": "false"},
        {"daybook_sessions_config_dir": "/tmp/../outside"},
        {"daybook_archive_quote_classifier_start_calendar": [{"Hour": True, "Minute": 20}]},
    ],
)
def test_declaration_refuses_bad_source_paths_types_and_calendar(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"daybook_weeknotes_reconcile_launchd_enabled": True},
        {"daybook_sessions_launchd_scope": "user"},
        {"daybook_weeknotes_reconcile_pi_auth_source": "/Users/fixture/.pi/auth.json"},
        {"daybook_weeknotes_reconcile_state_path": "/Users/fixture/.daybook/another/state.json"},
        {"daybook_weeknotes_reconcile_launchd_plist_path": "/tmp/another.plist"},
        {"daybook_weeknotes_reconcile_start_calendar": [{"Hour": 7, "Minute": 41}]},
        {
            "daybook_weeknotes_post_identity_epoch": "monday-after-v1",
            "daybook_weeknotes_identity_required_repo_ref": "b" * 40,
        },
    ],
)
def test_original_weeknotes_control_identity_and_disabled_install_guards(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        studio(**overrides)


def test_malformed_or_missing_private_metadata_never_enters_error_text() -> None:
    for values in (
        {},
        {**secrets(), "daybook_weeknotes_confidential_names_json": "PRIVATE-NOT-JSON"},
        {**secrets(), "daybook_weeknotes_public_repositories_json": "[]"},
    ):
        with pytest.raises(ValueError, match=r"credentials|metadata") as error:
            resources(studio(), values)
        assert "PRIVATE-NOT-JSON" not in str(error.value)


def test_entire_defaults_and_template_sets_are_exact_actual_role_oracles() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Paired original role oracle is run explicitly for qualification")
    import jinja2
    import yaml

    role = Path(source) / "roles/daybook_sessions_deploy"
    assert yaml.safe_load((role / "defaults/main.yml").read_text()) == {**DEFAULTS, **SECRET_DEFAULTS}
    tasks = yaml.safe_load((role / "tasks/weeknotes_reconcile.yml").read_text())
    checksum_task = next(
        t["ansible.builtin.stat"] for t in tasks if t.get("register") == "daybook_weeknotes_reconcile_env_metadata"
    )
    assert checksum_task["checksum_algorithm"] == "sha256"
    assert set(DEFAULTS).isdisjoint(SECRET_DEFAULTS)
    assert set(DaybookSessionsConfig.model_fields) == set(DEFAULTS)
    packaged = files(PACKAGE).joinpath("templates")
    templates = sorted((role / "templates").glob("*.j2"))
    assert {p.name for p in templates} == {p.name for p in packaged.iterdir()}
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(role / "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters.update(importlib.import_module("ansible.plugins.filter.core").FilterModule().filters())
    for cfg in (config(), studio()):
        values = role_values(cfg, secrets())
        for path in templates:
            assert packaged.joinpath(path.name).read_bytes() == path.read_bytes()
            assert render_template(path.name, values) == env.get_template(path.name).render(values)
