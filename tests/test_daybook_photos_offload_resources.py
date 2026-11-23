"""Original Photos offload declaration/rendering; no Photos/library/app calls."""

from __future__ import annotations

import plistlib
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.daybook_photos_offload import DaybookPhotosOffloadConfig
from ops_deploy.services.daybook_photos_offload.render import resources


def config(**overrides: Any) -> DaybookPhotosOffloadConfig:
    return DaybookPhotosOffloadConfig(
        **{
            "daybook_photos_offload_service_user": "fixture",
            "daybook_photos_offload_repo_ref": "a" * 40,
            "daybook_photos_offload_repo_bundle_src": "/owned/controller/main.bundle",
            "daybook_photos_offload_repo_url": "/Library/Application Support/Daybook/photos-offload/source.bundle",
            **overrides,
        }
    )


def test_original_paths_and_disabled_install_are_distinct_from_activation() -> None:
    cfg = config()
    assert cfg.daybook_photos_offload_python_version == "3.14.10"
    assert cfg.ansible_become_flags == "-H -i"
    assert cfg.daybook_photos_offload_service_home == "/Users/fixture"
    assert cfg.daybook_photos_offload_checkout_attestation_path.endswith("/photos-offload/managed-v1")
    assert cfg.daybook_photos_offload_venv_path.endswith("/photos-offload/daybook/.venv")
    assert cfg.daybook_photos_offload_launchd_enabled is False
    assert cfg.daybook_photos_offload_launchd_manage_state is True
    rows = resources(cfg)
    assert [row.mode for row in rows] == [0o700, 0o644]
    assert all(row.owner == "fixture" and row.group == "staff" for row in rows)
    plist = plistlib.loads(rows[1].content.encode())
    assert plist["RunAtLoad"] is False
    assert plist["LimitLoadToSessionType"] == "Aqua"
    assert plist["StartCalendarInterval"] == [{"Hour": 8, "Minute": 10}, {"Hour": 20, "Minute": 10}]
    assert "--summary-only" in rows[0].content
    assert "offload-reconcile" in rows[0].content
    assert "PYTHONPATH=" in rows[0].content


def test_disabled_role_does_not_require_live_account_source_or_rendering() -> None:
    cfg = DaybookPhotosOffloadConfig(daybook_photos_offload_enabled=False)
    assert resources(cfg) == ()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("service_user", "CHANGEME"),
        ("repo_ref", "main"),
        ("repo_bundle_src", "relative"),
        ("repo_url", "https://github.com/ephes/daybook.git"),
        ("checkout_path", "/Users/fixture/daybook"),
        ("checkout_attestation_path", "/tmp/managed-v1"),
        ("venv_path", "/tmp/venv"),
        ("runtime_dir", "/tmp/owner-state"),
        ("config_dir", "/Users/fixture/../unsafe"),
        ("state_path", "/Users/fixture/Pictures/Photos Library.photoslibrary/ledger.json"),
        ("launcher_path", "/tmp/reconcile.sh"),
        ("log_dir", "/tmp/logs"),
        ("launchd_manage_state", False),
        ("launchd_enabled", "false"),
        ("readiness_timeout_seconds", 0),
        ("readiness_timeout_seconds", 301),
        ("throttle_interval_seconds", 9),
        ("start_calendar", []),
        ("start_calendar", [{"Hour": True, "Minute": 10}]),
        ("start_calendar", [{"Hour": 24, "Minute": 10}]),
        ("start_calendar", [{"Hour": 8, "Minute": 10, "Other": 1}]),
    ],
)
def test_original_closed_paths_account_schedule_and_source_contracts(key: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        config(**{"daybook_photos_offload_" + key: value})
