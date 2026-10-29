"""Original archive declarations and dormant templates; no media or host work."""

from __future__ import annotations

import os
import plistlib
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.services.daybook_photos_archive_sync import DaybookPhotosArchiveSyncConfig
from ops_deploy.services.daybook_photos_archive_sync.config import DEFAULTS, PACKAGE
from ops_deploy.services.daybook_photos_archive_sync.render import render_resources


def config(**overrides: Any) -> DaybookPhotosArchiveSyncConfig:
    return DaybookPhotosArchiveSyncConfig(
        **{
            "inventory_hostname": "owned-writer",
            "daybook_photos_archive_sync_enabled": True,
            "daybook_photos_archive_sync_service_user": "fixture",
            "daybook_photos_archive_sync_repo_ref": "a" * 40,
            "daybook_photos_archive_sync_repo_bundle_src": "/owned/controller/main.bundle",
            "daybook_photos_archive_sync_expected_smb_server": "nas.example.invalid",
            "daybook_photos_archive_sync_expected_writer_host": "owned-writer",
            **overrides,
        }
    )


def test_inert_default_and_original_disabled_schedule() -> None:
    assert DaybookPhotosArchiveSyncConfig().daybook_photos_archive_sync_enabled is False
    cfg = config()
    script, plist = render_resources(cfg)
    parsed = plistlib.loads(str(plist["content"]).encode())
    # Original archive plist relies on its persistent launchctl disabled
    # override. It has no Disabled key, unlike the separate attention pilot.
    assert "Disabled" not in parsed
    assert parsed["RunAtLoad"] is True
    assert parsed["StartInterval"] == 7200
    assert parsed["ProgramArguments"] == [cfg.daybook_photos_archive_sync_launcher_path]
    assert script["mode"] == 0o700
    assert plist["mode"] == 0o600
    assert "--execute" in str(script["content"])
    assert "/database/Photos.sqlite" in str(script["content"])
    # This is dormant generated code; construction does not execute its SQL
    # preflight or its mutating archival application command.
    assert cfg.daybook_photos_archive_sync_launchd_enabled is False


@pytest.mark.parametrize(
    "override",
    [
        {"daybook_photos_archive_sync_expected_writer_host": "other"},
        {"inventory_hostname": "other"},
        {"daybook_photos_archive_sync_service_user": "root"},
        {"daybook_photos_archive_sync_repo_ref": "main"},
        {"daybook_photos_archive_sync_runtime_dir": "/outside"},
        {"daybook_photos_archive_sync_source_root": "/outside"},
        {"daybook_photos_archive_sync_stdout_log": "/outside"},
        {"daybook_photos_archive_sync_state_path": "/outside"},
        {"daybook_photos_archive_sync_mount_point": "/outside"},
        {"daybook_photos_archive_sync_checkout_path": "/Users/fixture/../outside"},
        {"daybook_photos_archive_sync_interval_seconds": 300},
        {"daybook_photos_archive_sync_timeout_seconds": 7200},
        {"daybook_photos_archive_sync_launchd_enabled": "false"},
    ],
)
def test_original_single_writer_paths_and_timeout_budget(override: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**override)


def test_paired_all35_defaults_and_both_template_bytes_are_original() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Paired original role oracle is run explicitly for qualification")
    role = Path(source) / "roles/daybook_photos_archive_sync_deploy"
    original = yaml.safe_load((role / "defaults/main.yml").read_text())
    original.pop("ops_library_documentation_category")
    assert original == DEFAULTS
    assert len(DEFAULTS) == 35
    for name in ("archive-sync.sh.j2", "archive-sync.plist.j2"):
        assert (role / "templates" / name).read_bytes() == files(PACKAGE).joinpath("templates/" + name).read_bytes()
