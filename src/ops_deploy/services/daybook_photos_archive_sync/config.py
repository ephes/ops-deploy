"""Original single-writer, owner-identity Nikon archive declaration."""

from __future__ import annotations

import json
import re
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any, Self

from jinja2 import StrictUndefined, UndefinedError
from jinja2.nativetypes import NativeEnvironment
from pydantic import Field, StrictBool, StrictInt, model_validator

from ops_deploy.base import RoleConfig

PACKAGE = "ops_deploy.services.daybook_photos_archive_sync"
DEFAULTS: dict[str, Any] = json.loads(files(PACKAGE).joinpath("defaults.json").read_text())


class DaybookPhotosArchiveSyncConfig(RoleConfig):
    inventory_hostname: str = "CHANGEME"
    daybook_photos_archive_sync_enabled: StrictBool = Field(default=DEFAULTS["daybook_photos_archive_sync_enabled"])
    daybook_photos_archive_sync_launchd_enabled: StrictBool = Field(
        default=DEFAULTS["daybook_photos_archive_sync_launchd_enabled"]
    )
    daybook_photos_archive_sync_service_user: str = Field(default=DEFAULTS["daybook_photos_archive_sync_service_user"])
    daybook_photos_archive_sync_service_group: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_service_group"]
    )
    daybook_photos_archive_sync_service_home: str = Field(default=DEFAULTS["daybook_photos_archive_sync_service_home"])
    daybook_photos_archive_sync_repo_ref: str = Field(default=DEFAULTS["daybook_photos_archive_sync_repo_ref"])
    daybook_photos_archive_sync_repo_bundle_src: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_repo_bundle_src"]
    )
    daybook_photos_archive_sync_install_root: str = Field(default=DEFAULTS["daybook_photos_archive_sync_install_root"])
    daybook_photos_archive_sync_repo_bundle_path: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_repo_bundle_path"]
    )
    daybook_photos_archive_sync_checkout_path: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_checkout_path"]
    )
    daybook_photos_archive_sync_venv_path: str = Field(default=DEFAULTS["daybook_photos_archive_sync_venv_path"])
    daybook_photos_archive_sync_uv_bin: str = Field(default=DEFAULTS["daybook_photos_archive_sync_uv_bin"])
    daybook_photos_archive_sync_timeout_bin: str = Field(default=DEFAULTS["daybook_photos_archive_sync_timeout_bin"])
    daybook_photos_archive_sync_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_photos_archive_sync_timeout_seconds"]
    )
    daybook_photos_archive_sync_photos_access_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_photos_archive_sync_photos_access_timeout_seconds"]
    )
    daybook_photos_archive_sync_python_version: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_python_version"]
    )
    daybook_photos_archive_sync_path: str = Field(default=DEFAULTS["daybook_photos_archive_sync_path"])
    daybook_photos_archive_sync_library_path: str = Field(default=DEFAULTS["daybook_photos_archive_sync_library_path"])
    daybook_photos_archive_sync_source_root: str = Field(default=DEFAULTS["daybook_photos_archive_sync_source_root"])
    daybook_photos_archive_sync_mount_point: str = Field(default=DEFAULTS["daybook_photos_archive_sync_mount_point"])
    daybook_photos_archive_sync_expected_smb_server: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_expected_smb_server"]
    )
    daybook_photos_archive_sync_expected_smb_share: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_expected_smb_share"]
    )
    daybook_photos_archive_sync_expected_writer_host: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_expected_writer_host"]
    )
    daybook_photos_archive_sync_runtime_dir: str = Field(default=DEFAULTS["daybook_photos_archive_sync_runtime_dir"])
    daybook_photos_archive_sync_state_path: str = Field(default=DEFAULTS["daybook_photos_archive_sync_state_path"])
    daybook_photos_archive_sync_folder_map_path: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_folder_map_path"]
    )
    daybook_photos_archive_sync_use_folder_map: StrictBool = Field(
        default=DEFAULTS["daybook_photos_archive_sync_use_folder_map"]
    )
    daybook_photos_archive_sync_log_dir: str = Field(default=DEFAULTS["daybook_photos_archive_sync_log_dir"])
    daybook_photos_archive_sync_stdout_log: str = Field(default=DEFAULTS["daybook_photos_archive_sync_stdout_log"])
    daybook_photos_archive_sync_stderr_log: str = Field(default=DEFAULTS["daybook_photos_archive_sync_stderr_log"])
    daybook_photos_archive_sync_config_dir: str = Field(default=DEFAULTS["daybook_photos_archive_sync_config_dir"])
    daybook_photos_archive_sync_launcher_path: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_launcher_path"]
    )
    daybook_photos_archive_sync_launchd_label: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_launchd_label"]
    )
    daybook_photos_archive_sync_launchd_plist_path: str = Field(
        default=DEFAULTS["daybook_photos_archive_sync_launchd_plist_path"]
    )
    daybook_photos_archive_sync_interval_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_photos_archive_sync_interval_seconds"]
    )

    @model_validator(mode="before")
    @classmethod
    def original_defaults(cls, supplied: Any) -> Any:
        if not isinstance(supplied, dict):
            return supplied
        values = {**DEFAULTS, **supplied}
        pending = set(DEFAULTS) - set(supplied)
        environment = NativeEnvironment(undefined=StrictUndefined)
        for _ in range(len(DEFAULTS) + 1):
            remaining = set()
            for key in pending:
                try:
                    original = DEFAULTS[key]
                    values[key] = (
                        environment.from_string(original).render(values) if isinstance(original, str) else original
                    )
                    if any(marker in json.dumps(values[key]) for marker in ("{{", "{%", "{#")):
                        remaining.add(key)
                except UndefinedError:
                    remaining.add(key)
            if not remaining:
                return values
            pending = remaining
        raise ValueError("Archive synchronization defaults could not be resolved")

    @model_validator(mode="after")
    def original_writer_layout(self) -> Self:
        if not self.daybook_photos_archive_sync_enabled:
            return self
        prefix = "daybook_photos_archive_sync_"
        values = {key.removeprefix(prefix): value for key, value in self.model_dump().items() if key.startswith(prefix)}
        if (
            values["service_user"] in {"CHANGEME", "root"}
            or not re.fullmatch(r"[a-z_][a-z0-9_-]*", values["service_user"])
            or not values["service_home"].startswith("/Users/")
            or not re.fullmatch(r"[0-9a-f]{40}", values["repo_ref"])
            or not values["repo_bundle_src"].startswith("/")
            or values["expected_smb_server"] in {"", "CHANGEME"}
            or not values["expected_smb_share"]
            or values["expected_writer_host"] in {"", "CHANGEME"}
            or values["expected_writer_host"].lower() != self.inventory_hostname.lower()
        ):
            raise ValueError("Archive synchronization requires its original owner, bundle and single writer identity")
        paths = (
            "service_home",
            "install_root",
            "repo_bundle_path",
            "checkout_path",
            "runtime_dir",
            "venv_path",
            "log_dir",
            "stdout_log",
            "stderr_log",
            "state_path",
            "folder_map_path",
            "config_dir",
            "launcher_path",
            "launchd_plist_path",
            "library_path",
            "source_root",
            "mount_point",
        )
        for name in paths:
            text = values[name]
            if (
                not PurePosixPath(text).is_absolute()
                or any(part in {".", ".."} for part in text.split("/"))
                or any(char in text for char in "\0\r\n")
            ):
                raise ValueError("Archive synchronization paths must be original absolute paths without traversal")
        under_home = ("checkout_path", "install_root", "runtime_dir", "config_dir", "library_path", "source_root")
        if any(not values[name].startswith(values["service_home"] + "/") for name in under_home):
            raise ValueError("Archive synchronization requires owner-local deployment and source declarations")
        nested = {
            "repo_bundle_path": "install_root",
            "log_dir": "runtime_dir",
            "stdout_log": "log_dir",
            "stderr_log": "log_dir",
            "venv_path": "checkout_path",
            "launcher_path": "config_dir",
            "state_path": "runtime_dir",
            "folder_map_path": "runtime_dir",
        }
        if any(not values[leaf].startswith(values[parent] + "/") for leaf, parent in nested.items()):
            raise ValueError("Archive synchronization requires its original nested private resources")
        if (
            not values["mount_point"].startswith("/Volumes/")
            or values["launchd_plist_path"]
            != values["service_home"] + "/Library/LaunchAgents/" + values["launchd_label"] + ".plist"
            or values["interval_seconds"] < 3600
            or values["timeout_seconds"] <= 0
            or values["photos_access_timeout_seconds"] <= 0
            or values["photos_access_timeout_seconds"] + 5 + values["timeout_seconds"] + 60
            >= values["interval_seconds"]
        ):
            raise ValueError("Archive synchronization requires its original label, volume and bounded schedule")
        return self
