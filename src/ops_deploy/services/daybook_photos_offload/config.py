"""Original protected-source/user-environment Photos offload role declaration."""

from __future__ import annotations

import json
import re
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any, Literal, Self

from jinja2 import StrictUndefined, UndefinedError
from jinja2.nativetypes import NativeEnvironment
from pydantic import Field, StrictBool, StrictInt, model_validator

from ops_deploy.base import RoleConfig

PACKAGE = "ops_deploy.services.daybook_photos_offload"
DEFAULTS: dict[str, Any] = json.loads(files(PACKAGE).joinpath("defaults.json").read_text())


def resolved_defaults(overrides: dict[str, Any]) -> dict[str, Any]:
    values = {**DEFAULTS, **overrides}
    pending = set(DEFAULTS) - set(overrides)
    env = NativeEnvironment(undefined=StrictUndefined)
    env.filters["dirname"] = lambda path: str(PurePosixPath(path).parent)
    for _ in range(len(pending) + 1):
        remaining = set()
        for key in sorted(pending):
            original = DEFAULTS[key]
            try:
                value = (
                    env.from_string(original).render(values)
                    if isinstance(original, str) and "{{" in original
                    else original
                )
            except UndefinedError:
                remaining.add(key)
                continue
            values[key] = value
            if "{{" in json.dumps(value):
                remaining.add(key)
        if not remaining:
            return values
        pending = remaining
    raise ValueError("Photos offload role defaults could not be resolved")


class CalendarEntry(RoleConfig):
    Hour: StrictInt = Field(ge=0, le=23)
    Minute: StrictInt = Field(ge=0, le=59)


class DaybookPhotosOffloadConfig(RoleConfig):
    daybook_photos_offload_enabled: StrictBool = Field(default=DEFAULTS["daybook_photos_offload_enabled"])
    daybook_photos_offload_launchd_enabled: StrictBool = Field(
        default=DEFAULTS["daybook_photos_offload_launchd_enabled"]
    )
    daybook_photos_offload_service_user: str = Field(default=DEFAULTS["daybook_photos_offload_service_user"])
    daybook_photos_offload_service_group: str = Field(default=DEFAULTS["daybook_photos_offload_service_group"])
    daybook_photos_offload_service_home: str = Field(default=DEFAULTS["daybook_photos_offload_service_home"])
    ansible_become_flags: Literal["-H -i"] = Field(default=DEFAULTS["ansible_become_flags"])
    daybook_photos_offload_repo_url: str = Field(default=DEFAULTS["daybook_photos_offload_repo_url"])
    daybook_photos_offload_checkout_path: str = Field(default=DEFAULTS["daybook_photos_offload_checkout_path"])
    daybook_photos_offload_checkout_attestation_path: str = Field(
        default=DEFAULTS["daybook_photos_offload_checkout_attestation_path"]
    )
    daybook_photos_offload_repo_bundle_src: str = Field(default=DEFAULTS["daybook_photos_offload_repo_bundle_src"])
    daybook_photos_offload_repo_bundle_path: str = Field(default=DEFAULTS["daybook_photos_offload_repo_bundle_path"])
    daybook_photos_offload_repo_ref: str = Field(default=DEFAULTS["daybook_photos_offload_repo_ref"])
    daybook_photos_offload_uv_bin: str = Field(default=DEFAULTS["daybook_photos_offload_uv_bin"])
    daybook_photos_offload_python_version: str = Field(default=DEFAULTS["daybook_photos_offload_python_version"])
    daybook_photos_offload_venv_path: str = Field(default=DEFAULTS["daybook_photos_offload_venv_path"])
    daybook_photos_offload_path: str = Field(default=DEFAULTS["daybook_photos_offload_path"])
    daybook_photos_offload_system_group: str = Field(default=DEFAULTS["daybook_photos_offload_system_group"])
    daybook_photos_offload_library_path: str = Field(default=DEFAULTS["daybook_photos_offload_library_path"])
    daybook_photos_offload_runtime_dir: str = Field(default=DEFAULTS["daybook_photos_offload_runtime_dir"])
    daybook_photos_offload_state_path: str = Field(default=DEFAULTS["daybook_photos_offload_state_path"])
    daybook_photos_offload_config_dir: str = Field(default=DEFAULTS["daybook_photos_offload_config_dir"])
    daybook_photos_offload_launcher_path: str = Field(default=DEFAULTS["daybook_photos_offload_launcher_path"])
    daybook_photos_offload_log_dir: str = Field(default=DEFAULTS["daybook_photos_offload_log_dir"])
    daybook_photos_offload_stdout_log: str = Field(default=DEFAULTS["daybook_photos_offload_stdout_log"])
    daybook_photos_offload_stderr_log: str = Field(default=DEFAULTS["daybook_photos_offload_stderr_log"])
    daybook_photos_offload_launchd_label: str = Field(default=DEFAULTS["daybook_photos_offload_launchd_label"])
    daybook_photos_offload_launchd_plist_path: str = Field(
        default=DEFAULTS["daybook_photos_offload_launchd_plist_path"]
    )
    daybook_photos_offload_launchd_manage_state: StrictBool = Field(
        default=DEFAULTS["daybook_photos_offload_launchd_manage_state"]
    )
    daybook_photos_offload_readiness_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_photos_offload_readiness_timeout_seconds"], ge=1, le=300
    )
    daybook_photos_offload_throttle_interval_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_photos_offload_throttle_interval_seconds"], ge=10
    )
    daybook_photos_offload_start_calendar: list[CalendarEntry] = Field(
        default=DEFAULTS["daybook_photos_offload_start_calendar"], min_length=1
    )

    @model_validator(mode="before")
    @classmethod
    def defaults(cls, value: Any) -> Any:
        return resolved_defaults(dict(value)) if isinstance(value, dict) else value

    @model_validator(mode="after")
    def original_contract(self) -> Self:
        if not self.daybook_photos_offload_enabled:
            return self
        data = self.model_dump()
        prefix = "daybook_photos_offload_"
        value = {key.removeprefix(prefix): item for key, item in data.items() if key.startswith(prefix)}
        for name in ("service_user", "service_group", "system_group"):
            if not value[name].strip() or value[name] == "CHANGEME":
                raise ValueError("Photos offload requires its original explicit account and groups")
        paths = (
            "service_home",
            "checkout_path",
            "checkout_attestation_path",
            "repo_bundle_path",
            "repo_bundle_src",
            "venv_path",
            "uv_bin",
            "library_path",
            "runtime_dir",
            "state_path",
            "config_dir",
            "launcher_path",
            "log_dir",
            "stdout_log",
            "stderr_log",
            "launchd_plist_path",
        )
        for name in paths:
            path = value[name]
            if not path.startswith("/") or "\x00" in path or any(part in {".", ".."} for part in path.split("/")):
                raise ValueError("Photos offload requires absolute non-traversing managed paths")
        home, checkout = PurePosixPath(value["service_home"]), PurePosixPath(value["checkout_path"])
        if (
            not str(home).startswith("/Users/")
            or checkout.parent.parent != PurePosixPath("/Library/Application Support/Daybook")
            or value["checkout_attestation_path"] != str(checkout.parent / "managed-v1")
            or value["repo_bundle_path"] != str(checkout.parent / "source.bundle")
            or value["repo_url"] != value["repo_bundle_path"]
            or value["venv_path"] != str(checkout / ".venv")
        ):
            raise ValueError("Photos offload must preserve its original protected checkout and local bundle layout")
        for name in ("library_path", "runtime_dir", "config_dir"):
            if not value[name].startswith(str(home) + "/"):
                raise ValueError("Photos offload paths must remain owner-local")
        for name, parent in (
            ("state_path", "runtime_dir"),
            ("launcher_path", "config_dir"),
            ("stdout_log", "log_dir"),
            ("stderr_log", "log_dir"),
        ):
            if not value[name].startswith(value[parent] + "/"):
                raise ValueError("Photos offload managed children must preserve their original parent")
        if (
            value["log_dir"] != value["runtime_dir"] + "/logs"
            or PurePosixPath(value["state_path"]).is_relative_to(PurePosixPath(value["library_path"]))
            or value["launchd_plist_path"] != str(home / "Library/LaunchAgents" / (value["launchd_label"] + ".plist"))
            or not value["launchd_label"].strip()
            or not value["launchd_manage_state"]
        ):
            raise ValueError("Photos offload requires the original external ledger and managed GUI launchd contract")
        if not re.fullmatch(r"[0-9a-f]{40}", value["repo_ref"]) or not value["python_version"].strip():
            raise ValueError("Photos offload needs its exact original revision and Python selector")
        return self
