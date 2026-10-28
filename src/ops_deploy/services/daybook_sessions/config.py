"""Original Sessions/Archive/Weeknotes role declaration; credentials stay separate."""

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
from ops_deploy.core.git_source import GitSource

PACKAGE = "ops_deploy.services.daybook_sessions"
DEFAULTS: dict[str, Any] = json.loads(files(PACKAGE).joinpath("defaults.json").read_text())


def resolved_defaults(overrides: dict[str, Any]) -> dict[str, Any]:
    values = {**DEFAULTS, **overrides}
    pending = set(DEFAULTS) - set(overrides)
    env = NativeEnvironment(undefined=StrictUndefined)
    env.filters.update(dirname=lambda s: str(PurePosixPath(s).parent), bool=bool, ternary=lambda c, y, n: y if c else n)

    def render(value: Any) -> Any:
        if isinstance(value, str) and "{{" in value:
            return env.from_string(value).render(values)
        if isinstance(value, list):
            return [render(item) for item in value]
        if isinstance(value, dict):
            return {k: render(v) for k, v in value.items()}
        return value

    for _ in range(len(pending) + 1):
        remaining = set()
        for key in sorted(pending):
            try:
                value = render(DEFAULTS[key])
            except UndefinedError:
                remaining.add(key)
                continue
            values[key] = value
            if "{{" in json.dumps(value):
                remaining.add(key)
        if not remaining:
            return values
        pending = remaining
    raise ValueError("Sessions role default references could not be resolved")


class CalendarEntry(RoleConfig):
    Hour: StrictInt = Field(ge=0, le=23)
    Minute: StrictInt = Field(ge=0, le=59)


class DaybookSessionsConfig(RoleConfig):
    # Original names let private host overrides retain their existing meaning.
    daybook_sessions_enabled: StrictBool = Field(default=DEFAULTS["daybook_sessions_enabled"])
    daybook_sessions_service_user: str = Field(default=DEFAULTS["daybook_sessions_service_user"])
    daybook_sessions_service_group: str = Field(default=DEFAULTS["daybook_sessions_service_group"])
    daybook_sessions_service_home: str = Field(default=DEFAULTS["daybook_sessions_service_home"])
    daybook_sessions_repo_url: str = Field(default=DEFAULTS["daybook_sessions_repo_url"])
    daybook_sessions_repo_ref: str = Field(default=DEFAULTS["daybook_sessions_repo_ref"])
    daybook_sessions_checkout_path: str = Field(default=DEFAULTS["daybook_sessions_checkout_path"])
    daybook_sessions_checkout_force: StrictBool = Field(default=DEFAULTS["daybook_sessions_checkout_force"])
    daybook_sessions_repo_update: StrictBool = Field(default=DEFAULTS["daybook_sessions_repo_update"])
    daybook_sessions_repo_bundle_src: str = Field(default=DEFAULTS["daybook_sessions_repo_bundle_src"])
    daybook_sessions_repo_bundle_path: str = Field(default=DEFAULTS["daybook_sessions_repo_bundle_path"])
    daybook_sessions_config_dir: str = Field(default=DEFAULTS["daybook_sessions_config_dir"])
    daybook_sessions_env_file: str = Field(default=DEFAULTS["daybook_sessions_env_file"])
    daybook_sessions_launcher_path: str = Field(default=DEFAULTS["daybook_sessions_launcher_path"])
    daybook_sessions_log_dir: str = Field(default=DEFAULTS["daybook_sessions_log_dir"])
    daybook_sessions_stdout_log: str = Field(default=DEFAULTS["daybook_sessions_stdout_log"])
    daybook_sessions_stderr_log: str = Field(default=DEFAULTS["daybook_sessions_stderr_log"])
    daybook_sessions_state_path: str = Field(default=DEFAULTS["daybook_sessions_state_path"])
    daybook_sessions_uv_install_dir: str = Field(default=DEFAULTS["daybook_sessions_uv_install_dir"])
    daybook_sessions_uv_bin: str = Field(default=DEFAULTS["daybook_sessions_uv_bin"])
    daybook_sessions_python_version: str = Field(default=DEFAULTS["daybook_sessions_python_version"])
    daybook_sessions_uv_sync_args: list[str] = Field(default=DEFAULTS["daybook_sessions_uv_sync_args"])
    daybook_sessions_launchd_label: str = Field(default=DEFAULTS["daybook_sessions_launchd_label"])
    daybook_sessions_launchd_scope: Literal["system", "user"] = Field(
        default=DEFAULTS["daybook_sessions_launchd_scope"]
    )
    daybook_sessions_launchd_plist_path: str = Field(default=DEFAULTS["daybook_sessions_launchd_plist_path"])
    daybook_sessions_launchd_manage_state: StrictBool = Field(default=DEFAULTS["daybook_sessions_launchd_manage_state"])
    daybook_sessions_launchd_enabled: StrictBool = Field(default=DEFAULTS["daybook_sessions_launchd_enabled"])
    daybook_sessions_launchd_start_service: StrictBool = Field(
        default=DEFAULTS["daybook_sessions_launchd_start_service"]
    )
    daybook_sessions_launchd_run_at_load: StrictBool = Field(default=DEFAULTS["daybook_sessions_launchd_run_at_load"])
    daybook_sessions_schedule_interval_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_sessions_schedule_interval_seconds"]
    )
    daybook_sessions_launchd_path: str = Field(default=DEFAULTS["daybook_sessions_launchd_path"])
    daybook_archive_quote_classifier_enabled: StrictBool = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_enabled"]
    )
    daybook_archive_quote_classifier_launchd_enabled: StrictBool = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_launchd_enabled"]
    )
    daybook_archive_quote_classifier_launchd_label: str = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_launchd_label"]
    )
    daybook_archive_quote_classifier_launchd_plist_path: str = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_launchd_plist_path"]
    )
    daybook_archive_quote_classifier_launcher_path: str = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_launcher_path"]
    )
    daybook_archive_quote_classifier_env_file: str = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_env_file"]
    )
    daybook_archive_quote_classifier_stdout_log: str = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_stdout_log"]
    )
    daybook_archive_quote_classifier_stderr_log: str = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_stderr_log"]
    )
    daybook_archive_quote_classifier_run_at_load: StrictBool = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_run_at_load"]
    )
    daybook_archive_quote_classifier_throttle_interval_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_throttle_interval_seconds"]
    )
    daybook_archive_quote_classifier_start_calendar: list[CalendarEntry] = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_start_calendar"]
    )
    daybook_archive_quote_classifier_since_days: StrictInt = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_since_days"]
    )
    daybook_archive_quote_classifier_limit: StrictInt = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_limit"]
    )
    daybook_archive_quote_classifier_state: str = Field(default=DEFAULTS["daybook_archive_quote_classifier_state"])
    daybook_archive_quote_classifier_cmd: str = Field(default=DEFAULTS["daybook_archive_quote_classifier_cmd"])
    daybook_archive_quote_classifier_probe_enabled: StrictBool = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_probe_enabled"]
    )
    daybook_archive_quote_classifier_probe_prompt: str = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_probe_prompt"]
    )
    daybook_archive_quote_classifier_probe_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_archive_quote_classifier_probe_timeout_seconds"]
    )
    daybook_archive_url: str = Field(default=DEFAULTS["daybook_archive_url"])
    daybook_quotes_enabled: StrictBool = Field(default=DEFAULTS["daybook_quotes_enabled"])
    daybook_quotes_unused_path: str = Field(default=DEFAULTS["daybook_quotes_unused_path"])
    daybook_quotes_used_path: str = Field(default=DEFAULTS["daybook_quotes_used_path"])
    daybook_quote_lifecycle_state: str = Field(default=DEFAULTS["daybook_quote_lifecycle_state"])
    daybook_archive_browser_executable: str = Field(default=DEFAULTS["daybook_archive_browser_executable"])
    daybook_archive_browser_user_data_dir: str = Field(default=DEFAULTS["daybook_archive_browser_user_data_dir"])
    daybook_archive_browser_headless: StrictBool = Field(default=DEFAULTS["daybook_archive_browser_headless"])
    daybook_archive_browser_launch_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_archive_browser_launch_timeout_seconds"]
    )
    daybook_archive_browser_navigation_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_archive_browser_navigation_timeout_seconds"]
    )
    daybook_archive_browser_render_wait_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_archive_browser_render_wait_seconds"]
    )
    daybook_weeknotes_reconcile_enabled: StrictBool = Field(default=DEFAULTS["daybook_weeknotes_reconcile_enabled"])
    daybook_weeknotes_reconcile_launchd_enabled: StrictBool = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_launchd_enabled"]
    )
    daybook_weeknotes_reconcile_launchd_retired: StrictBool = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_launchd_retired"]
    )
    daybook_weeknotes_reconcile_launchd_label: str = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_launchd_label"]
    )
    daybook_weeknotes_reconcile_launchd_plist_path: str = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_launchd_plist_path"]
    )
    daybook_weeknotes_reconcile_env_file: str = Field(default=DEFAULTS["daybook_weeknotes_reconcile_env_file"])
    daybook_weeknotes_reconcile_env_checksum_file: str = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_env_checksum_file"]
    )
    daybook_weeknotes_reconcile_launcher_path: str = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_launcher_path"]
    )
    daybook_weeknotes_reconcile_stdout_log: str = Field(default=DEFAULTS["daybook_weeknotes_reconcile_stdout_log"])
    daybook_weeknotes_reconcile_stderr_log: str = Field(default=DEFAULTS["daybook_weeknotes_reconcile_stderr_log"])
    daybook_weeknotes_reconcile_start_calendar: list[CalendarEntry] = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_start_calendar"]
    )
    daybook_weeknotes_reconcile_runtime_dir: str = Field(default=DEFAULTS["daybook_weeknotes_reconcile_runtime_dir"])
    daybook_weeknotes_reconcile_state_path: str = Field(default=DEFAULTS["daybook_weeknotes_reconcile_state_path"])
    daybook_weeknotes_reconcile_pi_agent_dir: str = Field(default=DEFAULTS["daybook_weeknotes_reconcile_pi_agent_dir"])
    daybook_weeknotes_reconcile_pi_auth_source_root: str = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_pi_auth_source_root"]
    )
    daybook_weeknotes_reconcile_pi_auth_source: str = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_pi_auth_source"]
    )
    daybook_weeknotes_reconcile_pi_auth_rotate: StrictBool = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_pi_auth_rotate"]
    )
    daybook_weeknotes_reconcile_public_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_public_timeout_seconds"]
    )
    daybook_weeknotes_reconcile_family_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_weeknotes_reconcile_family_timeout_seconds"]
    )
    daybook_weeknotes_post_identity_epoch: str = Field(default=DEFAULTS["daybook_weeknotes_post_identity_epoch"])
    daybook_weeknotes_identity_required_repo_ref: str = Field(
        default=DEFAULTS["daybook_weeknotes_identity_required_repo_ref"]
    )
    daybook_weeknotes_identity_seed_path: str = Field(default=DEFAULTS["daybook_weeknotes_identity_seed_path"])
    daybook_weeknotes_identity_plan_path: str = Field(default=DEFAULTS["daybook_weeknotes_identity_plan_path"])
    daybook_weeknotes_identity_attestation_path: str = Field(
        default=DEFAULTS["daybook_weeknotes_identity_attestation_path"]
    )
    daybook_weeknotes_identity_activation_proof_path: str = Field(
        default=DEFAULTS["daybook_weeknotes_identity_activation_proof_path"]
    )
    daybook_weeknotes_identity_helper_path: str = Field(default=DEFAULTS["daybook_weeknotes_identity_helper_path"])
    daybook_weeknotes_identity_launcher_path: str = Field(default=DEFAULTS["daybook_weeknotes_identity_launcher_path"])
    daybook_weeknotes_identity_operator_action: str = Field(
        default=DEFAULTS["daybook_weeknotes_identity_operator_action"]
    )
    daybook_weeknotes_identity_apply_confirmation: str = Field(
        default=DEFAULTS["daybook_weeknotes_identity_apply_confirmation"]
    )
    daybook_weeknotes_identity_seed_moves: list[dict[str, Any]] = Field(
        default=DEFAULTS["daybook_weeknotes_identity_seed_moves"], repr=False
    )
    daybook_weeknotes_path: str = Field(default=DEFAULTS["daybook_weeknotes_path"])
    daybook_weeknotes_cast_base_url: str = Field(default=DEFAULTS["daybook_weeknotes_cast_base_url"])
    daybook_weeknotes_home_url: str = Field(default=DEFAULTS["daybook_weeknotes_home_url"])
    daybook_weeknotes_public_blog_id: str = Field(default=DEFAULTS["daybook_weeknotes_public_blog_id"])
    daybook_weeknotes_family_blog_id: str = Field(default=DEFAULTS["daybook_weeknotes_family_blog_id"])
    daybook_sessions_brew_bin: str = Field(default=DEFAULTS["daybook_sessions_brew_bin"])
    daybook_sessions_brew_user: str = Field(default=DEFAULTS["daybook_sessions_brew_user"])
    daybook_sessions_brew_update: StrictBool = Field(default=DEFAULTS["daybook_sessions_brew_update"])
    daybook_sessions_brew_packages: list[str] = Field(default=DEFAULTS["daybook_sessions_brew_packages"])
    daybook_sessions_path: str = Field(default=DEFAULTS["daybook_sessions_path"])
    daybook_sessions_aws_endpoint_url_s3: str = Field(default=DEFAULTS["daybook_sessions_aws_endpoint_url_s3"])
    daybook_sessions_aws_region: str = Field(default=DEFAULTS["daybook_sessions_aws_region"])
    daybook_sessions_aws_default_region: str = Field(default=DEFAULTS["daybook_sessions_aws_default_region"])
    daybook_sessions_redact_files: list[str] = Field(default=DEFAULTS["daybook_sessions_redact_files"])
    daybook_sessions_remove_legacy_runner_paths: list[str] = Field(
        default=DEFAULTS["daybook_sessions_remove_legacy_runner_paths"]
    )

    @model_validator(mode="before")
    @classmethod
    def _resolve(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        return resolved_defaults(value)

    @model_validator(mode="after")
    def _guard(self) -> Self:
        values = self.model_dump(mode="json")
        for value in values.values():
            if isinstance(value, str) and any(c in value for c in "\x00\r\n"):
                raise ValueError("Sessions declaration contains a control character")
        if not self.daybook_sessions_enabled:
            return self
        for key in ("daybook_sessions_service_user", "daybook_sessions_service_group"):
            if not re.fullmatch(r"[a-z_][a-z0-9_-]*", values[key]) or values[key] == "CHANGEME":
                raise ValueError("Sessions requires a real service user/group")
        if not re.fullmatch(r"[0-9a-f]{40}", self.daybook_sessions_repo_ref):
            raise ValueError("Sessions requires the exact once-per-run resolved Main revision")
        GitSource(repo=self.daybook_sessions_repo_url, ref=self.daybook_sessions_repo_ref)
        for key, value in values.items():
            if isinstance(value, str) and key.endswith(("_path", "_file", "_dir", "_home", "_root", "_bin", "_source")):
                if key in {
                    "daybook_sessions_path",
                    "daybook_quotes_unused_path",
                    "daybook_quotes_used_path",
                    "daybook_weeknotes_path",
                }:
                    continue
                if value == "":
                    continue
                path = PurePosixPath(value)
                if not path.is_absolute() or str(path) == "/" or ".." in path.parts:
                    raise ValueError("Sessions filesystem paths must be absolute without traversal")
        for key in (
            "daybook_sessions_schedule_interval_seconds",
            "daybook_archive_quote_classifier_limit",
            "daybook_archive_quote_classifier_probe_timeout_seconds",
        ):
            if values[key] <= 0:
                raise ValueError("Sessions intervals, bounds and probes must be positive")
        for calendar in (
            self.daybook_archive_quote_classifier_start_calendar,
            self.daybook_weeknotes_reconcile_start_calendar,
        ):
            if not calendar:
                raise ValueError("Sessions calendars must not be empty")
        if self.daybook_archive_quote_classifier_enabled:
            if self.daybook_archive_quote_classifier_cmd in {"", "CHANGEME"}:
                raise ValueError("Enabled classifier requires its existing command")
            browser = PurePosixPath(self.daybook_archive_browser_user_data_dir)
            parent = PurePosixPath(self.daybook_sessions_service_home) / ".daybook"
            if browser.parent != parent:
                raise ValueError("Classifier needs a dedicated browser profile directly below the service home")
        if self.daybook_weeknotes_reconcile_enabled:
            self._weeknotes_guard()
        return self

    def _weeknotes_guard(self) -> None:
        if self.daybook_sessions_launchd_scope != "system":
            raise ValueError("Weeknotes reconciler requires the original system scope")
        if self.daybook_weeknotes_reconcile_launchd_enabled:
            raise ValueError("Install keeps Weeknotes disabled; activation is a separate original operation")
        if (
            self.daybook_weeknotes_reconcile_launchd_label != "de.wersdoerfer.daybook.weeknotes-reconcile"
            or self.daybook_weeknotes_reconcile_launchd_plist_path
            != "/Library/LaunchDaemons/de.wersdoerfer.daybook.weeknotes-reconcile.plist"
        ):
            raise ValueError("Weeknotes reconciler requires its original exact label/plist")
        if [item.model_dump() for item in self.daybook_weeknotes_reconcile_start_calendar] != [
            {"Hour": 7, "Minute": 40},
            {"Hour": 19, "Minute": 40},
        ]:
            raise ValueError("Weeknotes reconciler requires the original 07:40/19:40 schedule")
        runtime = PurePosixPath(self.daybook_weeknotes_reconcile_runtime_dir)
        home = PurePosixPath(self.daybook_sessions_service_home)
        authroot = PurePosixPath(self.daybook_weeknotes_reconcile_pi_auth_source_root)
        if (
            not runtime.is_relative_to(home / ".daybook")
            or runtime == home / ".daybook"
            or not authroot.is_relative_to(home / ".config")
            or authroot == home / ".config"
        ):
            raise ValueError("Weeknotes needs dedicated runtime and source auth roots")
        for path, expected in (
            (self.daybook_weeknotes_reconcile_state_path, runtime / "state.json"),
            (self.daybook_weeknotes_reconcile_pi_agent_dir, runtime / "pi-agent"),
            (self.daybook_weeknotes_reconcile_pi_auth_source, authroot / "auth.json"),
        ):
            if PurePosixPath(path) != expected:
                raise ValueError("Weeknotes dedicated control path mismatch")
        if (
            self.daybook_weeknotes_reconcile_pi_auth_source
            == self.daybook_weeknotes_reconcile_pi_agent_dir + "/auth.json"
        ):
            raise ValueError("Weeknotes source auth must remain separate from refreshed auth")
        for key in (
            "daybook_weeknotes_identity_seed_path",
            "daybook_weeknotes_identity_plan_path",
            "daybook_weeknotes_identity_attestation_path",
        ):
            if PurePosixPath(getattr(self, key)).parent != runtime:
                raise ValueError("Weeknotes identity evidence must stay in its runtime directory")
        for key in (
            "daybook_weeknotes_reconcile_env_checksum_file",
            "daybook_weeknotes_identity_activation_proof_path",
            "daybook_weeknotes_identity_helper_path",
            "daybook_weeknotes_identity_launcher_path",
        ):
            if PurePosixPath(getattr(self, key)).parent != PurePosixPath(self.daybook_sessions_config_dir):
                raise ValueError("Weeknotes managed helpers/evidence must stay in its config directory")
        if (
            len(
                {
                    self.daybook_weeknotes_identity_seed_path,
                    self.daybook_weeknotes_identity_plan_path,
                    self.daybook_weeknotes_identity_attestation_path,
                }
            )
            != 3
        ):
            raise ValueError("Weeknotes identity evidence paths must be distinct")
        if self.daybook_weeknotes_post_identity_epoch not in {"", "monday-after-v1"}:
            raise ValueError("Weeknotes identity epoch is unsupported")
        if (
            self.daybook_weeknotes_post_identity_epoch
            and self.daybook_weeknotes_identity_required_repo_ref != self.daybook_sessions_repo_ref
        ):
            raise ValueError("Weeknotes identity proof must bind this run's resolved Main revision")
