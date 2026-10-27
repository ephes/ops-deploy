"""Typed original OpsGate role inputs, resolved before connection."""

from __future__ import annotations

import json
import os
import re
from importlib.resources import files
from typing import Any, Literal, Self

from jinja2 import StrictUndefined, UndefinedError
from jinja2.nativetypes import NativeEnvironment
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ops_deploy.base import RoleConfig

PACKAGE = "ops_deploy.services.opsgate"
DEFAULTS: dict[str, Any] = json.loads(files(PACKAGE).joinpath("defaults.json").read_text())


class WorkspaceRepository(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    repo: str = Field(min_length=1)
    version: str = Field(default="HEAD", min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_./-]*$")

    @field_validator("repo")
    @classmethod
    def _repository(cls, value: str) -> str:
        from urllib.parse import urlsplit

        if any(c in value for c in "\r\n\x00") or value.startswith("-"):
            raise ValueError("Workspace repository must be a literal Git URL")
        if "://" in value:
            parsed = urlsplit(value)
            if parsed.scheme not in {"https", "ssh", "file"} or parsed.password is not None:
                raise ValueError("Workspace repository must use a supported transport without inline credentials")
        elif not re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[A-Za-z0-9_./-]+", value):
            raise ValueError("Workspace repository must use a supported Git transport")
        return value


def resolved_defaults(overrides: dict[str, Any]) -> dict[str, Any]:
    values = {**DEFAULTS, "inventory_hostname": "runner", **overrides}
    pending = set(DEFAULTS) - set(overrides)
    environment = NativeEnvironment(undefined=StrictUndefined)

    def render(value: Any) -> Any:
        if isinstance(value, str) and "{{" in value:
            return environment.from_string(value).render(values)
        if isinstance(value, list):
            return [render(v) for v in value]
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
    raise ValueError("OpsGate default references could not be resolved")


class OpsGateConfig(RoleConfig):
    remote_rsync_path: str = "/opt/homebrew/bin/rsync"
    # Names intentionally follow the authoritative role's public variables.
    inventory_hostname: str = "runner"
    opsgate_service_name: str = Field(default=DEFAULTS["opsgate_service_name"])
    ops_user: str = Field(default=DEFAULTS["ops_user"])
    ops_group: str = Field(default=DEFAULTS["ops_group"])
    ops_home_dir: str = Field(default=DEFAULTS["ops_home_dir"])
    ops_shell: str = Field(default=DEFAULTS["ops_shell"])
    control_service_user: str = Field(default=DEFAULTS["control_service_user"])
    control_service_group: str = Field(default=DEFAULTS["control_service_group"])
    control_service_home_dir: str = Field(default=DEFAULTS["control_service_home_dir"])
    control_service_shell: str = Field(default=DEFAULTS["control_service_shell"])
    opsgate_manage_users: bool = Field(default=DEFAULTS["opsgate_manage_users"])
    execution_data_dir: str = Field(default=DEFAULTS["execution_data_dir"])
    tickets_dir: str = Field(default=DEFAULTS["tickets_dir"])
    session_artifacts_dir: str = Field(default=DEFAULTS["session_artifacts_dir"])
    opsgate_runner_tmp_dir: str = Field(default=DEFAULTS["opsgate_runner_tmp_dir"])
    opsgate_tmux_tmpdir: str = Field(default=DEFAULTS["opsgate_tmux_tmpdir"])
    opsgate_ops_workspace_dir: str = Field(default=DEFAULTS["opsgate_ops_workspace_dir"])
    opsgate_ops_manage_workspace_repos: bool = Field(default=DEFAULTS["opsgate_ops_manage_workspace_repos"])
    opsgate_ops_workspace_repositories: list[WorkspaceRepository] = Field(
        default=DEFAULTS["opsgate_ops_workspace_repositories"]
    )
    opsgate_ops_ssh_known_hosts_path: str = Field(default=DEFAULTS["opsgate_ops_ssh_known_hosts_path"])
    opsgate_ops_ssh_config_path: str = Field(default=DEFAULTS["opsgate_ops_ssh_config_path"])
    opsgate_ops_github_ssh_private_key_path: str = Field(default=DEFAULTS["opsgate_ops_github_ssh_private_key_path"])
    opsgate_ops_github_ssh_public_key_path: str = Field(default=DEFAULTS["opsgate_ops_github_ssh_public_key_path"])
    opsgate_ops_github_host_key: str = Field(default=DEFAULTS["opsgate_ops_github_host_key"])
    opsgate_ops_github_deploy_key_path_prefix: str = Field(
        default=DEFAULTS["opsgate_ops_github_deploy_key_path_prefix"]
    )
    opsgate_app_dir: str = Field(default=DEFAULTS["opsgate_app_dir"])
    opsgate_runner_app_dir: str = Field(default=DEFAULTS["opsgate_runner_app_dir"])
    opsgate_config_dir: str = Field(default=DEFAULTS["opsgate_config_dir"])
    opsgate_log_dir: str = Field(default=DEFAULTS["opsgate_log_dir"])
    opsgate_runtime_dir: str = Field(default=DEFAULTS["opsgate_runtime_dir"])
    opsgate_state_dir: str = Field(default=DEFAULTS["opsgate_state_dir"])
    opsgate_db_path: str = Field(default=DEFAULTS["opsgate_db_path"])
    opsgate_source_path: str = Field(default=DEFAULTS["opsgate_source_path"])
    opsgate_uv_bin: str = Field(default=DEFAULTS["opsgate_uv_bin"])
    opsgate_rsync_excludes: list[str] = Field(default=DEFAULTS["opsgate_rsync_excludes"])
    opsgate_api_impl: Literal["python", "rust"] = Field(default=DEFAULTS["opsgate_api_impl"])
    opsgate_runner_impl: Literal["python", "rust"] = Field(default=DEFAULTS["opsgate_runner_impl"])
    opsgate_rust_version: str = Field(default=DEFAULTS["opsgate_rust_version"])
    opsgate_rust_sha256: str = Field(default=DEFAULTS["opsgate_rust_sha256"])
    opsgate_rust_release_url: str = Field(default=DEFAULTS["opsgate_rust_release_url"])
    opsgate_rust_local_archive: str = Field(default=DEFAULTS["opsgate_rust_local_archive"])
    opsgate_rust_install_root: str = Field(default=DEFAULTS["opsgate_rust_install_root"])
    opsgate_rust_keep_versions: int = Field(default=DEFAULTS["opsgate_rust_keep_versions"])
    opsgate_launchd_python_plist_dir: str = Field(default=DEFAULTS["opsgate_launchd_python_plist_dir"])
    opsgate_launchd_verify_retries: int = Field(default=DEFAULTS["opsgate_launchd_verify_retries"])
    opsgate_launchd_verify_delay: int = Field(default=DEFAULTS["opsgate_launchd_verify_delay"])
    opsgate_api_bind_host: str = Field(default=DEFAULTS["opsgate_api_bind_host"])
    opsgate_api_bind_port: int = Field(default=DEFAULTS["opsgate_api_bind_port"])
    opsgate_trust_proxy_headers: bool = Field(default=DEFAULTS["opsgate_trust_proxy_headers"])
    opsgate_session_cookie_secure: bool = Field(default=DEFAULTS["opsgate_session_cookie_secure"])
    opsgate_ui_session_timeout_seconds: int = Field(default=DEFAULTS["opsgate_ui_session_timeout_seconds"])
    opsgate_require_tailscale_context: bool = Field(default=DEFAULTS["opsgate_require_tailscale_context"])
    opsgate_allowed_cidrs: list[str] = Field(default=DEFAULTS["opsgate_allowed_cidrs"])
    opsgate_disable_file_path: str = Field(default=DEFAULTS["opsgate_disable_file_path"])
    opsgate_runner_poll_interval_seconds: int = Field(default=DEFAULTS["opsgate_runner_poll_interval_seconds"])
    opsgate_runner_heartbeat_interval_seconds: int = Field(
        default=DEFAULTS["opsgate_runner_heartbeat_interval_seconds"]
    )
    opsgate_runner_stale_after_seconds: int = Field(default=DEFAULTS["opsgate_runner_stale_after_seconds"])
    opsgate_max_parallel_jobs: int = Field(default=DEFAULTS["opsgate_max_parallel_jobs"])
    opsgate_max_duration_seconds_default: int = Field(default=DEFAULTS["opsgate_max_duration_seconds_default"])
    opsgate_runner_api_base_url: str = Field(default=DEFAULTS["opsgate_runner_api_base_url"])
    opsgate_runner_host: str = Field(default=DEFAULTS["opsgate_runner_host"])
    opsgate_policy_floor_require_reviewer_step: bool = Field(
        default=DEFAULTS["opsgate_policy_floor_require_reviewer_step"]
    )
    opsgate_submit_policy_openclaw_require_reviewer_step: bool = Field(
        default=DEFAULTS["opsgate_submit_policy_openclaw_require_reviewer_step"]
    )
    opsgate_submit_policy_nyxmon_require_reviewer_step: bool = Field(
        default=DEFAULTS["opsgate_submit_policy_nyxmon_require_reviewer_step"]
    )
    opsgate_submit_policy_operator_require_reviewer_step: bool = Field(
        default=DEFAULTS["opsgate_submit_policy_operator_require_reviewer_step"]
    )
    opsgate_ui_username: str = Field(default=DEFAULTS["opsgate_ui_username"])
    opsgate_ops_git_user_name: str = Field(default=DEFAULTS["opsgate_ops_git_user_name"])
    opsgate_ops_git_user_email: str = Field(default=DEFAULTS["opsgate_ops_git_user_email"])
    opsgate_ops_github_username: str = Field(default=DEFAULTS["opsgate_ops_github_username"])
    opsgate_tmux_socket_label: str = Field(default=DEFAULTS["opsgate_tmux_socket_label"])
    opsgate_tmux_conf_path: str = Field(default=DEFAULTS["opsgate_tmux_conf_path"])
    opsgate_tmux_history_limit: int = Field(default=DEFAULTS["opsgate_tmux_history_limit"])
    opsgate_tmux_base_index: int = Field(default=DEFAULTS["opsgate_tmux_base_index"])
    opsgate_launchd_manage_state: bool = Field(default=DEFAULTS["opsgate_launchd_manage_state"])
    opsgate_launchd_start_services: bool = Field(default=DEFAULTS["opsgate_launchd_start_services"])
    opsgate_launchd_keepalive: bool = Field(default=DEFAULTS["opsgate_launchd_keepalive"])
    opsgate_launchd_path: str = Field(default=DEFAULTS["opsgate_launchd_path"])
    opsgate_api_launchd_label: str = Field(default=DEFAULTS["opsgate_api_launchd_label"])
    opsgate_api_launchd_plist_path: str = Field(default=DEFAULTS["opsgate_api_launchd_plist_path"])
    opsgate_api_launchd_manage_state: bool = Field(default=DEFAULTS["opsgate_api_launchd_manage_state"])
    opsgate_api_launchd_start_service: bool = Field(default=DEFAULTS["opsgate_api_launchd_start_service"])
    opsgate_api_program: str = Field(default=DEFAULTS["opsgate_api_program"])
    opsgate_api_program_arguments: list[str] = Field(default=DEFAULTS["opsgate_api_program_arguments"])
    opsgate_api_working_directory: str = Field(default=DEFAULTS["opsgate_api_working_directory"])
    opsgate_api_stdout_log: str = Field(default=DEFAULTS["opsgate_api_stdout_log"])
    opsgate_api_stderr_log: str = Field(default=DEFAULTS["opsgate_api_stderr_log"])
    opsgate_api_environment: dict[str, str] = Field(default=DEFAULTS["opsgate_api_environment"])
    opsgate_runner_launchd_label: str = Field(default=DEFAULTS["opsgate_runner_launchd_label"])
    opsgate_runner_launchd_plist_path: str = Field(default=DEFAULTS["opsgate_runner_launchd_plist_path"])
    opsgate_runner_launchd_manage_state: bool = Field(default=DEFAULTS["opsgate_runner_launchd_manage_state"])
    opsgate_runner_launchd_start_service: bool = Field(default=DEFAULTS["opsgate_runner_launchd_start_service"])
    opsgate_runner_program: str = Field(default=DEFAULTS["opsgate_runner_program"])
    opsgate_runner_program_arguments: list[str] = Field(default=DEFAULTS["opsgate_runner_program_arguments"])
    opsgate_runner_working_directory: str = Field(default=DEFAULTS["opsgate_runner_working_directory"])
    opsgate_runner_stdout_log: str = Field(default=DEFAULTS["opsgate_runner_stdout_log"])
    opsgate_runner_stderr_log: str = Field(default=DEFAULTS["opsgate_runner_stderr_log"])
    opsgate_runner_environment: dict[str, str] = Field(default=DEFAULTS["opsgate_runner_environment"])

    @model_validator(mode="before")
    @classmethod
    def _resolve(cls, value: Any) -> Any:
        return resolved_defaults(value) if isinstance(value, dict) else value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.opsgate_service_name != "opsgate" or self.ops_user == self.control_service_user:
            raise ValueError("OpsGate requires its fixed service name and separate runtime accounts")
        for name in (self.ops_user, self.ops_group, self.control_service_user, self.control_service_group):
            if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name):
                raise ValueError("OpsGate account names must be valid Unix identities")
        for label in (self.opsgate_api_launchd_label, self.opsgate_runner_launchd_label):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]+", label):
                raise ValueError("OpsGate launchd labels must be literal service identifiers")
        for key, value in self.model_dump(mode="json").items():
            if isinstance(value, str) and any(c in value for c in "\x00\r\n"):
                raise ValueError("OpsGate settings must be single-line values")
            if (
                key.endswith(("_dir", "_path", "_root", "_log"))
                and isinstance(value, str)
                and value
                and (not value.startswith("/") or value == "/" or os.path.normpath(value) != value)
            ):
                raise ValueError("OpsGate resource paths must be normalized absolute non-root paths")
        if not 1 <= self.opsgate_api_bind_port <= 65535:
            raise ValueError("OpsGate API port must be in 1..65535")
        if (
            self.opsgate_rust_keep_versions < 1
            or self.opsgate_launchd_verify_retries < 1
            or self.opsgate_launchd_verify_delay < 0
        ):
            raise ValueError("Rust retention and verification retries must be positive; verification delay nonnegative")
        if "rust" in (self.opsgate_api_impl, self.opsgate_runner_impl) and not self.opsgate_rust_version:
            raise ValueError("Rust implementation requires a pinned release")
        if self.opsgate_rust_version:
            if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", self.opsgate_rust_version):
                raise ValueError("Rust version must be a pinned release")
            if not self.opsgate_rust_local_archive and not re.fullmatch(r"[0-9a-f]{64}", self.opsgate_rust_sha256):
                raise ValueError("Rust release requires its archive SHA256")
        elif self.opsgate_rust_sha256 or self.opsgate_rust_local_archive:
            raise ValueError("Rust archive inputs require their pinned version")
        if not self.opsgate_rust_local_archive and not self.opsgate_rust_release_url.startswith("https://"):
            raise ValueError("Rust release download must use HTTPS")
        for app in (self.opsgate_app_dir, self.opsgate_runner_app_dir):
            if (self.opsgate_rust_install_root + "/").startswith(app + "/"):
                raise ValueError("Rust releases must remain outside source synchronization trees")
        if self.opsgate_launchd_python_plist_dir in (
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
        ):
            raise ValueError("Python rollback copies must remain outside automatically loaded launchd directories")
        if not self.opsgate_source_path or not os.path.isdir(self.opsgate_source_path):
            raise ValueError("OpsGate controller source directory is unavailable")
        names = [entry.name for entry in self.opsgate_ops_workspace_repositories]
        if len(names) != len(set(names)):
            raise ValueError("Workspace names must be unique")
        return self
