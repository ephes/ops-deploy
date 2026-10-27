"""Typed literal role inputs, with native paths resolved before connection."""

from __future__ import annotations

import json
import os
import re
from importlib.resources import files
from typing import Any, Literal, Self

from jinja2 import StrictUndefined, UndefinedError
from jinja2.nativetypes import NativeEnvironment
from pydantic import Field, model_validator

from ops_deploy.base import RoleConfig
from ops_deploy.services.voxhelm.artifacts import ArtifactContinuity

PACKAGE = "ops_deploy.services.voxhelm_remote_worker"
DEFAULTS: dict[str, Any] = json.loads(files(PACKAGE).joinpath("defaults.json").read_text())


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
                result = render(DEFAULTS[key])
            except UndefinedError:
                remaining.add(key)
                continue
            values[key] = result
            if "{{" in json.dumps(result):
                remaining.add(key)
        if not remaining:
            return values
        pending = remaining
    raise ValueError("Voxhelm role defaults could not be resolved")


class VoxhelmRemoteWorkerConfig(RoleConfig):
    preserved_artifacts: dict[str, ArtifactContinuity] = Field(default_factory=dict)
    inventory_hostname: str = "runner"
    voxhelm_remote_worker_enabled: bool = Field(default=DEFAULTS["voxhelm_remote_worker_enabled"])
    voxhelm_remote_worker_service_user: str = Field(default=DEFAULTS["voxhelm_remote_worker_service_user"])
    voxhelm_remote_worker_service_group: str = Field(default=DEFAULTS["voxhelm_remote_worker_service_group"])
    voxhelm_remote_worker_service_home: str = Field(default=DEFAULTS["voxhelm_remote_worker_service_home"])
    voxhelm_remote_worker_work_dir: str = Field(default=DEFAULTS["voxhelm_remote_worker_work_dir"])
    voxhelm_remote_worker_config_dir: str = Field(default=DEFAULTS["voxhelm_remote_worker_config_dir"])
    voxhelm_remote_worker_env_file: str = Field(default=DEFAULTS["voxhelm_remote_worker_env_file"])
    voxhelm_remote_worker_log_dir: str = Field(default=DEFAULTS["voxhelm_remote_worker_log_dir"])
    voxhelm_remote_worker_stdout_log: str = Field(default=DEFAULTS["voxhelm_remote_worker_stdout_log"])
    voxhelm_remote_worker_stderr_log: str = Field(default=DEFAULTS["voxhelm_remote_worker_stderr_log"])
    voxhelm_remote_worker_install_transcript_path: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_install_transcript_path"]
    )
    voxhelm_remote_worker_launcher_path: str = Field(default=DEFAULTS["voxhelm_remote_worker_launcher_path"])
    voxhelm_remote_worker_uv_bin: str = Field(default=DEFAULTS["voxhelm_remote_worker_uv_bin"])
    voxhelm_remote_worker_python_version: str = Field(default=DEFAULTS["voxhelm_remote_worker_python_version"])
    voxhelm_remote_worker_public_index_url: str = Field(default=DEFAULTS["voxhelm_remote_worker_public_index_url"])
    voxhelm_remote_worker_package_name: str = Field(default=DEFAULTS["voxhelm_remote_worker_package_name"])
    voxhelm_remote_worker_package_version: str = Field(default=DEFAULTS["voxhelm_remote_worker_package_version"])
    voxhelm_remote_worker_package_extras: list[str] = Field(default=DEFAULTS["voxhelm_remote_worker_package_extras"])
    voxhelm_remote_worker_binary_path: str = Field(default=DEFAULTS["voxhelm_remote_worker_binary_path"])
    voxhelm_remote_worker_force_install: bool = Field(default=DEFAULTS["voxhelm_remote_worker_force_install"])
    voxhelm_remote_worker_base_url: str = Field(default=DEFAULTS["voxhelm_remote_worker_base_url"])
    voxhelm_remote_worker_id: str = Field(default=DEFAULTS["voxhelm_remote_worker_id"])
    voxhelm_remote_worker_hostname: str = Field(default=DEFAULTS["voxhelm_remote_worker_hostname"])
    voxhelm_remote_worker_allowed_url_hosts: list[str] = Field(
        default=DEFAULTS["voxhelm_remote_worker_allowed_url_hosts"]
    )
    voxhelm_remote_worker_private_url_hosts: list[str] = Field(
        default=DEFAULTS["voxhelm_remote_worker_private_url_hosts"]
    )
    voxhelm_remote_worker_poll_seconds: int = Field(default=DEFAULTS["voxhelm_remote_worker_poll_seconds"])
    voxhelm_remote_worker_http_timeout_seconds: int = Field(
        default=DEFAULTS["voxhelm_remote_worker_http_timeout_seconds"]
    )
    voxhelm_remote_worker_heartbeat_interval_seconds: int = Field(
        default=DEFAULTS["voxhelm_remote_worker_heartbeat_interval_seconds"]
    )
    voxhelm_remote_worker_log_level: str = Field(default=DEFAULTS["voxhelm_remote_worker_log_level"])
    voxhelm_remote_worker_caffeinate_enabled: bool = Field(default=DEFAULTS["voxhelm_remote_worker_caffeinate_enabled"])
    voxhelm_remote_worker_caffeinate_bin: str = Field(default=DEFAULTS["voxhelm_remote_worker_caffeinate_bin"])
    voxhelm_remote_worker_caffeinate_args: list[str] = Field(default=DEFAULTS["voxhelm_remote_worker_caffeinate_args"])
    voxhelm_remote_worker_launchd_label: str = Field(default=DEFAULTS["voxhelm_remote_worker_launchd_label"])
    voxhelm_remote_worker_launchd_plist_path: str = Field(default=DEFAULTS["voxhelm_remote_worker_launchd_plist_path"])
    voxhelm_remote_worker_launchd_keepalive: bool = Field(default=DEFAULTS["voxhelm_remote_worker_launchd_keepalive"])
    voxhelm_remote_worker_launchd_manage_state: bool = Field(
        default=DEFAULTS["voxhelm_remote_worker_launchd_manage_state"]
    )
    voxhelm_remote_worker_launchd_start_service: bool = Field(
        default=DEFAULTS["voxhelm_remote_worker_launchd_start_service"]
    )
    voxhelm_remote_worker_launchd_path: str = Field(default=DEFAULTS["voxhelm_remote_worker_launchd_path"])
    voxhelm_remote_worker_brew_bin: str = Field(default=DEFAULTS["voxhelm_remote_worker_brew_bin"])
    voxhelm_remote_worker_brew_user: str = Field(default=DEFAULTS["voxhelm_remote_worker_brew_user"])
    voxhelm_remote_worker_brew_update: bool = Field(default=DEFAULTS["voxhelm_remote_worker_brew_update"])
    voxhelm_remote_worker_brew_packages: list[str] = Field(default=DEFAULTS["voxhelm_remote_worker_brew_packages"])
    voxhelm_remote_worker_stt_backend: str = Field(default=DEFAULTS["voxhelm_remote_worker_stt_backend"])
    voxhelm_remote_worker_stt_fallback_backend: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_stt_fallback_backend"]
    )
    voxhelm_remote_worker_mlx_model: str = Field(default=DEFAULTS["voxhelm_remote_worker_mlx_model"])
    voxhelm_remote_worker_whispercpp_model: str = Field(default=DEFAULTS["voxhelm_remote_worker_whispercpp_model"])
    voxhelm_remote_worker_whispercpp_model_source: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_whispercpp_model_source"]
    )
    voxhelm_remote_worker_whispercpp_bin: str = Field(default=DEFAULTS["voxhelm_remote_worker_whispercpp_bin"])
    voxhelm_remote_worker_whispercpp_processors: int = Field(
        default=DEFAULTS["voxhelm_remote_worker_whispercpp_processors"]
    )
    voxhelm_remote_worker_whisperkit_enabled: bool = Field(default=DEFAULTS["voxhelm_remote_worker_whisperkit_enabled"])
    voxhelm_remote_worker_whisperkit_base_url: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_whisperkit_base_url"]
    )
    voxhelm_remote_worker_whisperkit_model: str = Field(default=DEFAULTS["voxhelm_remote_worker_whisperkit_model"])
    voxhelm_remote_worker_stt_debug_logging: bool = Field(default=DEFAULTS["voxhelm_remote_worker_stt_debug_logging"])
    voxhelm_remote_worker_ffmpeg_bin: str = Field(default=DEFAULTS["voxhelm_remote_worker_ffmpeg_bin"])
    voxhelm_remote_worker_model_cache_dir: str = Field(default=DEFAULTS["voxhelm_remote_worker_model_cache_dir"])
    voxhelm_remote_worker_parakeet_enabled: bool = Field(default=DEFAULTS["voxhelm_remote_worker_parakeet_enabled"])
    voxhelm_remote_worker_parakeet_package_version: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_package_version"]
    )
    voxhelm_remote_worker_parakeet_python_version: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_python_version"]
    )
    voxhelm_remote_worker_parakeet_bin: str = Field(default=DEFAULTS["voxhelm_remote_worker_parakeet_bin"])
    voxhelm_remote_worker_parakeet_model_repo: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_model_repo"]
    )
    voxhelm_remote_worker_parakeet_model_revision: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_model_revision"]
    )
    voxhelm_remote_worker_parakeet_model_sha256: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_model_sha256"]
    )
    voxhelm_remote_worker_parakeet_model_root: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_model_root"]
    )
    voxhelm_remote_worker_parakeet_model_dir: str = Field(default=DEFAULTS["voxhelm_remote_worker_parakeet_model_dir"])
    voxhelm_remote_worker_parakeet_model_name: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_model_name"]
    )
    voxhelm_remote_worker_parakeet_chunk_seconds: int = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_chunk_seconds"]
    )
    voxhelm_remote_worker_parakeet_overlap_seconds: int = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_overlap_seconds"]
    )
    voxhelm_remote_worker_parakeet_max_sentence_seconds: float | Literal[""] = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_max_sentence_seconds"]
    )
    voxhelm_remote_worker_parakeet_timeout_seconds: int = Field(
        default=DEFAULTS["voxhelm_remote_worker_parakeet_timeout_seconds"]
    )
    voxhelm_remote_worker_ad_analysis_enabled: bool = Field(
        default=DEFAULTS["voxhelm_remote_worker_ad_analysis_enabled"]
    )
    voxhelm_remote_worker_ad_analysis_brew_packages: list[str] = Field(
        default=DEFAULTS["voxhelm_remote_worker_ad_analysis_brew_packages"]
    )
    voxhelm_remote_worker_window_model: str = Field(default=DEFAULTS["voxhelm_remote_worker_window_model"])
    voxhelm_remote_worker_window_model_url: str = Field(default=DEFAULTS["voxhelm_remote_worker_window_model_url"])
    voxhelm_remote_worker_window_model_sha256: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_window_model_sha256"]
    )
    voxhelm_remote_worker_window_model_source: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_window_model_source"]
    )
    voxhelm_remote_worker_window_timeout_seconds: int = Field(
        default=DEFAULTS["voxhelm_remote_worker_window_timeout_seconds"]
    )
    voxhelm_remote_worker_ffprobe_bin: str = Field(default=DEFAULTS["voxhelm_remote_worker_ffprobe_bin"])
    voxhelm_remote_worker_diarization_backend: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_diarization_backend"]
    )
    voxhelm_remote_worker_pyannote_model: str = Field(default=DEFAULTS["voxhelm_remote_worker_pyannote_model"])
    voxhelm_remote_worker_pyannote_device: str = Field(default=DEFAULTS["voxhelm_remote_worker_pyannote_device"])
    voxhelm_remote_worker_artifact_backend: str = Field(default=DEFAULTS["voxhelm_remote_worker_artifact_backend"])
    voxhelm_remote_worker_artifact_bucket: str = Field(default=DEFAULTS["voxhelm_remote_worker_artifact_bucket"])
    voxhelm_remote_worker_artifact_prefix: str = Field(default=DEFAULTS["voxhelm_remote_worker_artifact_prefix"])
    voxhelm_remote_worker_artifact_s3_endpoint_url: str = Field(
        default=DEFAULTS["voxhelm_remote_worker_artifact_s3_endpoint_url"]
    )
    voxhelm_remote_worker_artifact_s3_region: str = Field(default=DEFAULTS["voxhelm_remote_worker_artifact_s3_region"])
    voxhelm_remote_worker_artifact_s3_force_path_style: bool = Field(
        default=DEFAULTS["voxhelm_remote_worker_artifact_s3_force_path_style"]
    )

    @model_validator(mode="before")
    @classmethod
    def _resolve(cls, value: Any) -> Any:
        return resolved_defaults(value) if isinstance(value, dict) else value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        data = self.model_dump(mode="json")
        for path in self.preserved_artifacts:
            if not path.startswith("/") or os.path.normpath(path) != path or path == "/":
                raise ValueError("Artifact continuity paths must be normalized absolute paths")
        for key, value in data.items():
            if isinstance(value, str) and any(c in value for c in "\x00\r\n"):
                raise ValueError("Voxhelm configuration must use single-line literal values")
            if (
                key.endswith(("_dir", "_path", "_root", "_log", "_home", "_file"))
                and isinstance(value, str)
                and value
                and (not value.startswith("/") or value == "/" or os.path.normpath(value) != value)
            ):
                raise ValueError("Voxhelm resource paths must be normalized absolute non-root paths")
            if (
                key.endswith(("_label",))
                and isinstance(value, str)
                and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]+", value)
            ):
                raise ValueError("Voxhelm launchd labels must be literal service identifiers")
            if key.endswith("_port") and (
                not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535
            ):
                raise ValueError("Voxhelm ports must be in 1..65535")
            if key.endswith("_private_url_hosts") and any(
                not re.fullmatch(r"[A-Za-z0-9._:-]+", host) for host in value
            ):
                raise ValueError("Voxhelm private URL hosts must be literal host names")
        if not self.voxhelm_remote_worker_enabled:
            return self
        if (
            not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.voxhelm_remote_worker_service_user)
            or self.voxhelm_remote_worker_service_user == "CHANGEME"
        ):
            raise ValueError("Remote worker requires its existing service account")
        if (
            self.voxhelm_remote_worker_public_index_url != "https://pypi.org/simple"
            or self.voxhelm_remote_worker_package_name != "voxhelm"
        ):
            raise ValueError("Remote worker must select the public PyPI voxhelm package")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9.-]+)?", self.voxhelm_remote_worker_package_version):
            raise ValueError("Remote worker package version must be pinned")
        if not self.voxhelm_remote_worker_base_url or not self.voxhelm_remote_worker_id:
            raise ValueError("Remote worker requires its control-plane URL and identity")
        if self.voxhelm_remote_worker_log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError("Remote worker log level is unsupported")
        if (
            self.voxhelm_remote_worker_artifact_backend.strip().lower() != "s3"
            or not self.voxhelm_remote_worker_artifact_bucket
            or not self.voxhelm_remote_worker_artifact_s3_endpoint_url
        ):
            raise ValueError("Remote worker requires its shared S3 artifact configuration")
        for name in (
            "voxhelm_remote_worker_poll_seconds",
            "voxhelm_remote_worker_http_timeout_seconds",
            "voxhelm_remote_worker_heartbeat_interval_seconds",
        ):
            if getattr(self, name) <= 0:
                raise ValueError("Remote worker polling, heartbeat and timeouts must be positive")
        if self.voxhelm_remote_worker_parakeet_enabled:
            if not re.fullmatch(
                r"[0-9a-f]{40}", self.voxhelm_remote_worker_parakeet_model_revision
            ) or not re.fullmatch(r"[0-9a-f]{64}", self.voxhelm_remote_worker_parakeet_model_sha256):
                raise ValueError("Parakeet model requires a pinned Git revision and weight SHA256")
            if (
                not 0
                <= self.voxhelm_remote_worker_parakeet_overlap_seconds
                < self.voxhelm_remote_worker_parakeet_chunk_seconds
                or self.voxhelm_remote_worker_parakeet_timeout_seconds <= 0
            ):
                raise ValueError("Parakeet overlap must be smaller than its positive chunk duration")
            maximum = self.voxhelm_remote_worker_parakeet_max_sentence_seconds
            if maximum != "" and maximum <= 0:
                raise ValueError("Parakeet maximum sentence duration must be empty or positive")
        if self.voxhelm_remote_worker_ad_analysis_enabled and (
            not self.voxhelm_remote_worker_parakeet_enabled
            or not re.fullmatch(r"[0-9a-f]{64}", self.voxhelm_remote_worker_window_model_sha256)
        ):
            raise ValueError("Ad-analysis requires Parakeet and its pinned window model")
        return self
