"""Typed literal role inputs, with native paths resolved before connection."""

from __future__ import annotations

import json
import os
import re
from importlib.resources import files
from typing import Any, Literal, Self

from jinja2 import StrictUndefined, UndefinedError
from jinja2.nativetypes import NativeEnvironment
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ops_deploy.base import RoleConfig

from .artifacts import ArtifactContinuity

PACKAGE = "ops_deploy.services.voxhelm"
DEFAULTS: dict[str, Any] = json.loads(files(PACKAGE).joinpath("defaults.json").read_text())


class PinnedArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    url: str = Field(pattern=r"^https?://[^\s]+$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dest: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class KokoroVoice(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    model_file: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    voicepack_file: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    voicepack_key: str
    phoneme_language: str


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


class VoxhelmConfig(RoleConfig):
    remote_rsync_path: str = "/opt/homebrew/bin/rsync"
    preserved_artifacts: dict[str, ArtifactContinuity] = Field(default_factory=dict)
    voxhelm_whispercpp_model_sha256: str = Field(default="", pattern=r"^(?:[0-9a-f]{64})?$")
    source_preservation_revision: str = Field(default="", pattern=r"^(?:[0-9a-f]{40})?$")
    source_overrides: dict[str, str] = Field(default_factory=dict)
    inventory_hostname: str = "runner"
    voxhelm_service_name: str = Field(default=DEFAULTS["voxhelm_service_name"])
    voxhelm_source_path: str = Field(default=DEFAULTS["voxhelm_source_path"])
    voxhelm_sync_excludes: list[str] = Field(default=DEFAULTS["voxhelm_sync_excludes"])
    voxhelm_app_dir: str = Field(default=DEFAULTS["voxhelm_app_dir"])
    voxhelm_config_dir: str = Field(default=DEFAULTS["voxhelm_config_dir"])
    voxhelm_log_dir: str = Field(default=DEFAULTS["voxhelm_log_dir"])
    voxhelm_start_script_path: str = Field(default=DEFAULTS["voxhelm_start_script_path"])
    voxhelm_worker_script_path: str = Field(default=DEFAULTS["voxhelm_worker_script_path"])
    voxhelm_wyoming_stt_script_path: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_script_path"])
    voxhelm_whisperkit_script_path: str = Field(default=DEFAULTS["voxhelm_whisperkit_script_path"])
    voxhelm_prune_script_path: str = Field(default=DEFAULTS["voxhelm_prune_script_path"])
    voxhelm_uv_bin: str = Field(default=DEFAULTS["voxhelm_uv_bin"])
    voxhelm_python_version: str = Field(default=DEFAULTS["voxhelm_python_version"])
    voxhelm_bind_host: str = Field(default=DEFAULTS["voxhelm_bind_host"])
    voxhelm_app_port: int = Field(default=DEFAULTS["voxhelm_app_port"])
    voxhelm_uvicorn_log_level: str = Field(default=DEFAULTS["voxhelm_uvicorn_log_level"])
    voxhelm_task_backend: str = Field(default=DEFAULTS["voxhelm_task_backend"])
    voxhelm_task_queue: str = Field(default=DEFAULTS["voxhelm_task_queue"])
    voxhelm_transcription_execution_mode: str = Field(default=DEFAULTS["voxhelm_transcription_execution_mode"])
    voxhelm_remote_worker_lease_seconds: int = Field(default=DEFAULTS["voxhelm_remote_worker_lease_seconds"])
    voxhelm_remote_worker_poll_seconds: int = Field(default=DEFAULTS["voxhelm_remote_worker_poll_seconds"])
    voxhelm_remote_worker_max_attempts: int = Field(default=DEFAULTS["voxhelm_remote_worker_max_attempts"])
    voxhelm_worker_enabled: bool = Field(default=DEFAULTS["voxhelm_worker_enabled"])
    voxhelm_worker_interval_seconds: int = Field(default=DEFAULTS["voxhelm_worker_interval_seconds"])
    voxhelm_worker_label: str = Field(default=DEFAULTS["voxhelm_worker_label"])
    voxhelm_worker_plist_path: str = Field(default=DEFAULTS["voxhelm_worker_plist_path"])
    voxhelm_worker_stdout_log: str = Field(default=DEFAULTS["voxhelm_worker_stdout_log"])
    voxhelm_worker_stderr_log: str = Field(default=DEFAULTS["voxhelm_worker_stderr_log"])
    voxhelm_wyoming_stt_enabled: bool = Field(default=DEFAULTS["voxhelm_wyoming_stt_enabled"])
    voxhelm_wyoming_stt_label: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_label"])
    voxhelm_wyoming_stt_plist_path: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_plist_path"])
    voxhelm_wyoming_stt_stdout_log: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_stdout_log"])
    voxhelm_wyoming_stt_stderr_log: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_stderr_log"])
    voxhelm_prune_enabled: bool = Field(default=DEFAULTS["voxhelm_prune_enabled"])
    voxhelm_prune_dry_run: bool = Field(default=DEFAULTS["voxhelm_prune_dry_run"])
    voxhelm_prune_interval_seconds: int = Field(default=DEFAULTS["voxhelm_prune_interval_seconds"])
    voxhelm_prune_daily_time: str = Field(default=DEFAULTS["voxhelm_prune_daily_time"])
    voxhelm_prune_label: str = Field(default=DEFAULTS["voxhelm_prune_label"])
    voxhelm_prune_plist_path: str = Field(default=DEFAULTS["voxhelm_prune_plist_path"])
    voxhelm_prune_stdout_log: str = Field(default=DEFAULTS["voxhelm_prune_stdout_log"])
    voxhelm_prune_stderr_log: str = Field(default=DEFAULTS["voxhelm_prune_stderr_log"])
    voxhelm_source_artifact_retention_seconds: int | Literal[""] = Field(
        default=DEFAULTS["voxhelm_source_artifact_retention_seconds"]
    )
    voxhelm_job_metadata_retention_seconds: int | Literal[""] = Field(
        default=DEFAULTS["voxhelm_job_metadata_retention_seconds"]
    )
    voxhelm_staged_input_retention_seconds: int | Literal[""] = Field(
        default=DEFAULTS["voxhelm_staged_input_retention_seconds"]
    )
    voxhelm_wyoming_stt_max_audio_seconds: int | Literal[""] = Field(
        default=DEFAULTS["voxhelm_wyoming_stt_max_audio_seconds"]
    )
    voxhelm_private_url_hosts: list[str] = Field(default=DEFAULTS["voxhelm_private_url_hosts"])
    voxhelm_batch_max_download_bytes: int = Field(default=DEFAULTS["voxhelm_batch_max_download_bytes"])
    voxhelm_ffmpeg_bin: str = Field(default=DEFAULTS["voxhelm_ffmpeg_bin"])
    voxhelm_stt_backend: str = Field(default=DEFAULTS["voxhelm_stt_backend"])
    voxhelm_stt_fallback_backend: str = Field(default=DEFAULTS["voxhelm_stt_fallback_backend"])
    voxhelm_known_speaker_stt_backend: str = Field(default=DEFAULTS["voxhelm_known_speaker_stt_backend"])
    voxhelm_stt_debug_logging: bool = Field(default=DEFAULTS["voxhelm_stt_debug_logging"])
    voxhelm_diarization_backend: str = Field(default=DEFAULTS["voxhelm_diarization_backend"])
    voxhelm_pyannote_model: str = Field(default=DEFAULTS["voxhelm_pyannote_model"])
    voxhelm_pyannote_device: str = Field(default=DEFAULTS["voxhelm_pyannote_device"])
    voxhelm_uv_extras: list[str] = Field(default=DEFAULTS["voxhelm_uv_extras"])
    voxhelm_tts_backend: str = Field(default=DEFAULTS["voxhelm_tts_backend"])
    voxhelm_tts_max_input_chars: int = Field(default=DEFAULTS["voxhelm_tts_max_input_chars"])
    voxhelm_model_cache_dir: str = Field(default=DEFAULTS["voxhelm_model_cache_dir"])
    voxhelm_piper_voice_dir: str = Field(default=DEFAULTS["voxhelm_piper_voice_dir"])
    voxhelm_piper_voices: list[str] = Field(default=DEFAULTS["voxhelm_piper_voices"])
    voxhelm_piper_default_voice: str = Field(default=DEFAULTS["voxhelm_piper_default_voice"])
    voxhelm_piper_language_voices: dict[str, str] = Field(default=DEFAULTS["voxhelm_piper_language_voices"])
    voxhelm_tts_kokoro_enabled: bool = Field(default=DEFAULTS["voxhelm_tts_kokoro_enabled"])
    voxhelm_tts_language_routing_enabled: bool = Field(default=DEFAULTS["voxhelm_tts_language_routing_enabled"])
    voxhelm_kokoro_model_dir: str = Field(default=DEFAULTS["voxhelm_kokoro_model_dir"])
    voxhelm_kokoro_models: dict[str, KokoroVoice] = Field(default=DEFAULTS["voxhelm_kokoro_models"])
    voxhelm_kokoro_default_voice: str = Field(default=DEFAULTS["voxhelm_kokoro_default_voice"])
    voxhelm_tts_language_voices: dict[str, str] = Field(default=DEFAULTS["voxhelm_tts_language_voices"])
    voxhelm_espeak_library: str = Field(default=DEFAULTS["voxhelm_espeak_library"])
    voxhelm_kokoro_artifacts: list[PinnedArtifact] = Field(default=DEFAULTS["voxhelm_kokoro_artifacts"])
    voxhelm_wyoming_stt_host: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_host"])
    voxhelm_wyoming_stt_port: int = Field(default=DEFAULTS["voxhelm_wyoming_stt_port"])
    voxhelm_wyoming_stt_backend: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_backend"])
    voxhelm_wyoming_stt_model: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_model"])
    voxhelm_wyoming_stt_language: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_language"])
    voxhelm_wyoming_stt_languages: list[str] = Field(default=DEFAULTS["voxhelm_wyoming_stt_languages"])
    voxhelm_wyoming_stt_prompt: str = Field(default=DEFAULTS["voxhelm_wyoming_stt_prompt"])
    voxhelm_wyoming_stt_normalize_transcript: bool = Field(default=DEFAULTS["voxhelm_wyoming_stt_normalize_transcript"])
    voxhelm_wyoming_samples_per_chunk: int = Field(default=DEFAULTS["voxhelm_wyoming_samples_per_chunk"])
    voxhelm_lane_scheduler_enabled: bool = Field(default=DEFAULTS["voxhelm_lane_scheduler_enabled"])
    voxhelm_lane_scheduler_dir: str = Field(default=DEFAULTS["voxhelm_lane_scheduler_dir"])
    voxhelm_lane_scheduler_stale_seconds: int = Field(default=DEFAULTS["voxhelm_lane_scheduler_stale_seconds"])
    voxhelm_lane_scheduler_interactive_slots: int = Field(default=DEFAULTS["voxhelm_lane_scheduler_interactive_slots"])
    voxhelm_lane_scheduler_non_interactive_slots: int = Field(
        default=DEFAULTS["voxhelm_lane_scheduler_non_interactive_slots"]
    )
    voxhelm_artifact_backend: str = Field(default=DEFAULTS["voxhelm_artifact_backend"])
    voxhelm_artifact_root: str = Field(default=DEFAULTS["voxhelm_artifact_root"])
    voxhelm_artifact_bucket: str = Field(default=DEFAULTS["voxhelm_artifact_bucket"])
    voxhelm_artifact_prefix: str = Field(default=DEFAULTS["voxhelm_artifact_prefix"])
    voxhelm_artifact_s3_endpoint_url: str = Field(default=DEFAULTS["voxhelm_artifact_s3_endpoint_url"])
    voxhelm_artifact_s3_region: str = Field(default=DEFAULTS["voxhelm_artifact_s3_region"])
    voxhelm_artifact_s3_force_path_style: bool = Field(default=DEFAULTS["voxhelm_artifact_s3_force_path_style"])
    voxhelm_bootstrap_operator_username: str = Field(default=DEFAULTS["voxhelm_bootstrap_operator_username"])
    voxhelm_bootstrap_operator_email: str = Field(default=DEFAULTS["voxhelm_bootstrap_operator_email"])
    voxhelm_allowed_hosts: list[str] = Field(default=DEFAULTS["voxhelm_allowed_hosts"])
    voxhelm_csrf_trusted_origins: list[str] = Field(default=DEFAULTS["voxhelm_csrf_trusted_origins"])
    voxhelm_mlx_model: str = Field(default=DEFAULTS["voxhelm_mlx_model"])
    voxhelm_whispercpp_model: str = Field(default=DEFAULTS["voxhelm_whispercpp_model"])
    voxhelm_whispercpp_model_url: str = Field(default=DEFAULTS["voxhelm_whispercpp_model_url"])
    voxhelm_whispercpp_bin: str = Field(default=DEFAULTS["voxhelm_whispercpp_bin"])
    voxhelm_whispercpp_processors: int = Field(default=DEFAULTS["voxhelm_whispercpp_processors"])
    voxhelm_whisperkit_enabled: bool = Field(default=DEFAULTS["voxhelm_whisperkit_enabled"])
    voxhelm_whisperkit_cli_bin: str = Field(default=DEFAULTS["voxhelm_whisperkit_cli_bin"])
    voxhelm_whisperkit_host: str = Field(default=DEFAULTS["voxhelm_whisperkit_host"])
    voxhelm_whisperkit_port: int = Field(default=DEFAULTS["voxhelm_whisperkit_port"])
    voxhelm_whisperkit_base_url: str = Field(default=DEFAULTS["voxhelm_whisperkit_base_url"])
    voxhelm_whisperkit_model: str = Field(default=DEFAULTS["voxhelm_whisperkit_model"])
    voxhelm_whisperkit_audio_encoder_compute_units: str = Field(
        default=DEFAULTS["voxhelm_whisperkit_audio_encoder_compute_units"]
    )
    voxhelm_whisperkit_text_decoder_compute_units: str = Field(
        default=DEFAULTS["voxhelm_whisperkit_text_decoder_compute_units"]
    )
    voxhelm_whisperkit_concurrent_worker_count: int = Field(
        default=DEFAULTS["voxhelm_whisperkit_concurrent_worker_count"]
    )
    voxhelm_whisperkit_chunking_strategy: str = Field(default=DEFAULTS["voxhelm_whisperkit_chunking_strategy"])
    voxhelm_whisperkit_timeout_seconds: int = Field(default=DEFAULTS["voxhelm_whisperkit_timeout_seconds"])
    voxhelm_whisperkit_label: str = Field(default=DEFAULTS["voxhelm_whisperkit_label"])
    voxhelm_whisperkit_plist_path: str = Field(default=DEFAULTS["voxhelm_whisperkit_plist_path"])
    voxhelm_whisperkit_stdout_log: str = Field(default=DEFAULTS["voxhelm_whisperkit_stdout_log"])
    voxhelm_whisperkit_stderr_log: str = Field(default=DEFAULTS["voxhelm_whisperkit_stderr_log"])
    voxhelm_brew_bin: str = Field(default=DEFAULTS["voxhelm_brew_bin"])
    voxhelm_brew_user: str = Field(default=DEFAULTS["voxhelm_brew_user"])
    voxhelm_brew_update: bool = Field(default=DEFAULTS["voxhelm_brew_update"])
    voxhelm_allowed_url_hosts: list[str] = Field(default=DEFAULTS["voxhelm_allowed_url_hosts"])
    voxhelm_trusted_http_hosts: list[str] = Field(default=DEFAULTS["voxhelm_trusted_http_hosts"])
    voxhelm_max_upload_bytes: int = Field(default=DEFAULTS["voxhelm_max_upload_bytes"])
    voxhelm_max_url_download_bytes: int = Field(default=DEFAULTS["voxhelm_max_url_download_bytes"])
    voxhelm_url_fetch_timeout_seconds: int = Field(default=DEFAULTS["voxhelm_url_fetch_timeout_seconds"])
    voxhelm_launchd_label: str = Field(default=DEFAULTS["voxhelm_launchd_label"])
    voxhelm_launchd_plist_path: str = Field(default=DEFAULTS["voxhelm_launchd_plist_path"])
    voxhelm_launchd_path: str = Field(default=DEFAULTS["voxhelm_launchd_path"])
    voxhelm_launchd_keepalive: bool = Field(default=DEFAULTS["voxhelm_launchd_keepalive"])
    voxhelm_launchd_manage_state: bool = Field(default=DEFAULTS["voxhelm_launchd_manage_state"])
    voxhelm_launchd_start_service: bool = Field(default=DEFAULTS["voxhelm_launchd_start_service"])
    voxhelm_launchd_stdout_log: str = Field(default=DEFAULTS["voxhelm_launchd_stdout_log"])
    voxhelm_launchd_stderr_log: str = Field(default=DEFAULTS["voxhelm_launchd_stderr_log"])
    voxhelm_healthcheck_enabled: bool = Field(default=DEFAULTS["voxhelm_healthcheck_enabled"])
    voxhelm_healthcheck_url: str = Field(default=DEFAULTS["voxhelm_healthcheck_url"])
    voxhelm_healthcheck_retries: int = Field(default=DEFAULTS["voxhelm_healthcheck_retries"])
    voxhelm_healthcheck_delay: int = Field(default=DEFAULTS["voxhelm_healthcheck_delay"])

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
        for path in self.source_overrides:
            if path.startswith("/") or os.path.normpath(path) != path or path in (".", "..") or path.startswith("../"):
                raise ValueError("Source overrides must name normalized relative files")
        if self.source_overrides and not self.source_preservation_revision:
            raise ValueError("Source overrides require their exact original revision")
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
        if not self.voxhelm_source_path or not os.path.isdir(self.voxhelm_source_path):
            raise ValueError("Voxhelm controller source directory is unavailable")
        if self.voxhelm_bootstrap_operator_username in ("", "CHANGEME"):
            raise ValueError("Voxhelm bootstrap operator must be configured")
        if self.voxhelm_known_speaker_stt_backend not in ("", "parakeet"):
            raise ValueError("Known-speaker backend must be empty or parakeet")
        if self.voxhelm_transcription_execution_mode.strip().lower() not in ("django_tasks", "remote_pull"):
            raise ValueError("Voxhelm execution mode must be django_tasks or remote_pull")
        if self.voxhelm_diarization_backend.strip().lower() not in ("none", "pyannote"):
            raise ValueError("Voxhelm diarization backend must be none or pyannote")
        if any(not re.fullmatch(r"https?://[^/\s,?#]+", origin) for origin in self.voxhelm_csrf_trusted_origins):
            raise ValueError("CSRF origins must be HTTP(S) origins without a path")
        if not self.voxhelm_piper_voices or not self.voxhelm_piper_default_voice:
            raise ValueError("Voxhelm Piper voices and default must be configured")
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", voice) for voice in self.voxhelm_piper_voices):
            raise ValueError("Piper voices must be literal artifact names")
        for name in (
            "voxhelm_remote_worker_lease_seconds",
            "voxhelm_remote_worker_poll_seconds",
            "voxhelm_remote_worker_max_attempts",
        ):
            if getattr(self, name) <= 0:
                raise ValueError("Remote worker lease, poll and attempts must be positive")
        for name in (
            "voxhelm_source_artifact_retention_seconds",
            "voxhelm_job_metadata_retention_seconds",
            "voxhelm_staged_input_retention_seconds",
            "voxhelm_wyoming_stt_max_audio_seconds",
        ):
            value = getattr(self, name)
            if value != "" and value < 0:
                raise ValueError("Optional retention and audio limits must be nonnegative")
        if self.voxhelm_prune_interval_seconds < 60 or (
            self.voxhelm_prune_daily_time
            and not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", self.voxhelm_prune_daily_time)
        ):
            raise ValueError("Pruning needs a minimum60-second interval and an empty or HH:MM daily time")
        if self.voxhelm_tts_kokoro_enabled:
            if not self.voxhelm_kokoro_models:
                raise ValueError("Enabled Kokoro requires configured voices")
            artifacts = {item.dest for item in self.voxhelm_kokoro_artifacts}
            for model in self.voxhelm_kokoro_models.values():
                if (
                    not model.voicepack_key
                    or not model.phoneme_language
                    or not {model.model_file, model.voicepack_file} <= artifacts
                ):
                    raise ValueError("Kokoro voices require all metadata and provisioned artifacts")
            if (
                self.voxhelm_kokoro_default_voice
                and self.voxhelm_kokoro_default_voice not in self.voxhelm_kokoro_models
            ):
                raise ValueError("Kokoro default must name a configured voice")
        if self.voxhelm_tts_language_routing_enabled:
            if not self.voxhelm_tts_language_voices:
                raise ValueError("Language routing requires a configured language map")
            for voice in self.voxhelm_tts_language_voices.values():
                if voice.startswith("kokoro-") and (
                    not self.voxhelm_tts_kokoro_enabled or voice not in self.voxhelm_kokoro_models
                ):
                    raise ValueError("Routed Kokoro voices must be configured and enabled")
        return self
