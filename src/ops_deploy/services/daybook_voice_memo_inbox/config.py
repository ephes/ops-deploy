"""Original Inbox fixed paths, disabled-first state and runtime budget limits."""

from __future__ import annotations

import json
import math
import re
from importlib.resources import files
from typing import Any, Self

from jinja2 import StrictUndefined, UndefinedError
from jinja2.nativetypes import NativeEnvironment
from pydantic import Field, StrictBool, StrictFloat, StrictInt, model_validator

from ops_deploy.base import RoleConfig

PACKAGE = "ops_deploy.services.daybook_voice_memo_inbox"
DEFAULTS: dict[str, Any] = json.loads(files(PACKAGE).joinpath("defaults.json").read_text())


def resolved_defaults(overrides: dict[str, Any]) -> dict[str, Any]:
    values = {**DEFAULTS, **overrides}
    pending = set(DEFAULTS) - set(overrides)
    env = NativeEnvironment(undefined=StrictUndefined)
    for _ in range(len(pending) + 1):
        remaining = set()
        for key in sorted(pending):
            try:
                value = DEFAULTS[key]
                if isinstance(value, str) and "{{" in value:
                    value = env.from_string(value).render(values)
            except UndefinedError:
                remaining.add(key)
                continue
            values[key] = value
            if "{{" in json.dumps(value):
                remaining.add(key)
        if not remaining:
            return values
        pending = remaining
    raise ValueError("Inbox default references could not be resolved")


class DaybookInboxConfig(RoleConfig):
    daybook_voice_memo_inbox_enabled: StrictBool = Field(default=DEFAULTS["daybook_voice_memo_inbox_enabled"])
    daybook_voice_memo_inbox_launchd_enabled: StrictBool = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_launchd_enabled"]
    )
    daybook_voice_memo_inbox_activation_confirmation: str = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_activation_confirmation"], repr=False
    )
    daybook_voice_memo_inbox_activation_phrase: str = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_activation_phrase"]
    )
    daybook_voice_memo_inbox_service_user: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_service_user"])
    daybook_voice_memo_inbox_service_group: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_service_group"])
    daybook_voice_memo_inbox_service_home: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_service_home"])
    daybook_voice_memo_inbox_system_group: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_system_group"])
    daybook_voice_memo_inbox_repo_bundle_src: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_repo_bundle_src"])
    daybook_voice_memo_inbox_repo_ref: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_repo_ref"])
    daybook_voice_memo_inbox_install_root: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_install_root"])
    daybook_voice_memo_inbox_checkout_path: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_checkout_path"])
    daybook_voice_memo_inbox_repo_bundle_path: str = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_repo_bundle_path"]
    )
    daybook_voice_memo_inbox_uv_bin: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_uv_bin"])
    daybook_voice_memo_inbox_python_version: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_python_version"])
    daybook_voice_memo_inbox_python_install_dir: str = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_python_install_dir"]
    )
    daybook_voice_memo_inbox_python: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_python"])
    daybook_voice_memo_inbox_source_dir: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_source_dir"])
    daybook_voice_memo_inbox_database_name: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_database_name"])
    daybook_voice_memo_inbox_runtime_dir: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_runtime_dir"])
    daybook_voice_memo_inbox_state_path: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_state_path"])
    daybook_voice_memo_inbox_lock_path: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_lock_path"])
    daybook_voice_memo_inbox_log_dir: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_log_dir"])
    daybook_voice_memo_inbox_stdout_log: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_stdout_log"])
    daybook_voice_memo_inbox_stderr_log: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_stderr_log"])
    daybook_voice_memo_inbox_long_stdout_log: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_long_stdout_log"])
    daybook_voice_memo_inbox_long_stderr_log: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_long_stderr_log"])
    daybook_voice_memo_inbox_credential_dir: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_credential_dir"])
    daybook_voice_memo_inbox_credential_path: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_credential_path"])
    daybook_voice_memo_inbox_policy_path: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_policy_path"])
    daybook_voice_memo_inbox_activation_marker_path: str = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_activation_marker_path"]
    )
    daybook_voice_memo_inbox_activation_proof_path: str = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_activation_proof_path"]
    )
    daybook_voice_memo_inbox_launchd_label: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_launchd_label"])
    daybook_voice_memo_inbox_plist_path: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_plist_path"])
    daybook_voice_memo_inbox_interval_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_interval_seconds"]
    )
    daybook_voice_memo_inbox_activation_status_retries: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_activation_status_retries"]
    )
    daybook_voice_memo_inbox_activation_status_delay_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_activation_status_delay_seconds"]
    )
    daybook_voice_memo_inbox_long_launchd_label: str = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_launchd_label"]
    )
    daybook_voice_memo_inbox_long_plist_path: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_long_plist_path"])
    daybook_voice_memo_inbox_long_interval_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_interval_seconds"]
    )
    daybook_voice_memo_inbox_bucket: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_bucket"])
    daybook_voice_memo_inbox_prefix: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_prefix"])
    daybook_voice_memo_inbox_s3_endpoint_url: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_s3_endpoint_url"])
    daybook_voice_memo_inbox_s3_region: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_s3_region"])
    daybook_voice_memo_inbox_voxhelm_endpoint: str = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_voxhelm_endpoint"]
    )
    daybook_voice_memo_inbox_model: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_model"])
    daybook_voice_memo_inbox_language: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_language"])
    daybook_voice_memo_inbox_prompt: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_prompt"], repr=False)
    daybook_voice_memo_inbox_min_stable_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_min_stable_seconds"]
    )
    daybook_voice_memo_inbox_max_audio_bytes: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_max_audio_bytes"]
    )
    daybook_voice_memo_inbox_max_duration_seconds: StrictFloat = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_max_duration_seconds"]
    )
    daybook_voice_memo_inbox_duration_tolerance_seconds: StrictFloat = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_duration_tolerance_seconds"]
    )
    daybook_voice_memo_inbox_ffprobe_path: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_ffprobe_path"])
    daybook_voice_memo_inbox_ffmpeg_path: str = Field(default=DEFAULTS["daybook_voice_memo_inbox_ffmpeg_path"])
    daybook_voice_memo_inbox_request_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_request_timeout_seconds"]
    )
    daybook_voice_memo_inbox_long_lane_enabled: StrictBool = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_lane_enabled"]
    )
    daybook_voice_memo_inbox_long_label_enabled: StrictBool = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_label_enabled"]
    )
    daybook_voice_memo_inbox_long_max_duration_seconds: StrictFloat = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_max_duration_seconds"]
    )
    daybook_voice_memo_inbox_long_max_audio_bytes: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_max_audio_bytes"]
    )
    daybook_voice_memo_inbox_long_realtime_factor: StrictFloat = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_realtime_factor"]
    )
    daybook_voice_memo_inbox_long_queue_slack_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_queue_slack_seconds"]
    )
    daybook_voice_memo_inbox_long_validation_timeout_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_validation_timeout_seconds"]
    )
    daybook_voice_memo_inbox_long_max_attempts: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_max_attempts"]
    )
    daybook_voice_memo_inbox_long_queue_per_run: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_queue_per_run"]
    )
    daybook_voice_memo_inbox_long_min_gap_seconds: StrictInt = Field(
        default=DEFAULTS["daybook_voice_memo_inbox_long_min_gap_seconds"]
    )

    @model_validator(mode="before")
    @classmethod
    def original_defaults(cls, values: Any) -> Any:
        return resolved_defaults(values) if isinstance(values, dict) else values

    @model_validator(mode="after")
    def original_contract(self) -> Self:
        if not self.daybook_voice_memo_inbox_enabled:
            return self
        v = {key.removeprefix("daybook_voice_memo_inbox_"): value for key, value in self.model_dump().items()}
        user = v["service_user"]
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", user) or user == "CHANGEME":
            raise ValueError("Inbox service user is invalid")
        expected = {
            "service_group": "staff",
            "service_home": "/Users/" + user,
            "system_group": "wheel",
            "install_root": "/Library/Application Support/Daybook/voice-memo-inbox",
            "uv_bin": "/opt/homebrew/bin/uv",
            "python_install_dir": "/Library/Application Support/Daybook/python",
            "database_name": "CloudRecordings.db",
            "launchd_label": "de.wersdoerfer.daybook.voice-memo-inbox",
            "long_launchd_label": "de.wersdoerfer.daybook.voice-memo-inbox-long",
            "ffprobe_path": "/opt/homebrew/bin/ffprobe",
            "ffmpeg_path": "/opt/homebrew/bin/ffmpeg",
            "voxhelm_endpoint": "http://127.0.0.1:8787/v1/audio/transcriptions",
            "prefix": "Inbox/Voice Memos",
            "interval_seconds": 300,
            "activation_status_retries": 72,
            "activation_status_delay_seconds": 5,
            "activation_phrase": "BASELINE ALL CURRENT VOICE MEMOS AS HISTORICAL",
            "long_interval_seconds": 600,
            "duration_tolerance_seconds": 1.0,
        }
        home, install = v["service_home"], v["install_root"]
        expected.update(
            {
                "checkout_path": install + "/daybook",
                "repo_bundle_path": install + "/source.bundle",
                "python": v["checkout_path"] + "/.venv/bin/python",
                "source_dir": home + "/Library/Group Containers/group.com.apple.VoiceMemos.shared/Recordings",
                "runtime_dir": home + "/.local/state/daybook/voice-memo-inbox",
                "policy_path": install + "/policy.json",
                "activation_marker_path": install + "/activation.json",
                "activation_proof_path": install + "/activation-proven.json",
                "credential_dir": home + "/.config/daybook-voice-memo-inbox",
            }
        )
        runtime = v["runtime_dir"]
        expected.update(
            {
                "state_path": runtime + "/ledger.json",
                "lock_path": runtime + "/ingest.lock",
                "log_dir": runtime + "/logs",
                "stdout_log": v["log_dir"] + "/ingest.log",
                "stderr_log": v["log_dir"] + "/ingest.err.log",
                "long_stdout_log": v["log_dir"] + "/ingest-long.log",
                "long_stderr_log": v["log_dir"] + "/ingest-long.err.log",
                "credential_path": v["credential_dir"] + "/credentials.json",
                "plist_path": home + "/Library/LaunchAgents/" + v["launchd_label"] + ".plist",
                "long_plist_path": home + "/Library/LaunchAgents/" + v["long_launchd_label"] + ".plist",
            }
        )
        if any(v[key] != value for key, value in expected.items()):
            raise ValueError("Inbox requires the original fixed paths and schedule contracts")
        if (
            not re.fullmatch(r"[0-9a-f]{40}", v["repo_ref"])
            or not re.fullmatch(r"3\.14\.[0-9]+", v["python_version"])
            or not v["repo_bundle_src"].startswith("/")
            or any(c in v["repo_bundle_src"] for c in "\0\r\n")
        ):
            raise ValueError("Inbox source and interpreter declarations are invalid")
        if not v["bucket"] or v["bucket"] == "CHANGEME" or not re.match(r"^https?://[^/\s]+", v["s3_endpoint_url"]):
            raise ValueError("Inbox storage declaration is incomplete")
        limits = {
            "min_stable_seconds": (120, math.inf),
            "max_audio_bytes": (1, 16777216),
            "max_duration_seconds": (0, 180),
            "request_timeout_seconds": (1, 299),
            "long_max_duration_seconds": (180, 3600),
            "long_max_audio_bytes": (16777216, 26214399),
            "long_realtime_factor": (0.02, 4),
            "long_queue_slack_seconds": (120, 900),
            "long_validation_timeout_seconds": (30, 120),
            "long_max_attempts": (1, 10),
            "long_queue_per_run": (1, 5),
            "long_min_gap_seconds": (431, 900),
        }
        for key, (minimum, maximum) in limits.items():
            value = v[key]
            if not math.isfinite(value) or not minimum <= value <= maximum:
                raise ValueError("Inbox runtime budgets are outside the original limits")
        if v["max_duration_seconds"] <= 0 or v["long_max_duration_seconds"] <= 180:
            raise ValueError("Inbox duration ranges must remain nonempty")
        if (
            v["long_max_audio_bytes"] < v["max_audio_bytes"]
            or math.ceil(v["long_max_duration_seconds"] * v["long_realtime_factor"]) + v["long_queue_slack_seconds"]
            > 2700
        ):
            raise ValueError("Inbox long lane exceeds its original admission deadline")
        if v["launchd_enabled"] and v["activation_confirmation"] != v["activation_phrase"]:
            raise ValueError("Inbox activation requires the original historical baseline phrase")
        return self
