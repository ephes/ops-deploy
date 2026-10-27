"""Voxhelm's original environment, launchers and launchd templates."""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping
from importlib.resources import files
from typing import Any

import jinja2

from .config import PACKAGE, VoxhelmConfig

SECRET_DEFAULTS: dict[str, str] = json.loads(files(PACKAGE).joinpath("secret_defaults.json").read_text())


def payload(cfg: VoxhelmConfig, secrets: Mapping[str, str]) -> dict[str, Any]:
    if set(secrets) - set(SECRET_DEFAULTS):
        raise ValueError("Voxhelm received an unsupported secret field")
    values = {**cfg.model_dump(mode="json"), **SECRET_DEFAULTS, **secrets}
    required = ["voxhelm_django_secret_key", "voxhelm_bearer_tokens_env", "voxhelm_bootstrap_operator_password"]
    if cfg.voxhelm_transcription_execution_mode.strip().lower() == "remote_pull":
        required += [
            "voxhelm_worker_tokens_env",
            "voxhelm_artifact_s3_access_key_id",
            "voxhelm_artifact_s3_secret_access_key",
        ]
        if (
            cfg.voxhelm_artifact_backend.strip().lower() != "s3"
            or not cfg.voxhelm_artifact_bucket
            or not cfg.voxhelm_artifact_s3_endpoint_url
        ):
            raise ValueError("Remote-pull transcription requires shared S3 artifacts")
    if cfg.voxhelm_diarization_backend.strip().lower() == "pyannote":
        required += ["voxhelm_huggingface_token"]
        if not cfg.voxhelm_pyannote_model:
            raise ValueError("Pyannote diarization requires its model identifier")
    for name in SECRET_DEFAULTS:
        value = values[name]
        if not isinstance(value, str) or any(c in value for c in "\x00\r\n"):
            raise ValueError("Voxhelm credentials must be single-line strings")
    if any(not values[name].strip() or "CHANGEME" in values[name] for name in required):
        raise ValueError("Voxhelm credentials are incomplete")
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters.update(
        quote=shlex.quote, bool=bool, dict2items=lambda value: [{"key": k, "value": v} for k, v in value.items()]
    )
    contents: dict[str, dict[str, Any]] = {}

    def resource(path: str, template: str, mode: int, **extra: Any) -> None:
        if path in contents:
            raise ValueError("Voxhelm managed resources overlap")
        text = env.get_template(template).render({**values, **extra})
        contents[path] = {
            "content": text,
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "mode": mode,
            "owner": "root",
            "group": "wheel",
        }

    resource(cfg.voxhelm_config_dir + "/voxhelm.env", "voxhelm.env.j2", 0o640)
    units = []
    for name, enabled, label, plist, script, stdout, stderr, template in [
        (
            "api",
            True,
            cfg.voxhelm_launchd_label,
            cfg.voxhelm_launchd_plist_path,
            cfg.voxhelm_start_script_path,
            cfg.voxhelm_launchd_stdout_log,
            cfg.voxhelm_launchd_stderr_log,
            "start.sh.j2",
        ),
        (
            "worker",
            cfg.voxhelm_worker_enabled,
            cfg.voxhelm_worker_label,
            cfg.voxhelm_worker_plist_path,
            cfg.voxhelm_worker_script_path,
            cfg.voxhelm_worker_stdout_log,
            cfg.voxhelm_worker_stderr_log,
            "worker.sh.j2",
        ),
        (
            "wyoming",
            cfg.voxhelm_wyoming_stt_enabled,
            cfg.voxhelm_wyoming_stt_label,
            cfg.voxhelm_wyoming_stt_plist_path,
            cfg.voxhelm_wyoming_stt_script_path,
            cfg.voxhelm_wyoming_stt_stdout_log,
            cfg.voxhelm_wyoming_stt_stderr_log,
            "wyoming-stt.sh.j2",
        ),
        (
            "whisperkit",
            cfg.voxhelm_whisperkit_enabled,
            cfg.voxhelm_whisperkit_label,
            cfg.voxhelm_whisperkit_plist_path,
            cfg.voxhelm_whisperkit_script_path,
            cfg.voxhelm_whisperkit_stdout_log,
            cfg.voxhelm_whisperkit_stderr_log,
            "whisperkit.sh.j2",
        ),
    ]:
        if not enabled:
            continue
        resource(script, template, 0o755)
        resource(
            plist,
            "voxhelm.launchd.plist.j2",
            0o644,
            voxhelm_launchd_label=label,
            voxhelm_start_script_path=script,
            voxhelm_launchd_stdout_log=stdout,
            voxhelm_launchd_stderr_log=stderr,
        )
        units.append(
            {
                "name": name,
                "label": label,
                "plist": plist,
                "script": script,
                "stdout": stdout,
                "stderr": stderr,
                "start": cfg.voxhelm_launchd_start_service,
                "periodic": False,
            }
        )
    if cfg.voxhelm_prune_enabled:
        resource(cfg.voxhelm_prune_script_path, "prune.sh.j2", 0o755)
        resource(cfg.voxhelm_prune_plist_path, "voxhelm-prune.launchd.plist.j2", 0o644)
        units.append(
            {
                "name": "prune",
                "label": cfg.voxhelm_prune_label,
                "plist": cfg.voxhelm_prune_plist_path,
                "script": cfg.voxhelm_prune_script_path,
                "stdout": cfg.voxhelm_prune_stdout_log,
                "stderr": cfg.voxhelm_prune_stderr_log,
                "start": False,
                "periodic": True,
            }
        )
    data = cfg.model_dump(mode="json", exclude={"source_overrides"})
    data.update(
        contents=contents,
        units=units,
        bootstrap={
            "username": cfg.voxhelm_bootstrap_operator_username,
            "email": cfg.voxhelm_bootstrap_operator_email,
            "password": values["voxhelm_bootstrap_operator_password"],
        },
    )
    return data
