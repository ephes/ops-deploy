"""Original remote-worker configuration; credentials travel only on stdin."""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping
from importlib.resources import files
from typing import Any

import jinja2

from .config import PACKAGE, VoxhelmRemoteWorkerConfig

SECRET_DEFAULTS: dict[str, str] = json.loads(files(PACKAGE).joinpath("secret_defaults.json").read_text())


def payload(cfg: VoxhelmRemoteWorkerConfig, secrets: Mapping[str, str]) -> dict[str, Any]:
    data = cfg.model_dump(mode="json")
    if not cfg.voxhelm_remote_worker_enabled:
        return data
    if set(secrets) - set(SECRET_DEFAULTS):
        raise ValueError("Remote worker received an unsupported secret field")
    values = {**data, **SECRET_DEFAULTS, **secrets}
    required = [
        "voxhelm_remote_worker_token",
        "voxhelm_remote_worker_artifact_s3_access_key_id",
        "voxhelm_remote_worker_artifact_s3_secret_access_key",
    ]
    if cfg.voxhelm_remote_worker_diarization_backend.strip().lower() == "pyannote":
        required += ["voxhelm_remote_worker_huggingface_token"]
    for name in SECRET_DEFAULTS:
        value = values[name]
        if not isinstance(value, str) or any(c in value for c in "\x00\r\n"):
            raise ValueError("Remote worker credentials must be single-line strings")
    if any(not values[name].strip() or "CHANGEME" in values[name] for name in required):
        raise ValueError("Remote worker credentials are incomplete")
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters.update(quote=shlex.quote, bool=bool)
    contents = {}
    for path, template, mode, owner, group in [
        (cfg.voxhelm_remote_worker_env_file, "worker.env.j2", 0o640, "root", cfg.voxhelm_remote_worker_service_group),
        (
            cfg.voxhelm_remote_worker_launcher_path,
            "worker-launcher.sh.j2",
            0o755,
            "root",
            cfg.voxhelm_remote_worker_service_group,
        ),
        (cfg.voxhelm_remote_worker_launchd_plist_path, "worker.launchd.plist.j2", 0o644, "root", "wheel"),
    ]:
        if path in contents:
            raise ValueError("Remote worker managed resources overlap")
        text = env.get_template(template).render(values)
        contents[path] = {
            "content": text,
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "mode": mode,
            "owner": owner,
            "group": group,
        }
    data["contents"] = contents
    return data
