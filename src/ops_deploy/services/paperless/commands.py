"""Paperless-specific embedded host resources and protected stdin payloads."""

from __future__ import annotations

import base64
import json
import shlex
from importlib.resources import files

from .config import PaperlessConfig, PaperlessCredentials, canonical_path, validate_credentials
from .index_contract import expected_index_sentinels


def host_command(script: str, *, interpreter: str = "python3") -> str:
    if script not in {
        "index_state",
        "reindex",
        "scanner_password",
        "scanner_acl",
        "scanner_mount",
        "scanner_ssh",
        "runtime_state",
        "python_assets",
        "release",
    }:
        raise ValueError("unknown Paperless host helper")
    if interpreter != "python3":
        canonical_path(interpreter)
    source = files("ops_deploy.services.paperless").joinpath(f"files/{script}.py").read_bytes()
    encoded = base64.b64encode(source).decode("ascii")
    loader = f"import base64;exec(compile(base64.b64decode('{encoded}'),'<paperless-host>','exec'))"
    return shlex.join([interpreter, "-I", "-B", "-c", loader])


def index_payload(cfg: PaperlessConfig, document_count: int, triggers: tuple[str, ...] = ()) -> str:
    if cfg.force_reindex and "force" not in triggers:
        triggers = (*triggers, "force")
    return json.dumps(
        {
            "directory": f"{cfg.external_storage_root}/data/index",
            "document_count": document_count,
            "expected": expected_index_sentinels(cfg.version, cfg.ocr_language),
            "triggers": triggers,
        }
    )


def reindex_payload(cfg: PaperlessConfig) -> str:
    return json.dumps(
        {
            "username": cfg.username,
            "service_name": cfg.service_name,
            "env_file": f"{cfg.site_root}/.env",
            "python_bin": f"{cfg.site_root}/.venv/bin/python",
            "manage_dir": f"{cfg.site_root}/paperless-ngx/src",
        }
    )


def scanner_password_payload(cfg: PaperlessConfig, credentials: PaperlessCredentials, *, apply: bool) -> str:
    """Secret-bearing result: use stdin_arguments/StdinLines; never log it."""
    validate_credentials(cfg, credentials)
    return json.dumps(
        {"username": cfg.scanner_username, "password": credentials.scanner_password.get_secret_value(), "apply": apply}
    )


def scanner_acl_payload(cfg: PaperlessConfig, *, apply: bool) -> str:
    return json.dumps(
        {"directory": f"{cfg.external_storage_root}/consume", "username": cfg.scanner_username, "apply": apply}
    )
