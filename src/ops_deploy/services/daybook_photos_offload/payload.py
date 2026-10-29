"""Original Photos paths, generated code and controller-bound local Main bundle."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime.inspect import daybook_code_manifest

from .config import DaybookPhotosOffloadConfig
from .render import resources


def component_payload(cfg: DaybookPhotosOffloadConfig, source: SourceTree, bundle: Path, *, uid: int) -> dict[str, Any]:
    if not cfg.daybook_photos_offload_enabled or type(uid) is not int or uid <= 0:
        raise ValueError("Photos requires its enabled original non-root GUI account")
    revision = cfg.daybook_photos_offload_repo_ref
    manifest = daybook_code_manifest(source, revision)
    if not {"pyproject.toml", "uv.lock"}.issubset(manifest):
        raise ValueError("Photos requires original frozen dependency declarations")
    if str(bundle) != cfg.daybook_photos_offload_repo_bundle_src or not bundle.is_absolute():
        raise ValueError("Photos bundle must be the exact controller-prepared source")
    result = subprocess.run(["/usr/bin/git", "bundle", "list-heads", str(bundle)], capture_output=True, timeout=120)
    if result.returncode or result.stdout.decode("ascii", "replace").strip() != revision + " refs/heads/main":
        raise ValueError("Photos bundle must carry only its original exact Main commit")
    user = cfg.daybook_photos_offload_service_user
    group = cfg.daybook_photos_offload_service_group
    home = cfg.daybook_photos_offload_service_home

    def row(path: str, mode: int) -> dict[str, Any]:
        return {"path": path, "owner": user, "group": group, "mode": mode}

    return {
        "user": user,
        "group": group,
        "home": home,
        "uid": uid,
        "system_group": cfg.daybook_photos_offload_system_group,
        "path": cfg.daybook_photos_offload_path,
        "checkout": cfg.daybook_photos_offload_checkout_path,
        "attestation": cfg.daybook_photos_offload_checkout_attestation_path,
        "bundle": cfg.daybook_photos_offload_repo_bundle_path,
        "revision": revision,
        "bundle_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
        "uv_bin": cfg.daybook_photos_offload_uv_bin,
        "python_version": cfg.daybook_photos_offload_python_version,
        "library": cfg.daybook_photos_offload_library_path,
        "label": cfg.daybook_photos_offload_launchd_label,
        "plist": cfg.daybook_photos_offload_launchd_plist_path,
        "launchd_enabled": cfg.daybook_photos_offload_launchd_enabled,
        "directories": [
            row(cfg.daybook_photos_offload_runtime_dir, 0o700),
            row(cfg.daybook_photos_offload_config_dir, 0o700),
            row(home + "/Library/LaunchAgents", 0o755),
            row(cfg.daybook_photos_offload_log_dir, 0o700),
        ],
        "logs": [row(cfg.daybook_photos_offload_stdout_log, 0o600), row(cfg.daybook_photos_offload_stderr_log, 0o600)],
        "resources": [asdict(resource) for resource in resources(cfg)],
    }
