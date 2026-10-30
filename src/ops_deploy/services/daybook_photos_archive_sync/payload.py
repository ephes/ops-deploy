"""Controller Main bundle admission; no library, source-folder or ledger reads."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime.inspect import daybook_code_manifest

from .config import DaybookPhotosArchiveSyncConfig
from .render import render_resources


def payload(cfg: DaybookPhotosArchiveSyncConfig, source: SourceTree, bundle: Path, uid: int) -> dict[str, Any]:
    revision = cfg.daybook_photos_archive_sync_repo_ref
    manifest = daybook_code_manifest(source, revision)
    if not {"pyproject.toml", "uv.lock"}.issubset(manifest):
        raise ValueError("Archive synchronization requires its original frozen source declarations")
    if str(bundle) != cfg.daybook_photos_archive_sync_repo_bundle_src or not bundle.is_absolute():
        raise ValueError("Archive synchronization requires the exact controller-prepared Main bundle")
    result = subprocess.run(["/usr/bin/git", "bundle", "list-heads", str(bundle)], capture_output=True, timeout=120)
    if result.returncode or result.stdout.decode("ascii", "replace").strip() != revision + " refs/heads/main":
        raise ValueError("Archive synchronization bundle must carry one exact Main revision")
    prefix = "daybook_photos_archive_sync_"
    data = {key.removeprefix(prefix): value for key, value in cfg.model_dump().items() if key.startswith(prefix)}
    data.update(
        uid=uid,
        source_hashes=manifest,
        bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
        resources=render_resources(cfg),
    )
    return data
