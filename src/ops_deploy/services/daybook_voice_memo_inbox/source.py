"""Bind the Inbox source stage to the original protected root interpreter layout.

Controller code and bundle checks only. This module neither runs an application
nor opens an importer source, ledger, activation marker or credential body.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime.inspect import daybook_code_manifest
from ops_deploy.services.daybook_sessions.source import verify_controller_bundle

from .config import DaybookInboxConfig


def source_payload(cfg: DaybookInboxConfig, source: SourceTree, bundle: Path, *, uid: int) -> dict[str, Any]:
    """Prepare code-only input for explicit managed Inbox source/Python work.

    uid is the original service-account lookup result. The common native root
    observer derives its Python tree from checkout.parent.parent / 'python';
    bind that exact declaration, rather than accepting another root prefix.
    """
    if type(uid) is not int or uid <= 0:
        raise ValueError("Inbox requires the existing non-root GUI account uid")
    if not cfg.daybook_voice_memo_inbox_enabled:
        raise ValueError("Disabled Inbox source requires no preparation")
    revision = cfg.daybook_voice_memo_inbox_repo_ref
    checkout = Path(cfg.daybook_voice_memo_inbox_checkout_path)
    if Path(cfg.daybook_voice_memo_inbox_python_install_dir) != checkout.parent.parent / "python":
        raise ValueError("Inbox root Python tree must retain its original derivation")
    manifest = daybook_code_manifest(source, revision)
    if not {"pyproject.toml", "uv.lock"}.issubset(manifest):
        raise ValueError("Inbox source requires its frozen dependency declarations")
    verify_controller_bundle(bundle, revision)
    return {
        "owner": "root",
        "user": cfg.daybook_voice_memo_inbox_service_user,
        "group": cfg.daybook_voice_memo_inbox_service_group,
        "uid": uid,
        "label": cfg.daybook_voice_memo_inbox_launchd_label,
        "long_label": cfg.daybook_voice_memo_inbox_long_launchd_label,
        "checkout": str(checkout),
        "revision": revision,
        "source_hashes": manifest,
        "bundle": cfg.daybook_voice_memo_inbox_repo_bundle_path,
        "python": cfg.daybook_voice_memo_inbox_python,
        "python_version": cfg.daybook_voice_memo_inbox_python_version,
        "python_install_dir": cfg.daybook_voice_memo_inbox_python_install_dir,
        "uv_bin": cfg.daybook_voice_memo_inbox_uv_bin,
        "ffprobe": cfg.daybook_voice_memo_inbox_ffprobe_path,
        "ffmpeg": cfg.daybook_voice_memo_inbox_ffmpeg_path,
    }
