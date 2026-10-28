"""Private stdin resource expectations from the exact original Inbox declaration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from typing import Any

from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig
from ops_deploy.services.daybook_operations_runtime.decision import InstalledRuntime

from .composition import final_resources
from .config import DaybookInboxConfig
from .layout import directories, logs
from .render import resources


def resource_payload(
    cfg: DaybookInboxConfig,
    secrets: Mapping[str, str],
    *,
    uid: int,
    runtime: DaybookRuntimeConfig | None = None,
    installed: InstalledRuntime | None = None,
) -> dict[str, Any]:
    """No secret digest/repr: plaintext expectations are for protected stdin only."""
    if type(uid) is not int or uid <= 0:
        raise ValueError("Inbox resources require the original GUI account uid")

    def rows(values: Any) -> list[dict[str, Any]]:
        return [
            {
                "path": row.path,
                "owner": row.owner,
                "group": row.group,
                "mode": row.mode,
                "content": row.content.reveal().decode(),
            }
            for row in values
        ]

    return {
        "user": cfg.daybook_voice_memo_inbox_service_user,
        "uid": uid,
        "label": cfg.daybook_voice_memo_inbox_launchd_label,
        "long_label": cfg.daybook_voice_memo_inbox_long_launchd_label,
        "directories": [asdict(row) for row in directories(cfg)],
        "logs": [asdict(row) for row in logs(cfg)],
        "resources": rows(resources(cfg, secrets)),
        "final_resources": rows(final_resources(cfg, secrets, runtime=runtime, installed=installed)),
        "retired_long_plist": (
            cfg.daybook_voice_memo_inbox_long_plist_path
            if cfg.daybook_voice_memo_inbox_enabled and not cfg.daybook_voice_memo_inbox_long_label_enabled
            else None
        ),
    }
