"""Exact original dormant launcher and private plist; no runtime execution."""

from __future__ import annotations

import shlex
from importlib.resources import files

from jinja2 import Environment, StrictUndefined

from .config import PACKAGE, DaybookPhotosArchiveSyncConfig


def render_resources(cfg: DaybookPhotosArchiveSyncConfig) -> list[dict[str, str | int]]:
    environment = Environment(undefined=StrictUndefined, keep_trailing_newline=True)
    environment.filters["quote"] = shlex.quote
    environment.filters["bool"] = bool
    rows: list[dict[str, str | int]] = []
    for template, path, mode in (
        ("archive-sync.sh.j2", cfg.daybook_photos_archive_sync_launcher_path, 0o700),
        ("archive-sync.plist.j2", cfg.daybook_photos_archive_sync_launchd_plist_path, 0o600),
    ):
        body = environment.from_string(files(PACKAGE).joinpath("templates/" + template).read_text()).render(
            cfg.model_dump()
        )
        rows.append(
            {
                "path": path,
                "owner": cfg.daybook_photos_archive_sync_service_user,
                "group": cfg.daybook_photos_archive_sync_service_group,
                "mode": mode,
                "content": body,
            }
        )
    return rows
