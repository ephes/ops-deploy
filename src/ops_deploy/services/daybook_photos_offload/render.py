"""Exact original launcher/plist text; no library or ledger access."""

from __future__ import annotations

import shlex
from dataclasses import dataclass

import jinja2

from .config import PACKAGE, DaybookPhotosOffloadConfig


@dataclass(frozen=True)
class PhotoResource:
    path: str
    owner: str
    group: str
    mode: int
    content: str


def render_template(name: str, cfg: DaybookPhotosOffloadConfig) -> str:
    if name not in {"reconcile.sh.j2", "photos-offload.launchd.plist.j2"}:
        raise ValueError("Photos offload template must be an original packaged resource")
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["quote"] = shlex.quote
    return env.get_template(name).render(cfg.model_dump(mode="json"))


def resources(cfg: DaybookPhotosOffloadConfig) -> tuple[PhotoResource, ...]:
    if not cfg.daybook_photos_offload_enabled:
        return ()
    user, group = cfg.daybook_photos_offload_service_user, cfg.daybook_photos_offload_service_group
    return (
        PhotoResource(
            cfg.daybook_photos_offload_launcher_path, user, group, 0o700, render_template("reconcile.sh.j2", cfg)
        ),
        PhotoResource(
            cfg.daybook_photos_offload_launchd_plist_path,
            user,
            group,
            0o644,
            render_template("photos-offload.launchd.plist.j2", cfg),
        ),
    )
