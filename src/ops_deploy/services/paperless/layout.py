"""Original Paperless account/storage layout without healthy ownership churn."""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Link
from pyinfra.operations import files, server

from ops_deploy.helpers import mark_read_only

from .config import PaperlessConfig


def require_storage(cfg: PaperlessConfig) -> None:
    if cfg.verify_storage_mount:
        mount = str(PurePosixPath(cfg.external_storage_root).parent)
        mark_read_only(
            server.shell(
                name="Require Paperless encrypted storage mount",
                commands=[f"findmnt --mountpoint {shlex.quote(mount)} >/dev/null"],
            )
        )


def account(cfg: PaperlessConfig) -> OperationMeta:
    server.group(name="Ensure Paperless group", group=cfg.group, system=False)
    return server.user(
        name="Ensure Paperless account",
        user=cfg.username,
        group=cfg.group,
        home=cfg.home_path,
        shell="/bin/bash",
        create_home=True,
        system=False,
    )


def link(cfg: PaperlessConfig, path: str, target: str) -> OperationMeta:
    existing = host.get_fact(Link, path=path)
    # Preserve an unchanged historical root-owned symlink. New links retain the
    # original role's service ownership; do not force-replace real directories.
    unchanged = isinstance(existing, dict) and existing.get("link_target") == target
    return files.link(
        name=f"Ensure Paperless link {path}",
        path=path,
        target=target,
        user=None if unchanged else cfg.username,
        group=None if unchanged else cfg.group,
    )


def directories(cfg: PaperlessConfig) -> None:
    for path in (
        cfg.site_root,
        f"{cfg.site_root}/bin",
        f"{cfg.site_root}/staticfiles",
        f"{cfg.site_root}/logs",
        f"{cfg.home_path}/.config",
    ):
        files.directory(
            name=f"Ensure Paperless directory {path}", path=path, user=cfg.username, group=cfg.group, mode="0755"
        )
    children = (
        "",
        "media",
        "media/documents",
        "media/documents/originals",
        "media/documents/thumbnails",
        "data",
        "consume",
        "export",
        "backup",
        "tmp",
    )
    for child in children:
        path = cfg.external_storage_root + ("/" + child if child else "")
        # The original scanner task finally makes consume0775. Converge that
        # final mode directly instead of0755→0775 on every healthy deployment.
        mode = "0775" if child == "consume" and cfg.scanner_enabled else "0755"
        files.directory(
            name=f"Ensure Paperless storage {child or 'root'}", path=path, user=cfg.username, group=cfg.group, mode=mode
        )
    if cfg.manage_symlinks:
        for child in ("media", "data", "consume", "export"):
            link(cfg, f"{cfg.site_root}/{child}", f"{cfg.external_storage_root}/{child}")
    if cfg.manage_tmpdir:
        files.directory(
            name="Ensure Paperless processing temp directory",
            path=cfg.temp_dir,
            user=cfg.username,
            group=cfg.group,
            mode="0755",
        )
