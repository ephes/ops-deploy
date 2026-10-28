"""Byte-preserved role templates with an explicit typed per-policy context."""

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import BackupConfig, MailReplicationConfig, MinioArchiveConfig, SyncoidConfig, UsbReplicationConfig

ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)
ENV.filters.update(
    bool=bool,
    ternary=lambda condition, yes, no: yes if condition else no,
    regex_replace=lambda value, pattern, replacement: re.sub(pattern, replacement, value),
)


def context(cfg: BackupConfig) -> dict[str, object]:
    values = cfg.model_dump(exclude_none=True)
    if isinstance(cfg, UsbReplicationConfig):
        prefix = "zfs_usb_replication"
        values.update(
            state_path=cfg.state_path or cfg.state_dir + "/status.json",
            attestation_dir=cfg.attestation_dir or cfg.state_dir + "/attestations",
            anchor_state_path=cfg.anchor_state_path or cfg.state_dir + "/anchors.json",
        )
    elif isinstance(cfg, SyncoidConfig):
        prefix = "zfs_syncoid_replication"
    elif isinstance(cfg, MinioArchiveConfig):
        prefix = "minio_offsite_replication"
        values.update(
            status_file=cfg.status_file or cfg.status_dir + "/status.json",
            latest_marker_file=cfg.latest_marker_file or cfg.status_dir + "/latest-archive.marker",
        )
    elif isinstance(cfg, MailReplicationConfig):
        prefix = "mail_offsite_replication"
        values.update(
            status_file=cfg.status_file or cfg.status_dir + "/status.json",
            latest_marker_file=cfg.latest_marker_file or cfg.status_dir + "/latest-success.marker",
        )
    else:
        raise TypeError("unknown typed backup policy")
    return {prefix + "_" + key: value for key, value in values.items()}


def render(cfg: BackupConfig, resource: str) -> str:
    return ENV.get_template(resource + ".j2").render(**context(cfg))
