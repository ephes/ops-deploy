"""Configure the original append-only MinIO archive pull, without running it."""

from pydantic import SecretStr
from pyinfra.api import deploy

from .common import key_input, prerequisites, resource, timer
from .config import MinioArchiveConfig
from .offsite import prepare


@deploy("Configure original MinIO archive pull")
def deploy_minio_archive(cfg: MinioArchiveConfig, key: SecretStr | None = None) -> None:
    if not cfg.enabled:
        return
    material = key_input(key) if cfg.ssh_key_manage else None
    prerequisites(cfg)
    prepare(cfg, material)
    triggers = [resource(cfg, "minio-offsite-replication.sh", cfg.script_path)]
    if cfg.alert_enabled:
        triggers.append(resource(cfg, "minio-offsite-alert.sh", cfg.alert_script_path))
    timer(cfg, "minio-offsite", restart_when=triggers)
