"""Shared host services ported from ops-library: PostgreSQL, Redis, Traefik, Docker, Vector, certbot and
the encrypted data volume.

Like :mod:`ops_deploy.base`, each module holds a typed config and a
``@deploy`` function; they are deploys, not shared helpers, so they sit
outside the size-capped helpers/ops/core layer. Secrets (database and Redis
passwords) are deploy arguments, never config fields.
"""

from typing import TYPE_CHECKING, Any

from ops_deploy.infra.backup import (
    BackupRestoreAccessConfig,
    BackupSourceConfig,
    MailReplicationConfig,
    MinioArchiveConfig,
    SnapshotRetention,
    SyncoidConfig,
    SyncoidJob,
    UsbDrive,
    UsbReplicationConfig,
    deploy_backup_restore_access,
    deploy_backup_restore_client,
    deploy_backup_source,
    deploy_mail_replication,
    deploy_minio_archive,
    deploy_syncoid,
    deploy_usb_replication,
)
from ops_deploy.infra.certbot_dns import CertbotDnsConfig, deploy_certbot_dns
from ops_deploy.infra.certbot_lifecycle import (
    CertbotDnsBackupConfig,
    CertbotDnsRestoreConfig,
    deploy_certbot_dns_backup,
    deploy_certbot_dns_restore,
)
from ops_deploy.infra.docker_install import DockerInstallConfig, deploy_docker_install, docker_steps
from ops_deploy.infra.encrypted_volume import EncryptedVolumeConfig, deploy_encrypted_volume
from ops_deploy.infra.hdparm_tune import HdparmDevice, HdparmTuneConfig, deploy_hdparm_tune
from ops_deploy.infra.mail_relay_client import MailRelayClientConfig, deploy_mail_relay_client
from ops_deploy.infra.netplan import NetplanConfig, deploy_netplan
from ops_deploy.infra.postgres_install import (
    DatabaseSpec,
    ExtensionSpec,
    PgHbaRule,
    PostgresInstallConfig,
    deploy_postgres_install,
)
from ops_deploy.infra.redis_install import RedisInstallConfig, deploy_redis_install
from ops_deploy.infra.smartd import SmartdConfig, SmartdDevice, deploy_smartd
from ops_deploy.infra.traefik_backup import (
    TraefikBackupConfig,
    TraefikRestoreConfig,
    deploy_traefik_backup,
    deploy_traefik_restore,
)
from ops_deploy.infra.traefik_deploy import FileCertificate, TraefikDeployConfig, deploy_traefik
from ops_deploy.infra.traefik_probes import (
    ProbeBaseline,
    ProbeCommands,
    ProbeError,
    ProbeSpec,
    TraefikHealthProbesConfig,
    capture_traefik_health_probes,
    deploy_traefik_health_probes,
    verify_traefik_health_probes,
)
from ops_deploy.infra.traefik_remove import TraefikRemoveConfig, deploy_traefik_remove
from ops_deploy.infra.vector_apt_install import VectorAptInstallConfig, deploy_vector_apt_install, vector_apt_steps
from ops_deploy.infra.zed import ZedConfig, deploy_zed
from ops_deploy.infra.zfs_storage import (
    ZfsDatasetConfig,
    ZfsPoolConfig,
    ZfsStorageConfig,
    deploy_zfs_dataset,
    deploy_zfs_pool,
    deploy_zfs_storage,
)

__all__ = [
    "BackupRestoreAccessConfig",
    "BackupSourceConfig",
    "CertbotDnsBackupConfig",
    "CertbotDnsConfig",
    "CertbotDnsRestoreConfig",
    "DatabaseSpec",
    "DockerInstallConfig",
    "EncryptedVolumeConfig",
    "ExtensionSpec",
    "FileCertificate",
    "HdparmDevice",
    "HdparmTuneConfig",
    "MailRelayClientConfig",
    "MailReplicationConfig",
    "MinioArchiveConfig",
    "NetplanConfig",
    "PgHbaRule",
    "PostgresInstallConfig",
    "ProbeBaseline",
    "ProbeCommands",
    "ProbeError",
    "ProbeSpec",
    "RedisInstallConfig",
    "SmartdConfig",
    "SmartdDevice",
    "SnapshotRetention",
    "SyncoidConfig",
    "SyncoidJob",
    "TailscaleBackupConfig",
    "TailscaleConfig",
    "TailscaleManualRestoreConfig",
    "TailscaleMetricsConfig",
    "TailscaleNyxmonConfig",
    "TailscaleNyxmonTarget",
    "TailscaleRemoveConfig",
    "TraefikBackupConfig",
    "TraefikDeployConfig",
    "TraefikHealthProbesConfig",
    "TraefikRemoveConfig",
    "TraefikRestoreConfig",
    "UsbDrive",
    "UsbReplicationConfig",
    "VectorAptInstallConfig",
    "ZedConfig",
    "ZfsDatasetConfig",
    "ZfsPoolConfig",
    "ZfsStorageConfig",
    "capture_traefik_health_probes",
    "deploy_backup_restore_access",
    "deploy_backup_restore_client",
    "deploy_backup_source",
    "deploy_certbot_dns",
    "deploy_certbot_dns_backup",
    "deploy_certbot_dns_restore",
    "deploy_docker_install",
    "deploy_encrypted_volume",
    "deploy_hdparm_tune",
    "deploy_mail_relay_client",
    "deploy_mail_replication",
    "deploy_minio_archive",
    "deploy_netplan",
    "deploy_postgres_install",
    "deploy_redis_install",
    "deploy_smartd",
    "deploy_syncoid",
    "deploy_tailscale",
    "deploy_tailscale_backup",
    "deploy_tailscale_manual_restore",
    "deploy_tailscale_metrics",
    "deploy_tailscale_nyxmon",
    "deploy_tailscale_remove",
    "deploy_traefik",
    "deploy_traefik_backup",
    "deploy_traefik_health_probes",
    "deploy_traefik_remove",
    "deploy_traefik_restore",
    "deploy_usb_replication",
    "deploy_vector_apt_install",
    "deploy_zed",
    "deploy_zfs_dataset",
    "deploy_zfs_pool",
    "deploy_zfs_storage",
    "docker_steps",
    "vector_apt_steps",
    "verify_traefik_health_probes",
]

if TYPE_CHECKING:
    from ops_deploy.infra.tailscale import (
        TailscaleBackupConfig,
        TailscaleConfig,
        TailscaleManualRestoreConfig,
        TailscaleMetricsConfig,
        TailscaleNyxmonConfig,
        TailscaleNyxmonTarget,
        TailscaleRemoveConfig,
        deploy_tailscale,
        deploy_tailscale_backup,
        deploy_tailscale_manual_restore,
        deploy_tailscale_metrics,
        deploy_tailscale_nyxmon,
        deploy_tailscale_remove,
    )


def __getattr__(name: str) -> Any:
    # Only the new Tailscale aliases depend on Fractal's endpoint model.
    # Resolve them after this package initializes so importing an existing
    # Fractal component first cannot re-enter its partially defined models.
    if name in (
        "TailscaleBackupConfig",
        "TailscaleConfig",
        "TailscaleManualRestoreConfig",
        "TailscaleMetricsConfig",
        "TailscaleNyxmonConfig",
        "TailscaleNyxmonTarget",
        "TailscaleRemoveConfig",
        "deploy_tailscale",
        "deploy_tailscale_backup",
        "deploy_tailscale_manual_restore",
        "deploy_tailscale_metrics",
        "deploy_tailscale_nyxmon",
        "deploy_tailscale_remove",
    ):
        import ops_deploy.infra.tailscale as tailscale

        return getattr(tailscale, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
