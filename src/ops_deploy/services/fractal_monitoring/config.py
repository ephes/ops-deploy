"""Typed versions of the original six monitoring roles and inline lag job.

Secrets stay out of these immutable configuration objects. Original collector
resources retain their policy and schema; deployment controls when to refresh.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, StrictBool, StrictInt, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.infra.mail_relay_client import MailRelayClientConfig
from ops_deploy.infra.smartd import SmartdConfig
from ops_deploy.infra.zed import ZedConfig
from ops_deploy.services._metrics_httpd import HttpdSwitchFields
from ops_deploy.services._nyxmon_json_metrics import JsonMetricsCheck


def safe_json(value: Any) -> Any:
    text = json.dumps(value, allow_nan=False)
    if "'''" in text or any(token in text for token in ("{{", "{%", "{#")):
        raise ValueError("unsafe templated collector value")
    return value


class SchemaRule(RoleConfig):
    path: tuple[str, ...]
    kind: Literal["mapping", "sequence", "boolean", "boolean_or_none", "number", "number_or_none"]
    equals_true: StrictBool = False

    @model_validator(mode="after")
    def _path(self) -> SchemaRule:
        if not self.path or any(not value or any(char in value for char in "\r\n\0") for value in self.path):
            raise ValueError("invalid metrics schema path")
        return self


class StorageExporterConfig(RoleConfig):
    enabled: StrictBool = True
    packages: tuple[str, ...] = ("python3",)
    bin_path: AbsolutePath = "/usr/local/bin/nyxmon-storage-metrics"
    mode: str = "0755"
    smartctl_no_spinup: StrictBool = False
    quiet_hours_enabled: StrictBool = False
    quiet_hours_start: str = "06:00"
    quiet_hours_end: str = "22:00"
    quiet_hours_skip_pools: tuple[str, ...] = ()
    quiet_hours_skip_disk_types: tuple[str, ...] = ("sat",)
    quiet_hours_spindown_enabled: StrictBool = False
    quiet_hours_spindown_script: str = ""
    quiet_hours_spindown_min_interval_sec: StrictInt = 300
    quiet_hours_spindown_state_file: AbsolutePath = "/run/nyxmon-storage-metrics-spindown.ts"
    pool_cache_path: AbsolutePath = "/var/lib/nyxmon-storage-metrics/pool-cache.json"
    quiet_hours_cache_max_age_sec: StrictInt = 172800
    pools: tuple[str, ...] = ()
    pool_capacity_thresholds: dict[str, dict[str, int | float]] = Field(default_factory=dict)
    disks: tuple[dict[str, Any], ...] = ()
    filesystems: tuple[dict[str, Any], ...] = ()
    zfs_datasets: tuple[dict[str, Any], ...] = ()
    timemachine_bundle_dirs: tuple[AbsolutePath, ...] = ()

    @model_validator(mode="after")
    def _safe(self) -> StorageExporterConfig:
        safe_json(self.model_dump())
        for key in ("quiet_hours_start", "quiet_hours_end"):
            if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", getattr(self, key)):
                raise ValueError("invalid collector quiet-hours time")
        if any(not pool for pool in self.pools):
            raise ValueError("collector pool names must be nonempty strings")
        for pool, policy in self.pool_capacity_thresholds.items():
            if self.pools and pool not in self.pools:
                raise ValueError("capacity threshold must target a configured pool")
            if (
                not {"warning_ratio", "critical_ratio"} <= policy.keys()
                or not policy["warning_ratio"] < policy["critical_ratio"]
            ):
                raise ValueError("capacity warning/critical ratios must be complete and ordered")
            free = {"warning_free_bytes", "critical_free_bytes"} & policy.keys()
            if free and (
                len(free) != 2
                or any(type(policy[k]) is not int for k in free)
                or policy["warning_free_bytes"] <= policy["critical_free_bytes"]
            ):
                raise ValueError("capacity free-byte thresholds must be complete ordered integers")
        for row in self.disks:
            if not all(isinstance(row.get(k), str) and row[k] for k in ("name", "device", "type")) or row[
                "type"
            ] not in {"nvme", "ata", "scsi", "sat"}:
                raise ValueError("storage disks require name/device and a supported device type")
        for row in self.filesystems:
            if (
                not isinstance(row.get("name"), str)
                or not row["name"]
                or not isinstance(row.get("path"), str)
                or not row["path"].startswith("/")
            ):
                raise ValueError("filesystem checks require names and absolute paths")
        names = []
        for row in self.zfs_datasets:
            if not all(isinstance(row.get(k), str) and row[k] for k in ("name", "dataset")):
                raise ValueError("ZFS checks require nonempty name/dataset bindings")
            names.append(row["name"])
        if len(names) != len(set(names)):
            raise ValueError("ZFS dataset check names must be unique")
        if len(self.timemachine_bundle_dirs) != len(set(self.timemachine_bundle_dirs)) or any(
            len(p) <= 1 for p in self.timemachine_bundle_dirs
        ):
            raise ValueError("Time Machine bundle directories must be unique absolute nonroot paths")
        if self.quiet_hours_spindown_script and not re.fullmatch(
            r"/[A-Za-z0-9._/+-]+", self.quiet_hours_spindown_script
        ):
            raise ValueError("unsafe existing spindown helper path")
        if not re.fullmatch(r"0?[0-7]{3}", self.mode):
            raise ValueError("invalid exporter mode")
        if self.quiet_hours_spindown_min_interval_sec < 0 or self.quiet_hours_cache_max_age_sec <= 0:
            raise ValueError("invalid collector cache/spindown interval")
        if self.quiet_hours_spindown_enabled and not self.quiet_hours_spindown_script:
            raise ValueError("spindown requires the separately supplied existing helper")
        return self


class EndpointConfig(RoleConfig, HttpdSwitchFields):
    service_name: str
    timer_name: str
    path: str
    enabled: StrictBool = True
    user: str = "metrics"
    group: str = "metrics"
    bind: str = "127.0.0.1"
    auth_user: str = Field(default="nyxmon", max_length=255)
    packages: tuple[str, ...] = ("python3", "apache2-utils")
    timer_interval: StrictInt = 300
    timer_on_boot_sec: StrictInt = 30
    timer_accuracy_sec: StrictInt = 10
    timer_randomized_delay_sec: StrictInt = 30
    freshness_sec: StrictInt = 600

    @model_validator(mode="before")
    @classmethod
    def _derived_defaults(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        result = dict(value)
        if "group" not in result and "user" in result:
            result["group"] = result["user"]
        for key, parent in [("json_path", "data_dir"), ("htpasswd_path", "htpasswd_dir")]:
            if key in cls.model_fields and key not in result and parent in result:
                suffix = str(cls.model_fields[key].default).rsplit("/", 1)[-1]
                result[key] = str(result[parent]).rstrip("/") + "/" + suffix
        if "cache_json_path" in cls.model_fields and "cache_json_path" not in result and "json_path" in result:
            result["cache_json_path"] = result["json_path"]
        return result

    @model_validator(mode="after")
    def _safe(self) -> EndpointConfig:
        safe_json(self.model_dump(mode="json"))
        if any(isinstance(value, str) and any(c in value for c in "\r\n\0") for value in self.model_dump().values()):
            raise ValueError("endpoint unit inputs must be single lines")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", str(self.service_name)):
            raise ValueError("invalid endpoint service name")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", str(self.timer_name)):
            raise ValueError("invalid collector timer name")
        if not re.fullmatch(r"/[A-Za-z0-9._/~+-]*", str(self.path)):
            raise ValueError("unsafe endpoint HTTP path")
        for key, value in self.model_dump().items():
            if key.endswith(("_path", "_dir")) and isinstance(value, str) and ".." in value.split("/"):
                raise ValueError("managed paths must not traverse parent directories")
        if any(not re.fullmatch(r"[a-z_][a-z0-9_-]*", getattr(self, k)) for k in ("user", "group", "auth_user")):
            raise ValueError("invalid endpoint account")
        if not re.fullmatch(r"[A-Za-z0-9.:_-]+", self.bind):
            raise ValueError("invalid endpoint bind address")
        if (
            min(self.timer_interval, self.freshness_sec) < 1
            or min(self.timer_on_boot_sec, self.timer_accuracy_sec, self.timer_randomized_delay_sec) < 0
        ):
            raise ValueError("invalid endpoint timings")
        return self


class StorageEndpointConfig(EndpointConfig):
    service_name: str = "storage-metrics-endpoint"
    port: StrictInt = Field(default=9101, ge=1, le=65535)
    path: str = "/.well-known/storage"
    data_dir: AbsolutePath = "/var/lib/storage-metrics"
    json_path: AbsolutePath = "/var/lib/storage-metrics/storage.json"
    server_path: AbsolutePath = "/usr/local/bin/storage_metrics_httpd.py"
    htpasswd_dir: AbsolutePath = "/etc/storage-metrics-endpoint"
    htpasswd_path: AbsolutePath = "/etc/storage-metrics-endpoint/htpasswd"
    exporter_path: AbsolutePath = "/usr/local/bin/nyxmon-storage-metrics"
    timer_name: str = "storage-metrics-collector"
    timer_on_calendar: str = "*:0/5"


class BackupEndpointConfig(EndpointConfig):
    service_name: str = "backup-metrics-endpoint"
    port: StrictInt = Field(default=9103, ge=1, le=65535)
    path: str = "/.well-known/backup"
    data_dir: AbsolutePath = "/var/lib/backup-metrics"
    json_path: AbsolutePath = "/var/lib/backup-metrics/backup.json"
    server_path: AbsolutePath = "/usr/local/bin/backup_metrics_httpd.py"
    exporter_path: AbsolutePath = "/usr/local/bin/backup_metrics_exporter.py"
    htpasswd_dir: AbsolutePath = "/etc/backup-metrics-endpoint"
    htpasswd_path: AbsolutePath = "/etc/backup-metrics-endpoint/htpasswd"
    timer_name: str = "backup-metrics-collector"
    timer_randomized_delay_sec: StrictInt = 15
    systemctl_timeout: StrictInt = 10
    zfs_timeout: StrictInt = 45
    zfs_retries: StrictInt = 1
    zfs_retry_delay: StrictInt = 2
    quiet_hours_enabled: StrictBool = False
    quiet_hours_start: str = "06:00"
    quiet_hours_end: str = "22:00"
    quiet_hours_skip_local_snapshot_probes: StrictBool = True
    cache_json_path: AbsolutePath = "/var/lib/backup-metrics/backup.json"
    units: tuple[dict[str, Any], ...] = (
        {
            "id": "sanoid",
            "timer": "sanoid-ops-library.timer",
            "service": "sanoid-ops-library.service",
            "required": True,
        },
        {
            "id": "syncoid_local",
            "timer": "zfs-syncoid-replication.timer",
            "service": "zfs-syncoid-replication.service",
            "required": True,
        },
        {
            "id": "syncoid_usb",
            "timer": "zfs-usb-replication.timer",
            "service": "zfs-usb-replication.service",
            "required": False,
        },
    )
    local_datasets: tuple[str, ...] = ("tank/replica/fast/general", "tank/replica/fast/timemachine")
    usb_enabled: StrictBool = False
    usb_pool: str = "vault"
    usb_device: str = ""
    usb_devices: tuple[str, ...] = ()
    usb_replication_status_path: AbsolutePath = "/var/lib/zfs-usb-replication/status.json"
    usb_capacity_warning_ratio: float = 0.90
    usb_capacity_critical_ratio: float = 0.95
    usb_protection_max_age_hours: float = 0
    usb_health_module_path: AbsolutePath = "/usr/local/bin/backup_metrics_usb_health.py"
    usb_datasets: tuple[str, ...] = (
        "vault/replica/fast/general",
        "vault/replica/fast/timemachine",
        "vault/photos",
        "vault/videos",
        "vault/backups",
    )
    file_backups: tuple[dict[str, Any], ...] = ()

    @model_validator(mode="after")
    def _backup_safe(self) -> BackupEndpointConfig:
        if min(self.systemctl_timeout, self.zfs_timeout) < 1 or min(self.zfs_retries, self.zfs_retry_delay) < 0:
            raise ValueError("invalid backup command timeout/retry policy")
        for value in (self.quiet_hours_start, self.quiet_hours_end):
            if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value):
                raise ValueError("invalid backup quiet-hours time")
        if (
            not 0 < self.usb_capacity_warning_ratio < self.usb_capacity_critical_ratio <= 1
            or self.usb_protection_max_age_hours < 0
        ):
            raise ValueError("invalid backup USB capacity/freshness policy")
        safe_json(self.model_dump(mode="json"))
        return self


class ReplicationLagConfig(RoleConfig):
    enabled: StrictBool = False
    jobs: tuple[dict[str, Any], ...] = ()
    destination_endpoint: str = ""
    script_path: AbsolutePath = "/usr/local/bin/minio-replication-lag-probe.py"
    jobs_config_path: AbsolutePath = "/etc/minio-replication-monitor-jobs.json"
    service_name: str = "minio-replication-lag-check"
    timer_name: str = "minio-replication-lag-check"
    timer_interval_sec: StrictInt = 300
    timer_on_boot_sec: StrictInt = 120
    timer_randomized_delay_sec: StrictInt = 20
    mc_version: Literal["RELEASE.2025-08-13T08-35-41Z"] = "RELEASE.2025-08-13T08-35-41Z"
    mc_sha256: Literal["01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"] = (
        "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
    )
    mc_url: str = "https://github.com/minio/mc/releases/download/RELEASE.2025-08-13T08-35-41Z/mc.linux-amd64.RELEASE.2025-08-13T08-35-41Z"
    mc_path: Literal["/usr/local/bin/mc"] = "/usr/local/bin/mc"
    freshness_sec: StrictInt = 600

    @model_validator(mode="after")
    def _safe(self) -> ReplicationLagConfig:
        safe_json(self.model_dump(mode="json"))
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", self.service_name) or not re.fullmatch(
            r"[a-z0-9][a-z0-9_-]*", self.timer_name
        ):
            raise ValueError("invalid lag service/timer name")
        if not re.fullmatch(r"[0-9a-f]{64}", self.mc_sha256):
            raise ValueError("invalid mc source checksum")
        for url in (self.mc_url, self.destination_endpoint):
            if not url and not self.enabled:
                continue
            parsed = urlsplit(url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or any(char.isspace() or ord(char) < 32 for char in url)
            ):
                raise ValueError("MinIO URLs must be nonsecret absolute HTTP(S) bindings")
        if (
            min(self.timer_interval_sec, self.freshness_sec) < 1
            or min(self.timer_on_boot_sec, self.timer_randomized_delay_sec) < 0
        ):
            raise ValueError("invalid lag monitor timings")
        if self.enabled:
            if not self.jobs or not self.destination_endpoint:
                raise ValueError("lag monitor requires jobs and destination endpoint")
            names = []
            for row in self.jobs:
                if not isinstance(row.get("bucket"), str) or not row["bucket"]:
                    raise ValueError("lag jobs require a bucket")
                name = row.get("name") or row["bucket"].replace("-", "_")
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) or ".." in name:
                    raise ValueError("invalid lag job identity")
                state = row.get("monitor_state_dir")
                if state is not None and (
                    not isinstance(state, str)
                    or not re.fullmatch(r"/[A-Za-z0-9._/+-]+", state)
                    or ".." in state.split("/")
                ):
                    raise ValueError("invalid lag state directory")
                names.append(name)
                warning = float(row.get("warning_hours", 2))
                critical = float(row.get("critical_hours", 6))
                if (
                    warning <= 0
                    or critical < warning
                    or float(row.get("parity_critical_hours", 1)) * 3600 < 2 * self.timer_interval_sec
                ):
                    raise ValueError("invalid lag/parity grace policy")
            for row in self.jobs:
                if row.get("heartbeat", True) is False:
                    bucket = row.get("heartbeat_status_bucket")
                    if not bucket or bucket == row["bucket"] or bucket not in {r["bucket"] for r in self.jobs}:
                        raise ValueError("heartbeat-free job needs another configured heartbeat bucket")
            if len(names) != len(set(names)):
                raise ValueError("lag job names must be unique")
        return self


class FractalMonitoringConfig(RoleConfig):
    relay: MailRelayClientConfig
    smartd: SmartdConfig
    zed: ZedConfig
    exporter: StorageExporterConfig
    storage: StorageEndpointConfig
    backup: BackupEndpointConfig
    replication: ReplicationLagConfig = Field(default_factory=ReplicationLagConfig)
    expected_tailscale_ipv4: str
    expected_relay_ipv4: str
    storage_schema: tuple[SchemaRule, ...]
    backup_schema: tuple[SchemaRule, ...]

    @model_validator(mode="after")
    def _identity(self) -> FractalMonitoringConfig:
        ipaddress.IPv4Address(self.expected_tailscale_ipv4)
        ipaddress.IPv4Address(self.expected_relay_ipv4)
        if self.exporter.enabled and self.storage.enabled and self.exporter.bin_path != self.storage.exporter_path:
            raise ValueError("managed storage exporter must match its collector unit")
        if self.relay.enabled and self.relay.relayhost != self.expected_relay_ipv4:
            raise ValueError("relay host must equal the authorized backend identity")
        for endpoint in (self.storage, self.backup):
            if endpoint.enabled and endpoint.bind != self.expected_tailscale_ipv4:
                raise ValueError("endpoint must bind the declared Fractal address")
        return self


class FractalMonitoringChecksConfig(RoleConfig):
    checks: tuple[JsonMetricsCheck, ...]
    storage_url: str
    backup_url: str
    endpoint_timeout: StrictInt = 30
    expected_relay_ipv4: str
    storage_schema: tuple[SchemaRule, ...]
    backup_schema: tuple[SchemaRule, ...]
    # The private script retires this legacy name globally, preserving its original semantics.
    legacy_name: Literal["Fractal Storage Health (HTTP)"] = "Fractal Storage Health (HTTP)"

    @model_validator(mode="after")
    def _checks(self) -> FractalMonitoringChecksConfig:
        ipaddress.IPv4Address(self.expected_relay_ipv4)
        if self.endpoint_timeout < 1:
            raise ValueError("endpoint timeout must be positive")
        if tuple(c.url for c in self.checks) != (self.storage_url, self.backup_url):
            raise ValueError("managed check URLs must be the validated endpoint URLs")
        if len(self.checks) != 2 or tuple(c.name for c in self.checks) != ("Fractal Storage", "Fractal Backup"):
            raise ValueError("Fractal monitoring owns exactly its original two checks")
        if any(c.auth_username != "nyxmon" for c in self.checks):
            raise ValueError("Fractal checks retain their original monitor username")
        if any(
            isinstance(c.data.get("notification_suppression"), dict) and "auth" in c.data["notification_suppression"]
            for c in self.checks
        ):
            raise ValueError("suppression auth is supplied only on stdin at execution")
        if any(c.service_name != "fractal" or c.check_interval != 300 for c in self.checks):
            raise ValueError("Fractal checks retain service/interval identity")
        return self
