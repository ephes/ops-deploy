"""Strict RustFS inputs; secret material is separate from public configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, StrictInt, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.core.config import UnixUser
from ops_deploy.helpers.traefik import DEFAULT_INTERNAL_IP_RANGES, Hostname

Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")]
Port = Annotated[StrictInt, Field(ge=1, le=65535)]
BucketName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
# An object key below its bucket: no control characters, no empty or dot segments.
ObjectKey = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[^\x00-\x1f\x7f?#]+$")]
# host:port of a remote S3 endpoint, as RustFS remote targets store it.
HostPort = Annotated[str, Field(pattern=r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?:[0-9]{1,5}$")]
Hours = Annotated[float, Field(gt=0, le=8760)]

# Official GitHub release 1.0.4 (2026-10-25, commit 46337942d55f), no open
# advisory at pin time. The archive digests are the release's SHA256SUMS and
# provenance subjects; the binary digest is the single archive member.
RUSTFS_VERSION = "1.0.4"
RUSTFS_COMMIT = "46337942d55f3a8e6a97b147ca98d9ea8115555d"
# MinIO keeps 9001/9002 on loopback until its retirement.
MINIO_PORTS = frozenset({9001, 9002})


@dataclass(frozen=True)
class RustfsArtifact:
    archive: str
    archive_sha256: str
    binary_sha256: str

    @property
    def url(self) -> str:
        return f"https://github.com/rustfs/rustfs/releases/download/{RUSTFS_VERSION}/{self.archive}"


RUSTFS_ARTIFACTS = {
    "x86_64": RustfsArtifact(
        "rustfs-linux-x86_64-musl-v1.0.4.zip",
        "4924ad4b699b9f59943051efedae2d1eb6d4cac503a1b0384c4b25f7c2c31b5c",
        "96eab436e123765d17ca432419750ddc02836de503310615dfee7b6e9e0d5ecc",
    ),
    "aarch64": RustfsArtifact(
        "rustfs-linux-aarch64-musl-v1.0.4.zip",
        "81414fd0e41969f4f5c2e0555951cee76d3f224c112c269c80f52b31276f187a",
        "d3a23915ff222ed878301ec3be744e5409942c162f0cc0d156a263658b2b544f",
    ),
}
BINARY_SHA256 = frozenset(artifact.binary_sha256 for artifact in RUSTFS_ARTIFACTS.values())


class RustfsBucket(RoleConfig):
    name: BucketName
    # True enables versioning; False leaves the server's state alone (never suspends).
    versioning: StrictBool = True
    # Days after which noncurrent versions expire; the same lifecycle rule
    # removes delete markers without versions. None leaves lifecycle alone.
    noncurrent_expiry_days: Annotated[StrictInt, Field(ge=1, le=3650)] | None = None


class RustfsReplication(RoleConfig):
    """Bucket replication of one declared versioned bucket to a remote RustFS bucket.

    Objects, overwrites, deletes, delete markers and existing objects replicate;
    the remote target signs with ``RustfsCredentials.replication``.
    """

    bucket: BucketName
    rule_id: Name
    endpoint: HostPort
    target_bucket: BucketName
    secure: StrictBool = False


def _object_key(value: str) -> str:
    if value.startswith("/") or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("keys must be relative paths without empty or dot segments")
    return value


class RustfsMonitorJob(RoleConfig):
    """One replicated bucket watched by heartbeat objects (MinIO replica semantics).

    The source writes ``heartbeat_key`` into ``bucket``, or with
    ``heartbeat=False`` into ``heartbeat_status_bucket`` (another job's bucket
    with its own heartbeat), so buckets an application syncs verbatim stay free
    of foreign objects. The replica judges lag by that object's age.
    """

    name: Name
    bucket: BucketName
    heartbeat: StrictBool = True
    heartbeat_status_bucket: BucketName | None = None
    heartbeat_key: ObjectKey = "_replication-health/heartbeat.json"
    warning_hours: Hours = 2
    critical_hours: Hours = 6
    # A parity breach longer than this turns the replica's parity marker stale.
    parity_critical_hours: Hours = 1
    parity_tolerance_percent: Annotated[float, Field(ge=0, le=100)] = 0.1
    parity_size_delta_tolerance_bytes: Annotated[StrictInt, Field(ge=0)] = 0
    parity_object_delta_tolerance: Annotated[StrictInt, Field(ge=0)] = 200
    required: StrictBool = True

    @field_validator("heartbeat_key")
    @classmethod
    def relative_key(cls, value: str) -> str:
        return _object_key(value)

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.critical_hours < self.warning_hours:
            raise ValueError("critical_hours must not be below warning_hours")
        if self.heartbeat and self.heartbeat_status_bucket is not None:
            raise ValueError("heartbeat_status_bucket is only for heartbeat-free jobs")
        if not self.heartbeat and self.heartbeat_status_bucket in (None, self.bucket):
            raise ValueError("a heartbeat-free job needs another heartbeat_status_bucket")
        if not self.heartbeat and self.heartbeat_key == "_replication-health/heartbeat.json":
            raise ValueError("a heartbeat-free job needs its own heartbeat_key")
        return self

    @property
    def heartbeat_bucket(self) -> str:
        return self.bucket if self.heartbeat else str(self.heartbeat_status_bucket)


class RustfsReplicationMonitor(RoleConfig):
    """Heartbeat writer (``source``) or lag/parity probe (``replica``) on a timer.

    The source measures each job's replication queue and its object count and
    size on both sides, then writes the heartbeat object; the replica reads the
    replicated object and keeps ``<state_root>/<job>/{status.json,lag.marker,
    parity.marker}`` like the MinIO replica monitor, for file-age checks.
    """

    role: Literal["source", "replica"]
    jobs: tuple[RustfsMonitorJob, ...]
    # Source only: the replica's S3 API (http://host:port) for its counts.
    replica_endpoint: Annotated[str, Field(pattern=r"^http://[A-Za-z0-9.-]+:[0-9]{1,5}$")] | None = None
    state_root: AbsolutePath = "/var/lib/rustfs-replication-monitor"
    script_path: AbsolutePath = "/usr/local/bin/rustfs-replication-monitor"
    library_dir: AbsolutePath = "/usr/local/lib/rustfs-replication-monitor"
    jobs_path: AbsolutePath = "/etc/rustfs-replication-monitor.json"
    env_file: AbsolutePath = "/etc/default/rustfs-replication-monitor"
    timer_interval_sec: Annotated[StrictInt, Field(ge=60)] = 300
    timer_on_boot_sec: Annotated[StrictInt, Field(ge=0)] = 120
    timer_randomized_delay_sec: Annotated[StrictInt, Field(ge=0)] = 20

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if not self.jobs:
            raise ValueError("the replication monitor needs at least one job")
        names = [job.name for job in self.jobs]
        buckets = [job.bucket for job in self.jobs]
        if len(set(names)) != len(names) or len(set(buckets)) != len(buckets):
            raise ValueError("monitor jobs need unique names and buckets")
        own = {job.bucket for job in self.jobs if job.heartbeat}
        status_keys = [(job.heartbeat_bucket, job.heartbeat_key) for job in self.jobs]
        if any(not job.heartbeat and job.heartbeat_status_bucket not in own for job in self.jobs):
            raise ValueError("heartbeat_status_bucket must be another job's bucket with its own heartbeat")
        if len(set(status_keys)) != len(status_keys):
            raise ValueError("every job needs its own heartbeat object")
        if (self.role == "source") != (self.replica_endpoint is not None):
            raise ValueError("replica_endpoint is required for, and only for, the source role")
        if any(job.parity_critical_hours * 3600 < 2 * self.timer_interval_sec for job in self.jobs):
            raise ValueError("parity_critical_hours must cover at least two monitor intervals")
        return self

    @property
    def unit(self) -> str:
        return "rustfs-replication-heartbeat" if self.role == "source" else "rustfs-replication-lag-check"


class RustfsPolicy(RoleConfig):
    name: Name
    document: dict[str, Any]

    @model_validator(mode="after")
    def valid_document(self) -> Self:
        if self.document.get("Version") != "2012-10-17" or not isinstance(self.document.get("Statement"), list):
            raise ValueError("policy requires a 2012-10-17 document and Statement list")
        return self


class RustfsIdentity(RoleConfig):
    """A user whose attached policies are exactly ``policies``, without groups."""

    name: Name
    policies: tuple[Name, ...]
    # A bucket (GetBucketLocation) or a deliberately absent key below an owned
    # prefix (ranged GetObject) that this identity's signed request may reach.
    proof: Annotated[str, Field(min_length=3, pattern=r"^[^\x00-\x1f\x7f?#]+$")]

    @model_validator(mode="after")
    def safe_proof(self) -> Self:
        if not self.policies or len(set(self.policies)) != len(self.policies):
            raise ValueError("identity policies must be nonempty and unique")
        if self.proof.startswith(("/", "-")) or any(part in ("", ".", "..") for part in self.proof.split("/")):
            raise ValueError("proof must be a bucket or a key below its bucket")
        return self


class RustfsConfig(RoleConfig):
    """One single-node single-disk RustFS server on loopback or one local address.

    Out of scope: lifecycle rules other than noncurrent expiry, replication
    other than declared bucket rules, bucket policies, groups, service
    accounts, KMS and removal.
    """

    user: UnixUser = "rustfs"
    group: UnixUser = "rustfs"
    home: AbsolutePath = "/var/lib/rustfs"
    bin_path: AbsolutePath = "/usr/local/bin/rustfs"
    env_file: AbsolutePath = "/etc/default/rustfs"
    service_unit: Literal["/etc/systemd/system/rustfs.service"] = "/etc/systemd/system/rustfs.service"
    # The deploy refuses unless this path is a mount point and the data root
    # lies on it, so an absent encrypted volume never receives objects.
    required_mount: AbsolutePath = "/mnt/cryptdata"
    data_dir: AbsolutePath = "/mnt/cryptdata/rustfs/data"
    # Loopback, or one IPv4 address of the host (a private replica peer).
    bind_host: str = "127.0.0.1"
    api_port: Port = 9020
    region: Annotated[str, Field(pattern=r"^[a-z0-9-]{1,32}$")] = "us-east-1"
    expose_via_traefik: StrictBool = False
    traefik_api_host: Hostname = "s3.rustfs.home.example.com"
    traefik_cert_resolver: Name | Literal[""] = ""
    internal_ip_ranges: tuple[str, ...] = DEFAULT_INTERNAL_IP_RANGES
    buckets: tuple[RustfsBucket, ...] = ()
    policies: tuple[RustfsPolicy, ...] = ()
    identities: tuple[RustfsIdentity, ...] = ()
    replications: tuple[RustfsReplication, ...] = ()
    monitor: RustfsReplicationMonitor | None = None
    systemd_memory_max: Annotated[str, Field(pattern=r"^([0-9]+[KMGT]?|infinity)?$")] = ""
    systemd_limit_nofile: Annotated[StrictInt, Field(ge=1)] = 65536
    systemd_tasks_max: Annotated[str, Field(pattern=r"^([0-9]+|infinity)$")] = "infinity"
    healthcheck_timeout: Annotated[StrictInt, Field(ge=1)] = 30
    # A controller copy of the extracted executable (owned fixtures, offline
    # installs); it must match the pinned binary digest of the host's arch.
    local_binary: Path | None = None

    @field_validator("bind_host")
    @classmethod
    def single_address(cls, value: str) -> str:
        import ipaddress

        address = ipaddress.IPv4Address(value)
        if address.is_unspecified or address.is_multicast or str(address) != value:
            raise ValueError("bind_host must be one canonical unicast IPv4 address")
        return value

    @field_validator("internal_ip_ranges")
    @classmethod
    def valid_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        import ipaddress

        if not values:
            raise ValueError("internal_ip_ranges must not be empty")
        for value in values:
            ipaddress.ip_network(value)
        return values

    @model_validator(mode="after")
    def contract(self) -> Self:
        paths = [value for value in self.model_dump().values() if isinstance(value, str) and value.startswith("/")]
        if any(str(PurePosixPath(path)) != path or ".." in PurePosixPath(path).parts or path == "/" for path in paths):
            raise ValueError("paths must be canonical and below the filesystem root")
        data, mount = PurePosixPath(self.data_dir), PurePosixPath(self.required_mount)
        if data == mount or mount not in data.parents:
            raise ValueError("the data root must lie below the required mount")
        if self.api_port in MINIO_PORTS:
            raise ValueError("the API port must not collide with MinIO's loopback ports")
        for items in (self.buckets, self.policies, self.identities):
            names = [item.name for item in items]
            if len(names) != len(set(names)):
                raise ValueError("declarations must have unique names")
        policies = {item.name for item in self.policies}
        if any(not set(item.policies) <= policies for item in self.identities):
            raise ValueError("identities may attach only declared policies")
        versioned = {bucket.name for bucket in self.buckets if bucket.versioning}
        replicated = [item.bucket for item in self.replications]
        if not set(replicated) <= versioned or len(replicated) != len(set(replicated)):
            raise ValueError("each replication needs its own declared versioned bucket")
        if self.monitor is not None:
            declared = {bucket.name for bucket in self.buckets}
            if not {job.bucket for job in self.monitor.jobs} <= declared:
                raise ValueError("monitor jobs may watch only declared buckets")
            same_name = {item.bucket for item in self.replications if item.target_bucket == item.bucket}
            if self.monitor.role == "source" and {job.bucket for job in self.monitor.jobs} - same_name:
                raise ValueError("a source monitor watches only buckets replicated under the same name")
        return self

    @property
    def endpoint(self) -> str:
        return f"http://{self.bind_host}:{self.api_port}"


class RustfsUserCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    access: SecretStr
    secret: SecretStr

    @model_validator(mode="after")
    def usable(self) -> Self:
        access, secret = self.access.get_secret_value(), self.secret.get_secret_value()
        if not 3 <= len(access) <= 128 or any(not (char.isalnum() or char in "._-") for char in access):
            raise ValueError("access key must be 3-128 characters of letters, digits, '.', '_' or '-'")
        if len(secret) < 8 or secret == "CHANGEME" or any(ord(char) < 33 or ord(char) == 127 for char in secret):
            raise ValueError("secret must be at least 8 printable non-space characters and not a placeholder")
        return self


class RustfsCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    root: RustfsUserCredentials
    identities: dict[str, RustfsUserCredentials] = Field(default_factory=dict)
    # The remote identity every declared replication target signs with.
    replication: RustfsUserCredentials | None = None
    # The read-only identity the monitor uses on the replica (both roles).
    monitor: RustfsUserCredentials | None = None

    @field_validator("root")
    @classmethod
    def environment_value(cls, value: RustfsUserCredentials) -> RustfsUserCredentials:
        # The environment file quotes values literally.
        if any(char in value.secret.get_secret_value() for char in '\\"$`'):
            raise ValueError("root secret must not contain quotes, backslashes, '$' or '`'")
        return value

    @field_validator("monitor")
    @classmethod
    def monitor_environment_value(cls, value: RustfsUserCredentials | None) -> RustfsUserCredentials | None:
        # The monitor's environment file quotes values literally, like root's.
        if value is not None and any(char in value.secret.get_secret_value() for char in '\\"$`'):
            raise ValueError("monitor secret must not contain quotes, backslashes, '$' or '`'")
        return value
