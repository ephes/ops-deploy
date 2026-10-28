"""Original zfs_pool_deploy/zfs_dataset inputs; credentials stay outside models."""

from __future__ import annotations

import math
import re
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictFloat, StrictInt, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig

PoolName = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]*$", max_length=255)]
DatasetName = Annotated[
    str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]*(/[A-Za-z0-9_][A-Za-z0-9_.:-]*)+$", max_length=1024)
]
UnitName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@-]*$")]
Identity = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]*$")]
PropertyValue = str | StrictInt | StrictFloat | StrictBool
VDEV_WORDS = frozenset({"mirror", "raidz", "raidz1", "raidz2", "raidz3", "spare", "log", "cache"})


def validate_properties(value: dict[str, PropertyValue]) -> dict[str, PropertyValue]:
    for name, item in value.items():
        if type(item) is float and not math.isfinite(item):
            raise ValueError("ZFS property values must be finite")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]*", name):
            raise ValueError("invalid native ZFS property name")
        if any(ord(c) < 32 or ord(c) == 127 for c in str(item)):
            raise ValueError("ZFS property values must not contain controls")
    return value


def canonical(path: str) -> str:
    if not path.startswith("/") or path.startswith("//") or str(PurePosixPath(path)) != path or ".." in path.split("/"):
        raise ValueError("native storage paths must be absolute and canonical")
    return path


class ZfsPoolConfig(RoleConfig):
    """An imported pool or explicit original creation policy; no destroy/export/key rotation."""

    name: PoolName
    vdevs: tuple[str, ...] = Field(min_length=1)
    ashift: int = Field(default=12, ge=9, le=16)
    autotrim: bool = False
    properties: dict[str, PropertyValue] = Field(default_factory=dict)
    filesystem_properties: dict[str, PropertyValue] = Field(default_factory=dict)
    encryption_enabled: bool = True
    encryption_algorithm: Literal[
        "aes-128-ccm", "aes-192-ccm", "aes-256-ccm", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "on"
    ] = "aes-256-gcm"
    keyformat: Literal["passphrase", "raw"] = "passphrase"
    keylocation_type: Literal["file", "prompt"] = "file"
    keyfile_path: AbsolutePath | None = None
    keyfile_mode: Literal["0400"] = "0400"
    keyfile_owner: Literal["root"] = "root"
    keyfile_group: Identity = "root"
    configure_boot_unlock: bool = True
    unlock_service_name: UnitName | None = None
    mountpoint: AbsolutePath | Literal["none", "legacy"] | None = None
    allow_create: bool = False
    validate_only: bool = False
    force_create: bool = False
    no_log: bool = True
    packages: tuple[str, ...] = ("zfsutils-linux",)

    _pool_properties = field_validator("properties", "filesystem_properties")(validate_properties)

    @model_validator(mode="after")
    def _validate(self) -> ZfsPoolConfig:
        if self.name.lower() in VDEV_WORDS or self.name in {".", ".."}:
            raise ValueError("pool name is a native reserved topology word")
        if not self.validate_only and not self.allow_create:
            # Preserve the original role's unconditional, explicit source flag.
            raise ValueError("original pool deployment requires allow_create=True (or validate_only)")
        devices = [value for value in self.vdevs if value not in VDEV_WORDS]
        if not devices:
            raise ValueError("pool vdevs require an explicit device/file path")
        for path in devices:
            canonical(path)
            if path == "/" or any(c.isspace() or ord(c) < 32 for c in path):
                raise ValueError("invalid declared vdev path")
        for managed_path in (self.keyfile_path, self.mountpoint):
            if managed_path is not None and managed_path not in {"none", "legacy"}:
                canonical(managed_path)
        if self.keyfile_path == "/":
            raise ValueError("key file must name an ordinary file")
        if not self.packages or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+.:~-]*", item) for item in self.packages):
            raise ValueError("invalid original package prerequisite")
        return self

    @property
    def resolved_keyfile(self) -> str:
        return self.keyfile_path or f"/root/.zfs-key-{self.name}"

    @property
    def resolved_mountpoint(self) -> str:
        return self.mountpoint or f"/{self.name}"

    @property
    def resolved_unlock_unit(self) -> str:
        return self.unlock_service_name or f"zfs-unlock-{self.name}"


class ZfsDatasetConfig(RoleConfig):
    """Filesystem creation/configuration, with original creation-only case policy."""

    name: DatasetName
    properties: dict[str, PropertyValue] = Field(default_factory=dict)
    macos_compat: bool = False
    mountpoint: AbsolutePath | Literal["", "none", "legacy"] = ""
    mounted: bool = True
    validate_only: bool = False
    # The original role declares this flag but does not consume it in create.
    # Retain that actual behavior; never silently introduce encryption=off.
    inherit_encryption: bool = True
    no_log: bool = False

    _dataset_properties = field_validator("properties")(validate_properties)

    @model_validator(mode="after")
    def _validate(self) -> ZfsDatasetConfig:
        if any(part in {".", ".."} for part in self.name.split("/")):
            raise ValueError("invalid dataset identity")
        if self.mountpoint not in {"", "none", "legacy"}:
            canonical(self.mountpoint)
        return self

    @property
    def effective_properties(self) -> dict[str, PropertyValue]:
        values: dict[str, PropertyValue] = (
            {"xattr": "sa", "acltype": "nfsv4", "atime": "off"} if self.macos_compat else {}
        )
        values.update(self.properties)
        if values.get("acltype") == "nfs4":
            values["acltype"] = "nfsv4"
        return values


class ZfsStorageConfig(RoleConfig):
    """An ordered original pool/dataset bundle with explicit parent dependencies."""

    pools: tuple[ZfsPoolConfig, ...] = Field(min_length=1)
    datasets: tuple[ZfsDatasetConfig, ...] = ()

    @model_validator(mode="after")
    def _identities(self) -> ZfsStorageConfig:
        if len({p.name for p in self.pools}) != len(self.pools) or len({d.name for d in self.datasets}) != len(
            self.datasets
        ):
            raise ValueError("storage pool/dataset identities must be unique")
        if any(d.name.split("/")[0] not in {p.name for p in self.pools} for d in self.datasets):
            raise ValueError("storage bundle datasets must belong to a declared pool")
        return self

    @property
    def ordered_datasets(self) -> tuple[ZfsDatasetConfig, ...]:
        return tuple(sorted(self.datasets, key=lambda d: (d.name.count("/"), d.name)))
