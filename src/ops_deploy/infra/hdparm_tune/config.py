"""The hdparm_tune role's policy, without an assertion about hardware state."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig


class HdparmDevice(RoleConfig):
    device: AbsolutePath
    apm: Annotated[StrictInt, Field(ge=1, le=255)] | None = None
    spindown_time: Annotated[StrictInt, Field(ge=0, le=253)] | None = None
    acoustic_management: Annotated[StrictInt, Field(ge=0, le=254)] | None = None

    @field_validator("device")
    @classmethod
    def _device(cls, value: str) -> str:
        if not value.startswith("/dev/") or ".." in PurePosixPath(value).parts:
            raise ValueError("hdparm device must be a path below /dev without parent segments")
        return value

    @model_validator(mode="after")
    def _setting(self) -> HdparmDevice:
        if all(value is None for value in (self.apm, self.spindown_time, self.acoustic_management)):
            raise ValueError("a disk needs at least one hdparm setting")
        return self


class HdparmTuneConfig(RoleConfig):
    devices: tuple[HdparmDevice, ...] = ()
    apply_now: StrictBool = False
    # Ubuntu's udev hook skips -B/-S for disks without ID_ATA_FEATURE_SET_APM=1,
    # so the role also applies the policy from a boot oneshot. False (or no
    # devices) removes the unit and script.
    apply_on_boot: StrictBool = True
    boot_service_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9@_-][A-Za-z0-9@_.-]*\.service$")] = (
        "hdparm-tune.service"
    )
    boot_script_path: AbsolutePath = "/usr/local/sbin/hdparm-tune-apply"
    boot_device_wait_sec: Annotated[StrictInt, Field(ge=0)] = 60

    @field_validator("boot_script_path")
    @classmethod
    def _script(cls, value: str) -> str:
        path = PurePosixPath(value)
        if str(path) != value or ".." in path.parts or len(path.parts) < 2 or value.startswith("//"):
            raise ValueError("hdparm boot script path must be an absolute file path without dot segments")
        return value

    @model_validator(mode="after")
    def _unique(self) -> HdparmTuneConfig:
        if len({row.device for row in self.devices}) != len(self.devices):
            raise ValueError("hdparm devices must be unique")
        return self
