from __future__ import annotations

from typing import Annotated

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.infra.mail_relay_client.config import line


class SmartdDevice(RoleConfig):
    device: AbsolutePath
    name: str
    type: str
    no_spinup: StrictBool = False
    short_schedule: str | None = None
    long_schedule: str | None = None

    @field_validator("name", "type")
    @classmethod
    def _word(cls, value: str) -> str:
        line(value)
        if not value or any(char.isspace() for char in value):
            raise ValueError("device name/type must be a nonempty word")
        return value

    @field_validator("short_schedule", "long_schedule")
    @classmethod
    def _schedule(cls, value: str | None) -> str | None:
        if value is not None:
            line(value)
            if not value or any(char.isspace() or char in "()" for char in value):
                raise ValueError("invalid smartd schedule")
        return value


class SmartdConfig(RoleConfig):
    enabled: StrictBool = True
    devices: tuple[SmartdDevice, ...] = ()
    mail_to: str = ""
    mail_from: str = "root"  # Original role retains this variable but its template does not use it.
    manage_service: StrictBool = True
    opts: str = ""
    temp_diff: Annotated[StrictInt, Field(ge=0)] = 4
    temp_info: Annotated[StrictInt, Field(ge=0)] = 40
    temp_crit: Annotated[StrictInt, Field(ge=0)] = 45
    short_test_schedule: str = "S/../.././02"
    long_test_schedule: str = "L/../../6/03"
    config_path: AbsolutePath = "/etc/smartd.conf"
    packages: tuple[str, ...] = ("smartmontools", "nvme-cli")
    service_name: str = "smartmontools"

    @field_validator("mail_to", "mail_from", "opts", "service_name", "short_test_schedule", "long_test_schedule")
    @classmethod
    def _line(cls, value: str) -> str:
        line(value)
        if '"' in value or "$" in value or "`" in value or "\\" in value:
            raise ValueError("unsafe smartd configuration value")
        return value

    @model_validator(mode="after")
    def _required(self) -> SmartdConfig:
        if self.enabled and (not self.devices or not self.mail_to):
            raise ValueError("smartd requires devices and a mail recipient")
        return self
