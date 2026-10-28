from __future__ import annotations

from typing import Annotated

from pydantic import Field, StrictBool, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath
from ops_deploy.services._samba.config import RESERVED_SECTIONS, Name, SambaBaseConfig, single


class SambaTimeMachineConfig(SambaBaseConfig):
    path: AbsolutePath = "/fast/timemachine"
    required_dataset: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:/-]+$")] | None = None
    share_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")] = "timemachine"
    max_size: str = "6T"
    browseable: StrictBool = True
    users: tuple[Name, ...]
    system_user: Name = "timemachine"
    system_group: Name = "timemachine"
    system_uid: Annotated[int, Field(ge=1)] = 2000
    system_gid: Annotated[int, Field(ge=1)] = 2000
    manage_system_users: StrictBool = True
    fruit_metadata: str = "stream"
    fruit_model: str = "MacSamba"
    fruit_posix_rename: StrictBool = True
    fruit_timemachine: StrictBool = True
    server_string: str = "Time Machine Backup Server"
    snippet_path: AbsolutePath = "/etc/samba/smb.conf.d/timemachine.conf"

    @field_validator("share_name")
    @classmethod
    def _share_name(cls, value: str) -> str:
        if value.casefold() in RESERVED_SECTIONS:
            raise ValueError("reserved Samba section name")
        return value

    @field_validator("max_size", "fruit_metadata", "fruit_model")
    @classmethod
    def _single(cls, value: str) -> str:
        return single(value)

    @model_validator(mode="after")
    def _users(self) -> SambaTimeMachineConfig:
        if not self.users or len(set(self.users)) != len(self.users):
            raise ValueError("Time Machine needs distinct users")
        return self
