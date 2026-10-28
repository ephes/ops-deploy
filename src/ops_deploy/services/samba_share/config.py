from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StrictBool, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.services._samba.config import RESERVED_SECTIONS, Mode, Name, SambaBaseConfig, single


class SambaShare(RoleConfig):
    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")]
    path: AbsolutePath
    browseable: StrictBool = True
    read_only: StrictBool = False
    guest_ok: StrictBool = False
    valid_users: tuple[Name, ...] = ()
    create_mask: Mode = "0660"
    directory_mask: Mode = "0770"
    force_user: Name | Literal[""] = ""
    force_group: Name | Literal[""] = ""
    path_owner: Name | Literal[""] = ""
    path_group: Name | Literal[""] = ""
    path_mode: Mode | Literal[""] = ""
    extra_options: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if value.casefold() in RESERVED_SECTIONS:
            raise ValueError("reserved Samba section name")
        return value

    @field_validator("extra_options")
    @classmethod
    def _options(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            single(key)
            single(item)
            if any(c in key for c in "=[]") or "".join(key.split()).casefold() in {"include", "copy", "configbackend"}:
                raise ValueError("invalid extra Samba share option")
        return value


class SambaSharesConfig(SambaBaseConfig):
    shares: tuple[SambaShare, ...]
    users: tuple[Name, ...] = ()
    manage_system_users: StrictBool = True
    system_group: Name = "sambashare"

    @model_validator(mode="after")
    def _unique(self) -> SambaSharesConfig:
        if not self.shares or len({row.name for row in self.shares}) != len(self.shares):
            raise ValueError("a batch needs distinct Samba shares")
        if len(set(self.users)) != len(self.users):
            raise ValueError("duplicate Samba users")
        return self
