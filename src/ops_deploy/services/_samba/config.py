from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StrictBool, field_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig

RESERVED_SECTIONS = frozenset({"global", "globals", "homes", "printers"})

Name = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]*[$]?$", max_length=32)]
Mode = Annotated[str, Field(pattern=r"^0?[0-7]{3}$")]


def single(value: str) -> str:
    if not value or any(c in value for c in "\r\n\0"):
        raise ValueError("configuration value must be a nonempty single line")
    return value


class SambaBaseConfig(RoleConfig):
    packages: tuple[str, ...] = ("samba", "samba-vfs-modules", "python3-samba", "python3-tdb")
    config_file: AbsolutePath = "/etc/samba/smb.conf"
    snippet_dir: AbsolutePath = "/etc/samba/smb.conf.d"
    workgroup: str = "WORKGROUP"
    server_string: str = "Samba %h"
    min_protocol: str = "SMB3"
    disable_printing: StrictBool = True
    service_enabled: StrictBool = True
    service_state: Literal["started", "stopped", "restarted"] = "started"

    @field_validator("workgroup", "server_string", "min_protocol")
    @classmethod
    def _single(cls, value: str) -> str:
        return single(value)
