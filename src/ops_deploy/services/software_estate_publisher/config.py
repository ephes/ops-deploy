"""The two ops-library publisher roles' inputs as one typed config.

``platform="linux"``: ``software_estate_publisher_linux`` (root-managed
systemd timer, dedicated ``software-estate-publisher`` account, fixed paths
under ``/etc``, ``/var/lib`` and ``/usr/local``). ``platform="darwin"``:
``software_estate_publisher`` (the owner's ``gui/<uid>`` LaunchAgent, every
file below the owner's home). The writer credential is not part of the
config: it reaches the deploy as a secret.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from ops_deploy.base import RoleConfig

Username = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")]
Hostname = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]
Label = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]+$")]
_PATH = re.compile(r"^/[A-Za-z0-9_./-]+$")

LINUX_ACCOUNT = "software-estate-publisher"
LINUX_PROGRAM = PurePosixPath("/usr/local/lib/software-estate-publisher")
LINUX_CONFIG_DIR = PurePosixPath("/etc/software-estate-publisher")
LINUX_STATE_DIR = PurePosixPath("/var/lib/software-estate-publisher")
LINUX_ENTRY = PurePosixPath("/usr/local/bin/software-estate-publisher")
LINUX_UNIT_DIR = PurePosixPath("/etc/systemd/system")
LINUX_UNITS = ("software-estate-publisher.timer", "software-estate-publisher.service")


def _plain(value: Any) -> Any:
    text = str(value)
    if not _PATH.fullmatch(text) or os.path.normpath(text) != text:
        raise ValueError("paths must be normalized absolute paths of letters, digits, '_', '.', '-' and '/'")
    return value


class SoftwareEstatePublisherConfig(RoleConfig):
    """One host's publisher. ``state="absent"`` removes only the schedule."""

    platform: Literal["linux", "darwin"]
    state: Literal["present", "absent"] = "present"
    # The names the host may report as (role ``*_hostnames``); the host's own
    # short hostname must be one of them.
    hostnames: tuple[Hostname, ...] = Field(min_length=1)
    endpoint: str = ""
    # The controller-side ``scripts/software_estate`` host policy (present only).
    policy: dict[str, Any] | None = None
    # Minute of every hour (Linux role default 23, macOS role default 17).
    minute: int = Field(ge=0, le=59)
    python: PurePosixPath
    # macOS only: the owner whose home and GUI domain hold the publisher.
    owner: Username | None = None
    home: PurePosixPath | None = None
    label: Label = "local.ops.software-estate"
    directory: PurePosixPath | None = None
    credential_file: PurePosixPath | None = None

    @field_validator("python", "home", "directory", "credential_file", mode="before")
    @classmethod
    def _paths(cls, value: Any) -> Any:
        return value if value is None else _plain(value)

    @model_validator(mode="after")
    def _platform(self) -> Self:
        darwin = (self.owner, self.home, self.directory, self.credential_file)
        if self.platform == "linux":
            if any(value is not None for value in darwin):
                raise ValueError("owner, home, directory and credential_file are macOS settings")
        else:
            if self.owner is None or self.home is None or self.directory is None:
                raise ValueError("a macOS publisher needs owner, home and directory")
            if self.home == PurePosixPath("/") or len(self.home.parts) < 3:
                raise ValueError("home must be a user's home directory")
            below = [self.directory, self.credential_file]
            if any(path is not None and self.home not in path.parents for path in below):
                raise ValueError("macOS publisher paths must stay below the owner's home")
        if self.state == "present":
            if not re.fullmatch(r"https://[^\s\"'\\]+", self.endpoint):
                raise ValueError("endpoint must be an https URL")
            if self.policy is None or self.policy.get("host") not in self.hostnames:
                raise ValueError("policy.host must be one of hostnames")
            json.dumps(self.policy, allow_nan=False)
            if self.platform == "darwin" and self.credential_file is None:
                raise ValueError("a macOS publisher needs credential_file")
        return self

    # macOS paths, as the role's defaults derive them from the home.
    @property
    def program(self) -> PurePosixPath:
        if self.platform == "linux":
            return LINUX_PROGRAM
        assert self.home is not None
        return self.home / ".local/share/software-estate-publisher"

    @property
    def config_path(self) -> PurePosixPath:
        if self.platform == "linux":
            return LINUX_CONFIG_DIR / "config.json"
        return self.program / "config.json"

    @property
    def plist(self) -> PurePosixPath:
        assert self.home is not None
        return self.home / "Library/LaunchAgents" / (self.label + ".plist")
