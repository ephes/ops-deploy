"""Original dedicated work-source paths and private credential validation."""

from __future__ import annotations

import re
from typing import Self

from pydantic import BaseModel, ConfigDict, SecretStr, StrictStr, model_validator

from ops_deploy.base import RoleConfig


class DaybookWorkSourceAccessConfig(RoleConfig):
    mc_bin: StrictStr = "/usr/local/bin/mc"
    alias: StrictStr = "local"
    python: StrictStr = "/usr/bin/python3"
    state_dir: StrictStr = "/var/lib/daybook-work-source-access"

    @model_validator(mode="after")
    def original_paths(self) -> Self:
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]+", self.alias)
            or not self.mc_bin.startswith("/")
            or not self.python.startswith("/")
            or not re.fullmatch(r"/var/lib/[A-Za-z0-9_-]+", self.state_dir)
        ):
            raise ValueError("Dedicated work source requires its original safe absolute paths")
        return self


class DaybookWorkSourceCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    access_key: SecretStr
    secret_key: SecretStr

    @model_validator(mode="after")
    def original_credentials(self) -> Self:
        access = self.access_key.get_secret_value()
        secret = self.secret_key.get_secret_value()
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{15,127}", access)
            or access == "CHANGEME"
            or not 32 <= len(secret) <= 256
            or any(ord(character) < 32 or ord(character) == 127 for character in secret)
        ):
            raise ValueError("Dedicated work source credentials are invalid; values withheld")
        return self
