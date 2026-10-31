"""Original shared notifier paths and recipient-pinned authorization inputs."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Self

from pydantic import BaseModel, ConfigDict, SecretStr, StrictStr, model_validator

from ops_deploy.base import RoleConfig

PACKAGE = "ops_deploy.services.daybook_voice_memo_attention_notifier"


class DaybookVoiceMemoAttentionNotifierConfig(RoleConfig):
    script_src: StrictStr
    container: StrictStr = "openclaw-gateway"

    @model_validator(mode="after")
    def original_source(self) -> Self:
        path = PurePosixPath(self.script_src)
        if (
            not path.is_absolute()
            or path.suffix != ".py"
            or ".." in path.parts
            or any(char in self.script_src for char in "\0\r\n")
            or self.container != "openclaw-gateway"
        ):
            raise ValueError("Notifier requires the original absolute standalone Python source and container")
        return self


class DaybookVoiceMemoAttentionNotifierPins(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    public_key: SecretStr
    native_host: SecretStr
    recipient: SecretStr

    @model_validator(mode="after")
    def original_pins(self) -> Self:
        key, host, recipient = (
            value.get_secret_value() for value in (self.public_key, self.native_host, self.recipient)
        )
        if (
            not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}( [A-Za-z0-9._@-]+)?", key)
            or host == "CHANGEME"
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", host)
            or not re.fullmatch(r"[1-9][0-9]{4,19}", recipient)
        ):
            raise ValueError("Notifier dedicated authorization and recipient pins are invalid; values withheld")
        return self
