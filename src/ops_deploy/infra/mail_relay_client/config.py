from __future__ import annotations

import re
from typing import Annotated

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from ops_deploy.base._common import RoleConfig

_DOMAIN = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def line(value: str) -> str:
    if any(char in value for char in "\r\n\0"):
        raise ValueError("configuration values must be single lines")
    return value


class MailRelayClientConfig(RoleConfig):
    enabled: StrictBool = True
    relayhost: str = ""
    port: Annotated[StrictInt, Field(ge=1, le=65535)] = 25
    use_tls: StrictBool = False
    myhostname: str | None = None
    myorigin: str | None = None
    packages: tuple[str, ...] = ("postfix", "bsd-mailx")
    postfix_settings: dict[str, str] = Field(
        default_factory=lambda: {
            "inet_interfaces": "loopback-only",
            "mydestination": "",
            "mynetworks": "127.0.0.0/8 [::1]/128",
            "compatibility_level": "3.6",
        }
    )

    @field_validator("relayhost")
    @classmethod
    def _relay(cls, value: str) -> str:
        line(value)
        if value and not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
            raise ValueError("invalid relayhost")
        return value

    @field_validator("myhostname")
    @classmethod
    def _hostname(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value):
            raise ValueError("invalid Postfix hostname")
        return value

    @field_validator("myorigin")
    @classmethod
    def _origin(cls, value: str | None) -> str | None:
        if value is not None and not _DOMAIN.fullmatch(value):
            raise ValueError("myorigin must be a fully qualified mail domain")
        return value

    @field_validator("postfix_settings")
    @classmethod
    def _settings(cls, values: dict[str, str]) -> dict[str, str]:
        for key, value in values.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
                raise ValueError("invalid Postfix setting name")
            line(value)
        return values

    @model_validator(mode="after")
    def _required(self) -> MailRelayClientConfig:
        if self.enabled and not self.relayhost:
            raise ValueError("relayhost is required when enabled")
        return self

    def desired(self) -> dict[str, str]:
        if self.myhostname is None or self.myorigin is None:
            raise ValueError("resolve the target FQDN before computing Postfix settings")
        values = {
            **self.postfix_settings,
            "relayhost": f"[{self.relayhost}]:{self.port}",
            "myhostname": self.myhostname,
            "myorigin": self.myorigin,
        }
        if self.use_tls:
            values["smtp_tls_security_level"] = "may"
        return values
