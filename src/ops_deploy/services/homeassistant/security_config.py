"""Original python_security_floor include inputs for Home Assistant."""

from __future__ import annotations

import re
from typing import Self

from pydantic import Field, StrictBool, StrictStr, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig

from .security_policy import python_security_constraints


class SecurityEnvironment(RoleConfig):
    path: AbsolutePath
    label: StrictStr


class DistrustedRoot(RoleConfig):
    name: StrictStr
    sha256: StrictStr


class HomeAssistantSecurityConfig(RoleConfig):
    packages: dict[StrictStr, StrictStr] = Field(default_factory=lambda: {"certifi": "2026.10.19", "pip": "26.2.2"})
    requires_python: dict[StrictStr, StrictStr] = Field(default_factory=lambda: {"certifi": ">=3.7", "pip": ">=3.10"})
    distrusted_roots: tuple[DistrustedRoot, ...] = (
        DistrustedRoot(
            name="emSign ECC Root CA - G3", sha256="86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"
        ),
        DistrustedRoot(
            name="AAA Certificate Services", sha256="D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4"
        ),
    )
    deferred: tuple[StrictStr, ...] = ()
    managed_base_prefix: StrictStr = ""
    expected_python_version: StrictStr = ""
    system_store: AbsolutePath = "/etc/ssl/certs/ca-certificates.crt"
    system_store_dirs: tuple[AbsolutePath, ...] = ("/etc/ssl/certs", "/usr/lib/ssl/certs")
    system_python: AbsolutePath = "/usr/bin/python3"
    become: StrictBool = True

    @model_validator(mode="after")
    def original_policy(self) -> Self:
        python_security_constraints(self.packages)
        if self.managed_base_prefix and (
            not re.match(r"^/[^/].*", self.managed_base_prefix)
            or not re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+", self.expected_python_version)
            or self.deferred
        ):
            raise ValueError(
                "Managed base verification requires an absolute prefix, exact Python patch and no deferrals."
            )
        return self
