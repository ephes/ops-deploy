from __future__ import annotations

import re

from pydantic import StrictBool, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.infra.mail_relay_client.config import line


class ZedConfig(RoleConfig):
    enabled: StrictBool = True
    email_to: str = ""
    email_prog: str = "mail"
    rc_path: AbsolutePath = "/etc/zfs/zed.d/zed.rc"
    packages: tuple[str, ...] = ("zfs-zed",)
    service_name: str = "zfs-zed"
    manage_scrub_timer: StrictBool = True
    scrub_pools: tuple[str, ...] = ()
    scrub_timer_on_calendar: str = "weekly"
    scrub_timer_randomized_delay_sec: str = "6h"
    scrub_service_template: str = "zpool-scrub@.service"
    scrub_timer_template: str = "zpool-scrub@.timer"
    scrub_wait_for_completion: StrictBool = False
    scrub_spindown_enabled: StrictBool = False
    scrub_spindown_script_path: AbsolutePath | None = None

    @field_validator(
        "email_to",
        "email_prog",
        "service_name",
        "scrub_timer_on_calendar",
        "scrub_timer_randomized_delay_sec",
        "scrub_service_template",
        "scrub_timer_template",
    )
    @classmethod
    def _line(cls, value: str) -> str:
        line(value)
        if '"' in value or "`" in value or "$" in value or "\\" in value:
            raise ValueError("unsafe ZED configuration value")
        return value

    @field_validator("scrub_pools")
    @classmethod
    def _pools(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(not re.fullmatch(r"[A-Za-z0-9_.:-]+", value) for value in values):
            raise ValueError("invalid scrub pool names")
        return values

    @model_validator(mode="after")
    def _required(self) -> ZedConfig:
        for value in (self.scrub_service_template, self.scrub_timer_template, self.service_name):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@_.-]*", value):
                raise ValueError("invalid ZED unit name")
        if ".." in self.rc_path.split("/"):
            raise ValueError("invalid ZED configuration path")
        if self.enabled and not self.email_to:
            raise ValueError("ZED requires a mail recipient")
        if (
            self.enabled
            and self.manage_scrub_timer
            and self.scrub_spindown_enabled
            and self.scrub_spindown_script_path is None
        ):
            raise ValueError("scrub spindown requires the existing supplied helper")
        return self
