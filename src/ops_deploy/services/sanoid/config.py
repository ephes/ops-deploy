"""Snapshot policy; deployment never invokes Sanoid or ZFS."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, StrictStr, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig

Scalar = StrictStr | StrictInt


def line(value: str) -> str:
    if not value or any(c in value for c in "\n\r\0[]"):
        raise ValueError("expected a nonempty single configuration value")
    return value


class SanoidDataset(RoleConfig):
    name: str
    template: str = ""
    sanoid_skip: StrictBool = False
    autosnap: Literal["yes", "no"] | None = None
    autoprune: Literal["yes", "no"] | None = None

    @field_validator("name", "template", "autosnap", "autoprune")
    @classmethod
    def _line(cls, value: str | None) -> str | None:
        return line(value) if value else value


class SanoidConfig(RoleConfig):
    enabled: StrictBool = True
    packages: tuple[str, ...] = ("sanoid",)
    config_path: AbsolutePath = "/etc/sanoid/sanoid.conf"
    config_owner: str = "root"
    config_group: str = "root"
    config_mode: Annotated[str, Field(pattern=r"^0?[0-7]{3}$")] = "0644"
    templates: dict[str, dict[str, Scalar]]
    datasets: tuple[SanoidDataset, ...]
    manage_systemd: StrictBool = True
    service_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+\.service$")] = "sanoid-ops-library.service"
    timer_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+\.timer$")] = "sanoid-ops-library.timer"
    disable_package_timers: StrictBool = True
    on_calendar: str = "hourly"
    randomized_delay_sec: str = "15m"
    executable: AbsolutePath = "/usr/sbin/sanoid"
    cron_args: str = "--cron"

    @field_validator("on_calendar", "randomized_delay_sec", "cron_args", "config_owner", "config_group")
    @classmethod
    def _single(cls, value: str) -> str:
        return line(value)

    @model_validator(mode="after")
    def _policy(self) -> SanoidConfig:
        if not self.templates or not self.datasets:
            raise ValueError("Sanoid templates and datasets are required")
        for name, options in self.templates.items():
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or not options:
                raise ValueError("invalid Sanoid template")
            for key, value in options.items():
                if not re.fullmatch(r"[A-Za-z0-9_]+", key):
                    raise ValueError("invalid Sanoid option")
                line(str(value))
                if key in {"autosnap", "autoprune"}:
                    if value not in {"yes", "no"}:
                        raise ValueError("Sanoid autosnap/autoprune must be yes or no")
                elif key in {"frequently", "hourly", "daily", "weekly", "monthly", "yearly"}:
                    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                        raise ValueError("Sanoid retention counts must be nonnegative integers")
                else:
                    raise ValueError("unsupported Sanoid policy option")
        names = [ds.name for ds in self.datasets if not ds.sanoid_skip]
        if len(names) != len(set(names)):
            raise ValueError("duplicate Sanoid dataset")
        for ds in self.datasets:
            if not ds.sanoid_skip and (not ds.name or ds.template not in self.templates):
                raise ValueError("dataset must reference an existing Sanoid template")
        return self
