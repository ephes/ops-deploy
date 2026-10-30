"""Fixed original system label and LaunchDaemon path; no app declaration."""

from __future__ import annotations

from typing import Self

from pydantic import model_validator

from ops_deploy.base import RoleConfig

LABEL = "de.wersdoerfer.daybook.weeknotes-reconcile"
PLIST = "/Library/LaunchDaemons/" + LABEL + ".plist"


class WeeknotesDisableConfig(RoleConfig):
    label: str = LABEL
    plist: str = PLIST

    @model_validator(mode="after")
    def original_scope(self) -> Self:
        if self.label != LABEL or self.plist != PLIST:
            raise ValueError("Weeknotes emergency disable requires its original system label and plist")
        return self
