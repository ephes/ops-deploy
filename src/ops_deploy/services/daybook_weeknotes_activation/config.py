"""Separate original enable phrase and strict retirement admission."""

from __future__ import annotations

from typing import Self

from pydantic import ConfigDict, Field, StrictBool, model_validator

from ops_deploy.base import RoleConfig
from ops_deploy.services.daybook_weeknotes_identity import WeeknotesIdentityConfig

ENABLE_PHRASE = "ENABLE monday-after-v1 draft schedule"


class WeeknotesActivationConfig(RoleConfig):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)
    identity: WeeknotesIdentityConfig = Field(repr=False)
    confirmation: str = Field(repr=False)
    retired: StrictBool = False
    reconcile_launcher: str = "/etc/daybook-sessions/reconcile-weeknotes.sh"
    launchctl_bin: str = "/bin/launchctl"

    @model_validator(mode="after")
    def original_scope(self) -> Self:
        if self.retired or self.confirmation != ENABLE_PHRASE:
            raise ValueError("Weeknotes activation requires its original confirmation and an unretired timer")
        if self.identity.action != "apply":
            raise ValueError("Weeknotes activation requires fresh same-run verified apply")
        if (
            self.reconcile_launcher != "/etc/daybook-sessions/reconcile-weeknotes.sh"
            or self.launchctl_bin != "/bin/launchctl"
        ):
            raise ValueError("Weeknotes activation requires original fixed executable paths")
        return self
