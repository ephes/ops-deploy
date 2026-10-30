"""Original fixed-label emergency and removal declarations."""

from __future__ import annotations

import re
from typing import Literal, Self

from pydantic import StrictBool, model_validator

from ops_deploy.base import RoleConfig

LABELS = {
    "photos": "de.wersdoerfer.daybook.photos-offload",
    "archive": "de.wersdoerfer.daybook.photos-archive-sync",
    "attention": "de.wersdoerfer.daybook.voice-memo-attention",
}


class DaybookControlConfig(RoleConfig):
    service: Literal["photos", "archive", "attention"]
    action: Literal["disable", "remove"]
    owner: str
    home: str = ""
    label: str = ""
    confirmed: StrictBool = False

    @model_validator(mode="after")
    def original_scope(self) -> Self:
        if self.owner in {"root", "CHANGEME"} or not re.fullmatch(r"[a-z_][a-z0-9_-]*", self.owner):
            raise ValueError("Daybook controls require the original non-root GUI owner")
        if not self.home:
            object.__setattr__(self, "home", "/Users/" + self.owner)
        if not self.label:
            object.__setattr__(self, "label", LABELS[self.service])
        if self.home != "/Users/" + self.owner or self.label != LABELS[self.service]:
            raise ValueError("Daybook controls require the original owner home and exact label")
        if self.service == "attention":
            if self.action != "remove" or not self.confirmed:
                raise ValueError("Attention plist removal requires explicit confirmation")
        elif self.action != "disable":
            raise ValueError("Photos and archive expose only original emergency disable")
        return self
