"""Fixed original owner, label and plist; the enabled scheduler is refused."""

from __future__ import annotations

import re
from typing import Self

from pydantic import StrictBool, model_validator

from ops_deploy.base import RoleConfig

LABEL = "de.wersdoerfer.daybook.voice-memo-work"


class VoiceMemoWorkConfig(RoleConfig):
    owner: str
    enabled: StrictBool = False
    retired: StrictBool = False
    home: str = ""
    label: str = LABEL
    plist: str = ""

    @model_validator(mode="after")
    def original_scope(self) -> Self:
        if self.owner in {"root", "CHANGEME"} or not re.fullmatch(r"[a-z_][a-z0-9_-]*", self.owner):
            raise ValueError("Voice Memo work requires the original non-root GUI owner")
        home = "/Users/" + self.owner
        plist = home + "/Library/LaunchAgents/" + LABEL + ".plist"
        if not self.home:
            object.__setattr__(self, "home", home)
        if not self.plist:
            object.__setattr__(self, "plist", plist)
        if self.home != home or self.label != LABEL or self.plist != plist:
            raise ValueError("Voice Memo work requires the original owner home, exact label and plist")
        if self.enabled:
            # The role's enabled branch (credentials, cutoff, plist, bootstrap)
            # is not ported: the job runs as the operations source `memo-work`,
            # and a timer and a source must never both run the same work.
            raise ValueError("Voice Memo work converges only the disabled state; the enabled LaunchAgent is not ported")
        return self
