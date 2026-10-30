"""Original fixed owner/path relationships and explicit private migration intent."""

from __future__ import annotations

import re
from typing import Literal, Self

from pydantic import ConfigDict, Field, StrictInt, StrictStr, model_validator

from ops_deploy.base import RoleConfig

APPLY_PHRASE = "APPLY monday-after-v1 draft identity migration"
PATH = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"


class IdentityMove(RoleConfig):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)
    week: StrictStr = Field(pattern=r"^\d{4}-W\d{2}$")
    audience: Literal["public", "family"]
    blog_id: StrictInt = Field(ge=1)
    post_id: StrictInt = Field(ge=1)
    expected_revision_id: StrictInt = Field(ge=1)
    from_title: StrictStr = Field(min_length=1)
    from_slug: StrictStr = Field(min_length=1)


class WeeknotesIdentityConfig(RoleConfig):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)
    owner: str
    action: Literal["prepare", "dry-run", "apply", "verify", "status"]
    required_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    confirmation: str = Field(default="", repr=False)
    moves: tuple[IdentityMove, ...] = Field(default=(), repr=False)
    home: str = ""
    checkout: str = ""
    runtime: str = ""
    config_dir: str = "/etc/daybook-sessions"
    helper: str = ""
    launcher: str = ""
    env_file: str = ""
    env_checksum: str = ""
    seed: str = ""
    plan: str = ""
    attestation: str = ""
    proof: str = ""
    state: str = ""
    uv_bin: str = "/opt/homebrew/bin/uv"
    path: str = PATH
    scheduler_label: str = "de.wersdoerfer.daybook.weeknotes-reconcile"
    scheduler_plist: str = "/Library/LaunchDaemons/de.wersdoerfer.daybook.weeknotes-reconcile.plist"

    @model_validator(mode="after")
    def original_scope(self) -> Self:
        if self.owner in {"root", "CHANGEME"} or not re.fullmatch(r"[a-z_][a-z0-9_-]*", self.owner):
            raise ValueError("Identity operators require the original non-root owner")
        home = "/Users/" + self.owner
        runtime = home + "/.daybook/weeknotes-reconcile"
        config = "/etc/daybook-sessions"
        expected = {
            "home": home,
            "checkout": home + "/.local/share/daybook/sessions/daybook",
            "runtime": runtime,
            "config_dir": config,
            "helper": config + "/weeknotes-identity-ops.py",
            "launcher": config + "/weeknotes-identity-ops.sh",
            "env_file": config + "/weeknotes-reconcile.env",
            "env_checksum": config + "/weeknotes-reconcile.env.sha256",
            "seed": runtime + "/identity-migration-seed.json",
            "plan": runtime + "/identity-migration-plan.json",
            "attestation": runtime + "/identity-migration-attestation.json",
            "proof": config + "/weeknotes-identity-activation-proof.json",
            "state": runtime + "/state.json",
        }
        for key, value in expected.items():
            current = getattr(self, key)
            if not current:
                object.__setattr__(self, key, value)
            elif current != value:
                raise ValueError("Identity operators require the original exact path relationships")
        if (
            self.uv_bin != "/opt/homebrew/bin/uv"
            or self.path != PATH
            or self.scheduler_label != "de.wersdoerfer.daybook.weeknotes-reconcile"
            or self.scheduler_plist != "/Library/LaunchDaemons/" + self.scheduler_label + ".plist"
        ):
            raise ValueError("Identity operators require their original executable and timer declarations")
        if self.action == "apply" and self.confirmation != APPLY_PHRASE:
            raise ValueError("Identity apply requires the original exact business phrase")
        if self.action != "status" and not self.moves:
            raise ValueError("Identity operators require nonempty exact private intent")
        return self
