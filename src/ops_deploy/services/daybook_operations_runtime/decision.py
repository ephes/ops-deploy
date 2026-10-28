"""Action-aware normal deploy decision, with no host reads or writes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .config import DaybookRuntimeConfig


@dataclass(frozen=True)
class InstalledRuntime:
    """Evidence gathered by the deployment observer, never an adoption marker.

    resources_current covers exact desired profile (preserving enabled), plist,
    ownership/modes and existing credential equality. source_current includes
    exact resolved Main tracked bytes, clean checkout and declared lock/runtime.
    Neither may be inferred solely from revision text or an installed marker.
    """

    enabled: bool
    source_current: bool
    resources_current: bool


def normal_action(
    cfg: DaybookRuntimeConfig, installed: InstalledRuntime | None
) -> Literal["install_disabled", "pure_verify", "guarded_update"]:
    """Enabled current deployments verify; changed ones use the original update.

    This decision does not authorize the stop/window/update itself. The guarded
    fanout must qualify every component and preserve the original transition
    checks before it can be dispatched. No current desired Main is replaced by
    the installed old commit to manufacture equality.
    """
    if cfg.action != "install" or cfg.start:
        raise ValueError("normal action requires the default disabled-install declaration")
    if installed is None or not installed.enabled:
        return "install_disabled"
    return "pure_verify" if installed.source_current and installed.resources_current else "guarded_update"
