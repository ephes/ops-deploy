"""Original configuration ownership rules, evaluated without parsing user YAML.

This module is pure: callers must keep bodies host-local or in protected inputs.
It neither reads a target nor writes configuration or an Ansible backup.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pydantic import StrictBool

from ops_deploy.base._common import RoleConfig

LEGACY_MET = (
    r"(?ms)^# Weather \(you can configure your preferred weather provider\)\n"
    r"weather:\n  - platform: met\n    name: Home\n\n"
)
OBSOLETE = (
    "(?m)^# System monitor$\n"
    "^system_monitor:$\n"
    "^  process:$\n"
    "^    - python3$\n"
    "^  resources:$\n"
    "^    - type: disk_use_percent$\n"
    "^      arg: /$\n"
    "^    - type: memory_free$\n"
    "^    - type: memory_use_percent$\n"
    "^    - type: processor_use$\n"
    "^    - type: processor_temperature$\n"
    "^    - type: last_boot$\\n\\n?",
    "(?m)^# Discovery$\n^discovery:$\n^  ignore:$\n^    - sonos$\n^    - samsung_tv$\\n\\n?",
)


class ConfigurationPolicy(RoleConfig):
    manage_configuration: StrictBool = False
    manage_secrets: StrictBool = False
    manage_includes: StrictBool = False
    overwrite_config: StrictBool = False
    remove_legacy_met_weather_yaml: StrictBool = False


@dataclass(frozen=True)
class ConfigurationEdit:
    """A single original task's desired body, not a physical-write receipt.

    Preserve task order: template then optional exact replacements. Original
    replacement tasks notify restart; template tasks in configuration.yml do not.
    A caller can test current equality before each write, retaining that distinction.
    Bodies are intentionally absent from repr; never serialize this object into
    a controller receipt or error message.
    """

    operation: str
    content: str = field(repr=False)
    restart_on_change: bool
    backup: bool = True


def configuration_edits(
    existing: str | None, rendered: str, policy: ConfigurationPolicy
) -> tuple[ConfigurationEdit, ...]:
    """Return changed bodies in original order using the original pre-task stat.

    ``None`` means absent; an empty file exists. A new file does not run the
    old-file replacements in that invocation. No YAML loader or index opener is
    used and no unowned block is normalized.
    """
    if not policy.manage_configuration:
        return ()
    edits: list[ConfigurationEdit] = []
    body = existing
    if (existing is None or policy.overwrite_config) and body != rendered:
        body = rendered
        edits.append(ConfigurationEdit("template", body, restart_on_change=False))
    if existing is not None:
        assert body is not None
        patterns = ((LEGACY_MET,) if policy.remove_legacy_met_weather_yaml else ()) + OBSOLETE
        for pattern in patterns:
            updated = re.sub(pattern, "", body)
            if updated != body:
                edits.append(ConfigurationEdit("replace", updated, restart_on_change=True))
                body = updated
    return tuple(edits)


def include_content(existing: str | None, rendered: str, policy: ConfigurationPolicy) -> str | None:
    """Desired include body when original management/overwrite guards permit it."""
    if policy.manage_includes and (existing is None or policy.overwrite_config) and existing != rendered:
        return rendered
    return None


def secrets_content(existing: str | None, rendered: str, policy: ConfigurationPolicy) -> str | None:
    """Secrets management is independent of overwrite_config in the original role."""
    if policy.manage_secrets and existing != rendered:
        return rendered
    return None
