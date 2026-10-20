"""Configure systemd-journald through one managed drop-in (the ``journald_config`` role).

The drop-in is byte-identical to the role's template, including its
``# Managed by Ansible`` header, so switching a host between the tools
rewrites nothing and restarts nothing. journald has no reload: like the role's
handlers, the deploy restarts ``systemd-journald`` and (for
``Storage=persistent``) runs ``journalctl --flush`` only when the drop-in
changed, never on a converged host.
"""

from __future__ import annotations

import re
import shlex
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import (
    BeforeValidator,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, server
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, output, require_systemd
from ops_deploy.helpers import mark_read_only

DEFAULT_DROPIN = "/etc/systemd/journald.conf.d/60-ops-library.conf"
# The role template's header, byte for byte, then the section line.
HEADER = (
    "# Managed by Ansible (ops-library journald_config role). Do not edit by hand.\n"
    "#\n"
    "# Effective configuration across all files:\n"
    "#   systemd-analyze cat-config systemd/journald.conf\n"
    "[Journal]\n"
)

# The role's patterns (``tasks/main.yml``). Matched in full (``\Z``): Ansible's
# ``match`` test ends them with ``$``, which in Python also accepts one
# trailing newline; such a value is refused here instead.
_DROPIN = re.compile(r"/etc/systemd/journald\.conf\.d/[^/\x00-\x1f\x7f]+\.conf")
_SIZE = re.compile(r"[0-9]+(\.[0-9]+)?[KMGTPE]?")
_COUNT = re.compile(r"[0-9]+")
# systemd time spans: one or more ``<number><unit>`` parts (``21day``,
# ``2weeks 3days``, ``55s500ms``); a bare number means seconds and may only
# stand last, so ``1.51.5day`` is refused, as systemd refuses it.
_TIMESPAN = re.compile(
    r" *(([0-9]+(\.[0-9]+)? *(us|usec|ms|msec|s|sec|seconds?|m|min|minutes?|h|hr|hours?|d|days?|w|weeks?"
    r"|M|months?|y|years?) *)+([0-9]+(\.[0-9]+)?)?|[0-9]+(\.[0-9]+)?) *"
)
_EXTRA_KEY = re.compile(r"[A-Z][A-Za-z0-9]*")
# systemd splits lines on CR and NUL as well as LF; any control character
# could smuggle in a second directive.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_STORAGE = ("persistent", "volatile", "auto", "none", "")

# The role's ``journald_config_managed_settings``: journald key per field, in
# rendering order. An extra setting may not repeat one of these keys.
MANAGED_KEYS = {
    "storage": "Storage",
    "system_max_use": "SystemMaxUse",
    "system_keep_free": "SystemKeepFree",
    "system_max_file_size": "SystemMaxFileSize",
    "system_max_files": "SystemMaxFiles",
    "max_retention_sec": "MaxRetentionSec",
    "max_file_sec": "MaxFileSec",
}
# Everything the role validates and renders only for ``state: present``.
SETTINGS = (*MANAGED_KEYS, "extra_settings")
_SIZES = ("system_max_use", "system_keep_free", "system_max_file_size")
_TIMESPANS = ("max_retention_sec", "max_file_sec")


def _as_text(value: object) -> object:
    # What the role's ``| string`` sees: strings and numbers (``2000`` from
    # YAML). A boolean renders as ``True``, which no pattern accepts.
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        raise ValueError("must be a string or a number")
    return str(value)


Setting = Annotated[str, BeforeValidator(_as_text)]
ExtraValue = StrictBool | StrictInt | StrictFloat | StrictStr


class JournaldConfig(RoleConfig):
    """The role's ``journald_config_*`` variables without the prefix.

    An empty setting leaves the systemd default in place and writes nothing for
    that key. Values are checked only for ``state="present"``, as in the role:
    with ``state="absent"`` the settings are not used and are dropped unchecked
    (they keep their defaults).
    """

    state: Literal["present", "absent"] = "present"
    dropin_path: str = DEFAULT_DROPIN
    storage: Setting = "persistent"
    system_max_use: Setting = ""
    system_keep_free: Setting = ""
    system_max_file_size: Setting = ""
    system_max_files: Setting = ""
    max_retention_sec: Setting = ""
    max_file_sec: Setting = ""
    # Further ``[Journal]`` keys, rendered after the ones above in this order;
    # booleans as ``yes``/``no``.
    extra_settings: dict[StrictStr, ExtraValue] = Field(default_factory=dict)
    # Restart journald (and flush, for persistent storage) when the drop-in changes.
    restart_on_change: bool = True

    @model_validator(mode="before")
    @classmethod
    def _absent_ignores_settings(cls, data: Any) -> Any:
        # The role skips its whole settings validation for ``absent``.
        if isinstance(data, dict) and data.get("state") == "absent":
            return {key: value for key, value in data.items() if key not in SETTINGS}
        return data

    @field_validator("dropin_path")
    @classmethod
    def _dropin_in_conf_d(cls, value: str) -> str:
        if not _DROPIN.fullmatch(value):
            raise ValueError("dropin_path must be a *.conf file directly in /etc/systemd/journald.conf.d/")
        return value

    @model_validator(mode="after")
    def _settings_are_valid(self) -> JournaldConfig:
        if self.state == "absent":
            return self
        if self.storage not in _STORAGE:
            raise ValueError("storage must be persistent, volatile, auto, none or empty")
        for name in _SIZES:
            value = getattr(self, name)
            if value and not _SIZE.fullmatch(value):
                raise ValueError(f"{name} must be a byte count with an optional K/M/G/T/P/E suffix, got {value!r}")
        if self.system_max_files and not _COUNT.fullmatch(self.system_max_files):
            raise ValueError("system_max_files must be a non-negative integer")
        for name in _TIMESPANS:
            value = getattr(self, name)
            if value and not _TIMESPAN.fullmatch(value):
                raise ValueError(f"{name} must be a systemd time span (e.g. 21day, 3week), got {value!r}")
        for key, extra in self.extra_settings.items():
            if not _EXTRA_KEY.fullmatch(key) or key in MANAGED_KEYS.values():
                raise ValueError(
                    f"extra_settings key {key!r} must be a [Journal] key no first-class field already covers"
                )
            if _CONTROL.search(str(extra)):
                raise ValueError(f"extra_settings.{key} must be a single-line value")
        return self


def _extra(value: ExtraValue) -> str:
    return ("yes" if value else "no") if isinstance(value, bool) else str(value)


def render_journald_dropin(cfg: JournaldConfig) -> str:
    """The drop-in the role's ``journald.conf.j2`` renders for ``cfg``."""

    lines = [f"{key}={getattr(cfg, name)}\n" for name, key in MANAGED_KEYS.items() if getattr(cfg, name)]
    lines += [f"{key}={_extra(value)}\n" for key, value in cfg.extra_settings.items()]
    return HEADER + "".join(lines)


# The role fails unless ``systemctl is-active`` prints ``active``.
ACTIVE_CHECK = (
    'state=$(systemctl is-active systemd-journald || true); [ "$state" = active ] || '
    '{ echo "systemd-journald is ${state:-unknown}, not active" >&2; exit 1; }'
)


# ``LC_ALL`` overrides every other locale variable; ``LANG`` is set too.
STAT_KIND = "LC_ALL=C LANG=C stat -c %F"


def _kinds(*paths: PurePosixPath) -> list[str]:
    """``stat`` file type of each path, not following symlinks; ``missing`` if absent.

    ``%F`` names are translated (``Verzeichnis`` under a German locale), so
    each probe runs in the C locale to get the English names matched below.
    """

    probe = "; ".join(f"{STAT_KIND} {shlex.quote(str(path))} 2>/dev/null || echo missing" for path in paths)
    kinds = output(probe).splitlines()
    if len(kinds) != len(paths):
        raise DeployError(f"journald_config: could not read the file types of {', '.join(map(str, paths))}")
    return kinds


@deploy("journald config")
def deploy_journald_config(cfg: JournaldConfig) -> None:
    require_systemd("journald_config")
    path = PurePosixPath(cfg.dropin_path)
    quoted = shlex.quote(str(path))
    directory, dropin = _kinds(path.parent, path)
    # A symlink is replaced (present) or unlinked (absent), never followed, as
    # the role's ``template`` and ``file: state=absent`` do. Anything else in
    # the way is refused before any change, where the role would write into a
    # directory, remove a directory tree or follow a symlinked directory.
    if dropin not in ("missing", "regular file", "regular empty file", "symbolic link"):
        raise DeployError(f"journald_config: {path} is a {dropin}, not a regular file or symlink")
    if cfg.state == "present" and directory not in ("missing", "directory"):
        raise DeployError(f"journald_config: {path.parent} is a {directory}, not a directory")

    changes: list[OperationMeta] = []
    if dropin == "symbolic link" or (cfg.state == "absent" and dropin != "missing"):
        changes.append(server.shell(name=f"Remove {path}", commands=[f"rm -f {quoted}"]))
    if cfg.state == "present":
        files.directory(name=f"Ensure {path.parent}", path=str(path.parent), user="root", group="root", mode="0755")
        # Owner or mode drift counts as a change too, as with the role's template.
        changes.append(
            files.put(
                name=f"Write {path}",
                src=StringIO(render_journald_dropin(cfg)),
                dest=str(path),
                user="root",
                group="root",
                mode="0644",
            )
        )

    # The role's handlers: only a changed (or removed) drop-in restarts
    # journald; the flush only follows a written drop-in with persistent storage.
    if cfg.restart_on_change and changes:
        server.shell(
            name="Restart systemd-journald",
            commands=["systemctl restart systemd-journald"],
            _if=any_changed(*changes),
        )
        if cfg.state == "present" and cfg.storage == "persistent":
            server.shell(
                name="Flush journal to persistent storage",
                commands=["journalctl --flush"],
                _if=any_changed(*changes),
            )

    mark_read_only(server.shell(name="Check systemd-journald is running", commands=[ACTIVE_CHECK]))
