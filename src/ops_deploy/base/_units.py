"""systemd unit state, keyed by the name asked for (aliases included)."""

from __future__ import annotations

import shlex
from collections.abc import Sequence

from pyinfra import host
from pyinfra.api import FactBase

PROPERTIES = ("Id", "LoadState", "ActiveState", "UnitFileState")
# States in which ``systemctl stop`` has something to stop.
ACTIVE = frozenset({"active", "activating", "reloading"})
# States ``systemctl disable`` changes; ``static``/``indirect`` units have nothing to disable.
ENABLED = frozenset({"enabled", "enabled-runtime", "linked", "linked-runtime"})
UNIT_SUFFIXES = (
    ".service",
    ".socket",
    ".device",
    ".mount",
    ".automount",
    ".swap",
    ".target",
    ".path",
    ".timer",
    ".slice",
    ".scope",
)


class UnitStates(FactBase[list[dict[str, str]]]):
    """``systemctl show`` properties per requested unit.

    pyinfra's ``SystemdStatus``/``SystemdEnabled`` key units by ``Id``, which
    is the target of an alias (``gdm3.service`` shows ``Id=gdm.service``), so
    an alias never matches. This runs ``systemctl show`` once per unit, each
    block ended by a ``---`` line, and maps the blocks back to the names asked for.
    """

    default = list

    def command(self, units: Sequence[str]) -> str:
        props = " ".join(f"--property {name}" for name in PROPERTIES)
        return f'for unit in {shlex.join(units)}; do systemctl show {props} -- "$unit"; echo ---; done'

    def process(self, output: list[str]) -> list[dict[str, str]]:
        blocks: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in output:
            if line.strip() == "---":
                blocks.append(current)
                current = {}
            elif "=" in line:
                key, _, value = line.strip().partition("=")
                current[key] = value
        return blocks


def unit_states(units: Sequence[str]) -> dict[str, dict[str, str]]:
    """State per unit in ``units``; an empty dict for none."""

    if not units:
        return {}
    blocks = host.get_fact(UnitStates, units=list(units)) or []
    if len(blocks) != len(units):
        raise ValueError(f"systemctl show returned {len(blocks)} blocks for {len(units)} units")
    return dict(zip(units, blocks, strict=True))


def unit_name(name: str) -> str:
    """systemd's own default: a name without a type suffix is a ``.service``."""

    return name if name.endswith(UNIT_SUFFIXES) else f"{name}.service"
