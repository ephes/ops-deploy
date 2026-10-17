"""Facts whose output must never reach the console.

``pyinfra -vvv`` prints every fact's output. A fact that reads a secret's
digest (the sha256 of a secret file, a probe comparing credentials) or a
password hash (a deployed Traefik route) would print it; :func:`quiet_fact`
loads such a fact with that output switched off.

The switch is the state's ``print_fact_output``, which every host's greenlet
shares. Quiet calls are counted per state: the first saves the setting, the
last restores it, so overlapping calls on several hosts never leave it off.
While one is running, other hosts' facts are not printed either.
"""

from __future__ import annotations

from typing import Any
from weakref import WeakKeyDictionary

from pyinfra import host
from pyinfra.api import FactBase, State

# state -> [quiet calls in progress, print_fact_output before the first]
_QUIET: WeakKeyDictionary[State, list[Any]] = WeakKeyDictionary()


def quiet_fact(cls: type[FactBase[Any]], **kwargs: Any) -> Any:
    """``host.get_fact(cls, **kwargs)`` without printing the fact's output."""

    state = host.state
    entry = _QUIET.setdefault(state, [0, state.print_fact_output])
    if entry[0] == 0:
        entry[1] = state.print_fact_output
    entry[0] += 1
    state.print_fact_output = False
    try:
        return host.get_fact(cls, **kwargs)
    finally:
        entry[0] -= 1
        if entry[0] == 0:
            state.print_fact_output = entry[1]
