"""Dry-run (``--dry``) precision helpers; execution behaviour is unchanged.

pyinfra calls an operation's generator once while planning and again while
executing. Planning counts an operation as a change when its generator yields,
and as a *conditional* change when it also carries ``_if``. These helpers keep
the plan honest: a converged host plans no change, an operation that cannot be
decided before an earlier step has run is labelled conditional, and the
execution path still runs exactly the commands it ran before.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from typing import Any

from pyinfra import state
from pyinfra.api import operation
from pyinfra.api.operation import OperationMeta


def planned(meta: OperationMeta) -> bool:
    """Whether ``meta`` only has a planned result (planning, not yet executed)."""
    return not meta.is_complete() and not state.is_executing


def changed(meta: OperationMeta | None) -> bool:
    """The completed result once executed, the planned result while planning."""
    if meta is None:
        return False
    return meta.will_change if planned(meta) else meta.did_change()


def executing() -> bool:
    """Whether pyinfra is executing (not planning).

    Read-only checks start with ``if not executing(): return``: a check changes
    nothing, so a dry run lists it without a change, and execution regenerates
    the operation and runs the check as before.
    """
    return bool(state.is_executing)


def resolved_at_execution() -> bool:
    """``_if`` marker for an operation only execution can decide (always true).

    The operation then shows under pyinfra's "Conditional Change" column in a
    dry run instead of as a change; while executing the gate always passes.
    """
    return True


def plan_probes() -> bool:
    """Whether planning inspects the host (``--dry`` or an interactive run).

    ``pyinfra -y`` registers without planning; registration-time inspections
    stay off there so the apply path is unchanged.
    """
    return bool(state.should_check_for_changes())


@operation()
def handler(required: Callable[[], bool], operation: Any, arguments: dict[str, Any]) -> Generator[Any, None, None]:
    """A notification handler gated by ``_if=required``.

    ``required`` is evaluated with :func:`changed` semantics: while planning it
    reads the planned results of its triggers, so a dry run lists the handler
    (as conditional) only when a trigger is planned to change.
    """
    if not state.is_executing:
        try:
            needed = required()
        except RuntimeError:
            # A trigger with no planned result (a raw ``did_change``): keep the
            # handler listed as conditional rather than guessing no change.
            needed = True
        if not needed:
            return
    yield from operation._inner(**arguments)
