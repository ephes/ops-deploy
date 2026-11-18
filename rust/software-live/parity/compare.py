"""Comparison of what the Python program and the Rust binary produce (PLAN.md 6.2).

Both sides are parsed JSON. Values must be equal in type and value (``1``
and ``1.0`` and ``True`` differ) and in their key sets (P1), except where a
field depends on time (P2, PLAN.md 3): ``generated_at_epoch``,
``meta.age_seconds``, ``apt.oldest_security_index_age_seconds`` and the
``checked_at_epoch`` of a lookup answer that was fetched just now (its
``cached`` is ``false`` on both sides). A P2 field must still be a finite
number (not a bool) on both sides, or ``null`` on both. ``checked_at_epoch``
inside ``last_success`` and ``last_success_checked_at_epoch`` come from a
cache file and are P1. An observation's ``error`` (``"<Class>: <message>"``)
must be identical where the message is one the Python program raises itself
(``own_messages``); otherwise the message is the interpreter's or the OS's
and only the class is compared (PLAN.md 4.2 item 5). The JSON text itself
differs by design (compact separators, PLAN.md 4.2 item 3) and is not
compared.

Stdlib only; ``test_compare.py`` covers it on any Python from 3.10 on.
"""

from __future__ import annotations

import math
from typing import Any

TIME_KEYS = frozenset(
    {"generated_at_epoch", "age_seconds", "oldest_security_index_age_seconds"}
)


def is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def p2_field(key: str, python: dict[str, Any], rust: dict[str, Any]) -> bool:
    """Whether ``key`` of these two objects is a time-dependent (P2) field."""
    if key in TIME_KEYS:
        return True
    return (
        key == "checked_at_epoch"
        and python.get("cached") is False
        and rust.get("cached") is False
    )


def error_differs(python: str, rust: str, own_messages: frozenset[str]) -> bool:
    if python == rust:
        return False
    python_class, _, message = python.partition(": ")
    if message in own_messages or not message:
        return True
    return python_class != rust.partition(": ")[0]


def differences(
    python: Any, rust: Any, path: str = "$", own_messages: frozenset[str] = frozenset()
) -> list[str]:
    """Every P1 difference between the two values, as ``path: what`` lines."""
    if isinstance(python, dict) and isinstance(rust, dict):
        problems = []
        if set(python) != set(rust):
            only_python = sorted(set(python) - set(rust))
            only_rust = sorted(set(rust) - set(python))
            problems.append(
                f"{path}: keys only in Python {only_python}, only in Rust {only_rust}"
            )
        for key in sorted(set(python) & set(rust)):
            sub = f"{path}.{key}"
            if p2_field(key, python, rust):
                both_null = python[key] is None and rust[key] is None
                if not both_null and not (
                    is_number(python[key]) and is_number(rust[key])
                ):
                    problems.append(
                        f"{sub}: time field {python[key]!r} vs {rust[key]!r}"
                    )
                continue
            if (
                key == "error"
                and isinstance(python[key], str)
                and isinstance(rust[key], str)
            ):
                if error_differs(python[key], rust[key], own_messages):
                    problems.append(
                        f"{sub}: Python {python[key]!r}, Rust {rust[key]!r}"
                    )
                continue
            problems.extend(differences(python[key], rust[key], sub, own_messages))
        return problems
    if isinstance(python, list) and isinstance(rust, list):
        if len(python) != len(rust):
            return [f"{path}: {len(python)} items in Python, {len(rust)} in Rust"]
        problems = []
        for index, (left, right) in enumerate(zip(python, rust)):
            problems.extend(differences(left, right, f"{path}[{index}]", own_messages))
        return problems
    if type(python) is not type(rust) or python != rust:
        return [f"{path}: Python {python!r}, Rust {rust!r}"]
    return []


def time_spread(python: Any, rust: Any, key: str, limit: float) -> list[str]:
    """A P2 field must still be close on both sides (same run, same clock)."""
    left, right = python.get(key), rust.get(key)
    if is_number(left) and is_number(right) and abs(left - right) > limit:
        return [f"$.{key}: {left!r} and {right!r} are more than {limit} s apart"]
    return []
