"""Exact original binary-unit/truncation comparisons, without an Ansible dependency."""

from __future__ import annotations

import re
from decimal import Decimal

SIZE_PROPERTIES = frozenset(
    {
        "quota",
        "refquota",
        "reservation",
        "refreservation",
        "recordsize",
        "volblocksize",
        "volsize",
        "special_small_blocks",
    }
)
SIZE_RE = re.compile(r"^([0-9]+(?:[.][0-9]+)?)[ ]*([KMGTPEZ]?)(?:I?B)?$", re.IGNORECASE)
POWERS = {unit: power for power, unit in enumerate(" KMGTPEZ")}
POWERS[""] = 0


def size_to_bytes(value: object) -> int:
    match = SIZE_RE.fullmatch(str(value).strip())
    if match is None:
        raise ValueError("invalid native ZFS size")
    number, unit = match.groups()
    return int(Decimal(number) * 1024 ** POWERS[unit.upper()])


def comparable(name: str, value: object) -> str:
    text = str(value)
    if name in SIZE_PROPERTIES:
        if text.lower() == "none":
            return "0"
        if SIZE_RE.fullmatch(text):
            return str(size_to_bytes(text))
    return text
