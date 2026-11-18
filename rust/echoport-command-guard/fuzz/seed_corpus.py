#!/usr/bin/env python3
"""Seed the fuzz corpora from the Layer-1 fixtures (PLAN.md 7.4).

Writes one file per input into ``fuzz/corpus/<target>/`` (named by its
sha1, as libFuzzer names its corpus files), next to what earlier runs
committed:

- ``prefilter_tokens`` and ``py_repr``: every distinct fixture command;
- ``check``: every distinct command of the decision fixtures with the flag
  byte of its policy and a NUL, the commands of the curated sources (not the
  mutations) also with a few host choices;
- ``policy``: every ``--check-policy`` document and the two test policies.

Stdlib only: ``python3 -I fuzz/seed_corpus.py``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

FUZZ = Path(__file__).resolve().parent
FIXTURES = FUZZ.parent / "fixtures"
HOSTS = [b"", b"\x01\x00" * 4, b"\x03\xe0" * 4, b"\x2d\x40\x16\x01" * 3, b"\x08\x00\x3c\x02" * 3]


def write(target: str, data: bytes) -> None:
    directory = FUZZ / "corpus" / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / hashlib.sha1(data).hexdigest()).write_bytes(data)


def main() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    commands: dict[bytes, tuple[int, bool]] = {}
    for name in manifest["decision_files"]:
        for line in (FIXTURES / name).read_text().splitlines():
            case = json.loads(line)
            raw = bytes.fromhex(case["command_hex"]) if "command_hex" in case else case["command"].encode()
            # The other host states only for the curated sources, not the mutations.
            curated = not name.startswith("mutation/")
            commands.setdefault(raw, (1 if case["policy"] == "staging" else 0, curated))
    for raw, (flags, curated) in sorted(commands.items()):
        write("prefilter_tokens", raw)
        write("py_repr", raw)
        if b"\0" not in raw:
            for host in HOSTS if curated else HOSTS[:1]:
                write("check", bytes([flags]) + raw + b"\0" + host)
    for name in manifest["policy_files"]:
        for line in (FIXTURES / name).read_text().splitlines():
            case = json.loads(line)
            write("policy", bytes.fromhex(case["policy_hex"]) if "policy_hex" in case else case["policy_text"].encode())
    for policy in sorted((FIXTURES / "policies").glob("*.json")):
        write("policy", policy.read_bytes())


if __name__ == "__main__":
    main()
