"""Golden files: rendered output that must stay byte for byte what hosts have today.

A golden test renders a file the deploy writes to a host (a unit, an env
file, a route, a config) from synthetic inputs and compares it with the
copy recorded under ``tests/golden``. Identical bytes mean the next deploy
rewrites nothing and restarts nothing. A failing golden test is a decision,
not a bug: if the change to the host file is intended, record the new
render with ``OPS_DEPLOY_UPDATE_GOLDEN=1`` and review the diff of
``tests/golden`` before committing it.

Name the golden directory literally in the test module
(``Path(__file__).parent / "golden" / "<service>"``) so that
``just test-changed`` maps a changed golden file to its test.
"""

from __future__ import annotations

import os
from pathlib import Path

GOLDEN = Path(__file__).parent / "golden"


def assert_golden(path: Path, actual: str | bytes) -> None:
    """``actual`` equals the golden file at ``path`` (or, when updating, becomes it)."""

    data = actual.encode() if isinstance(actual, str) else actual
    if os.environ.get("OPS_DEPLOY_UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_bytes() != data:
            path.write_bytes(data)
        return
    assert path.exists(), f"no golden file {path.relative_to(GOLDEN.parent)}; record it with OPS_DEPLOY_UPDATE_GOLDEN=1"
    expected = path.read_bytes()
    if isinstance(actual, str):
        assert actual == expected.decode(), f"render differs from {path.relative_to(GOLDEN.parent)}"
    else:
        assert actual == expected, f"render differs from {path.relative_to(GOLDEN.parent)}"
