"""thermal_monitoring without ``fan_control`` plans exactly what it planned before fan control existed.

``tests/golden/thermal_monitoring_plans.json`` was recorded from the deploy
before the optional ``fan_control`` block was added (ops-deploy main
``5d30630``) with ``python -m tests.test_thermal_monitoring_golden``: for four
host states (converged, fresh, exporter drift, changed password) every
operation with its flags, every command the fake connector saw (planning and
execution, hashed), every upload (path and content hash) and every stdin
payload (hashed; the htpasswd entry carries a random bcrypt salt and is left
out). A config without ``fan_control`` (the macmini deploy) must reproduce it
byte for byte. On 2026-10-27 only eight shared Rust host-script stdin hashes
were refreshed for read-only layout validation; operations, commands and uploads
remained identical.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.thermal_monitoring import deploy_thermal_monitoring
from ops_deploy.testing import run_deploy_fake
from ops_deploy.testing.harness import secret_file_destination
from tests import fakehost
from tests.test_thermal_monitoring import CFG, EXPORTER, FRESH, SECRETS, converged, htpasswd

GOLDEN = Path(__file__).parent / "golden" / "thermal_monitoring_plans.json"


def _digest(text: str | bytes) -> str:
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


# pyinfra looks up the host's temporary directory once per process and caches it, so whether
# this fact shows up depends on the tests that ran before; it is pyinfra's, not the deploy's.
TMPDIR_FACT = 'if [ -n "$TMPDIR" ]'


def record(responses: dict[str, Any]) -> dict[str, Any]:
    result = run_deploy_fake(deploy_thermal_monitoring, CFG, SECRETS, responses=responses)
    events = [event for event in result.events if not event.value.startswith(TMPDIR_FACT)]
    stdin = []
    for command, payload in result.stdin:
        secret = secret_file_destination(command) is not None
        stdin.append([_digest(command), "secret_file" if secret else _digest(payload)])
    return {
        "succeeded": result.succeeded,
        "ops": [[op.name, op.changed, op.succeeded, op.read_only] for op in result.ops],
        "events": [[event.phase, event.kind, _digest(event.value)] for event in events],
        "uploads": [[path, _digest(content)] for path, content in result.uploads],
        "stdin": stdin,
    }


def scenarios() -> dict[str, dict[str, Any]]:
    drift = converged()
    drift.update(fakehost.file(EXPORTER, "#!/usr/bin/env python3\n", mode="-rwxr-xr-x"))
    password = converged()
    password.update(htpasswd(f"nyxmon:{hash_password('old-password')}\n"))
    return {"converged": converged(), "fresh": FRESH, "exporter drift": drift, "changed password": password}


def test_without_fan_control_the_plans_are_the_recorded_ones() -> None:
    assert CFG.fan_control is None
    golden = json.loads(GOLDEN.read_text())

    for name, responses in scenarios().items():
        assert record(responses) == golden[name], name
    assert set(golden) == set(scenarios())


if __name__ == "__main__":
    json.dump({name: record(r) for name, r in scenarios().items()}, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
