"""``ansible.builtin.apt`` with ``state: absent`` and ``purge: true`` for a package list.

At execution time: only the names dpkg knows in a state other than
not-installed (installed or with config files left) are purged, in one
``apt-get --purge remove`` with the module's dpkg options; nothing else runs.
An unreadable package state fails the operation. Like the module, apt
waits up to 60 seconds for the dpkg lock.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from typing import Annotated, Any

from pydantic import Field
from pyinfra.api import DeployError, StringCommand, operation

from ops_deploy.helpers.probes import probe

Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]+$")]

PACKAGES = r"""import json, os, subprocess, sys
STATES = {"installed", "config-files", "half-installed", "unpacked", "half-configured",
          "triggers-awaited", "triggers-pending"}
names = sys.argv[1:]
result = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Status}\n", "--", *names],
    capture_output=True, text=True, check=False, env={**os.environ, "LC_ALL": "C"}, timeout=60)
if result.returncode not in (0, 1):
    raise SystemExit("dpkg-query failed")
selected, seen, missing = [], set(), set()
for line in result.stdout.splitlines():
    package, state = line.split("\t")
    if package not in names or package in seen or state not in STATES | {"not-installed"}:
        raise SystemExit("unexpected package metadata")
    seen.add(package)
    if state in STATES:
        selected.append(package)
prefix = "dpkg-query: no packages found matching "
for line in result.stderr.splitlines():
    if not line.startswith(prefix) or line[len(prefix):] not in names:
        raise SystemExit("unexpected dpkg-query output")
    missing.add(line[len(prefix):])
if seen & missing or seen | missing != set(names) or bool(missing) != (result.returncode == 1):
    raise SystemExit("incomplete package metadata")
print(json.dumps(selected))
"""


def _probe(packages: tuple[str, ...]) -> str:
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", PACKAGES, *packages])


@operation()
def purge(packages: tuple[str, ...], label: str) -> Generator[Any, None, None]:
    if not packages:
        # The apt module with an empty name list changes nothing (and
        # dpkg-query -W without patterns would list every package).
        return
    raw = probe(_probe(packages), name=f"{label} package state")
    try:
        selected = json.loads(raw) if raw is not None else None
    except ValueError:
        selected = None
    if not isinstance(selected, list) or any(name not in packages for name in selected):
        raise DeployError(f"Cannot establish the {label} package state")
    if selected:
        yield StringCommand(
            shlex.join(
                [
                    "env",
                    "DEBIAN_FRONTEND=noninteractive",
                    "apt-get",
                    "-q",
                    "-y",
                    # The module waits up to its lock_timeout (60 s) for the dpkg lock.
                    "-o",
                    "DPkg::Lock::Timeout=60",
                    "-o",
                    "Dpkg::Options::=--force-confdef",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                    "--purge",
                    "remove",
                    "--",
                    *selected,
                ]
            )
        )
