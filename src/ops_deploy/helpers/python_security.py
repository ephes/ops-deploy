"""certifi/pip security floors for deploys that install a ``uv.lock``.

After the eMudhra/emSign CA compromise (certifi advisory GHSA-6q48-6c7w-9gw2)
an environment must not get certifi below 2026.10.19 or upstream pip below
26.2.2 back from a normal deploy. Two checks, both fail closed:

- :func:`require_lock_floors` reads the locks uv may install on the
  controller (the project's and, for a workspace member, its workspace root's),
  before any operation is planned, and refuses one that locks either package
  below its floor. Packages the lock does not contain are ignored: nothing is added.
- :func:`verify_trust` is a read-only operation after the dependency sync: it
  runs ``templates/python_security_check.py.txt`` with the environment's
  interpreter (``-I -c``, as the service user) and fails if certifi/pip are below
  their floor, imported from outside the environment without a distribution
  package using the system store, or if their bundles contain a distrusted
  root (matched by SHA-256 fingerprint). Explicit trust settings such as
  ``SSL_CERT_FILE`` are not changed or inspected.
"""

from __future__ import annotations

import re
import tomllib
from importlib.resources import files
from pathlib import Path, PurePosixPath

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import server

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.python import _as_user

SECURITY_FLOORS = {"certifi": (2026, 10, 19), "pip": (26, 2, 2)}


def _release(version: object) -> tuple[int, ...] | None:
    text = str(version)
    if not re.fullmatch(r"\d+(\.\d+)*", text):
        return None
    parts = tuple(int(part) for part in text.split("."))
    return parts + (0,) * (3 - len(parts))


def lock_floor_problems(lock_text: str) -> list[str]:
    """Packages ``lock_text`` (a ``uv.lock``) locks below their floor, one message each."""

    packages = tomllib.loads(lock_text).get("package", [])
    if not isinstance(packages, list):
        raise ValueError("uv.lock [[package]] entries are malformed")
    problems = []
    for package in packages:
        name = re.sub(r"[-_.]+", "-", str(package.get("name", ""))).lower()
        if name not in SECURITY_FLOORS:
            continue
        floor = ".".join(map(str, SECURITY_FLOORS[name]))
        locked = _release(package.get("version"))
        if locked is None:
            problems.append(f"{name} {package.get('version')}: version not recognised")
        elif locked < SECURITY_FLOORS[name]:
            problems.append(f"{name} {package['version']} is locked; {floor} or later is required")
    return problems


def project_locks(project: Path, root: Path) -> list[Path]:
    """The ``uv.lock`` files uv may install for ``project`` within the synced tree ``root``.

    A workspace member is installed from its workspace root's lock, so every
    existing ``uv.lock`` from ``project`` up to ``root`` counts.
    """

    project, root = project.resolve(), root.resolve()
    if not project.is_relative_to(root):
        raise ValueError(f"{project} is not inside {root}")
    candidates = [project, *(p for p in project.parents if p.is_relative_to(root))]
    return [lock for lock in (d / "uv.lock" for d in candidates) if lock.is_file()]


def require_lock_floors(project: Path, label: str, *, root: Path | None = None) -> None:
    """Raise ``ValueError`` when a lock uv may install for ``project`` is below a floor.

    Checks :func:`project_locks` (``root`` defaults to ``project``). Without
    any lock it is left to ``uv sync`` (a frozen sync fails without one; an
    unlocked one resolves current releases).
    """

    for lock in project_locks(project, root or project):
        problems = lock_floor_problems(lock.read_text())
        if problems:
            where = lock.relative_to((root or project).resolve())
            raise ValueError(
                f"{label}: {where}, a uv.lock about to be installed, is below the certifi/pip security floor "
                f"({'; '.join(problems)}). Nothing was changed. "
                "Update the stale lock in the source, or deploy a reviewed source revision whose lock meets the floor."
            )


def verify_trust(python: PurePosixPath, *, user: str, home: PurePosixPath, name: str) -> OperationMeta:
    """Read-only operation: ``python``'s environment meets the certifi/pip floors and trusts no distrusted root."""

    script = files("ops_deploy.helpers").joinpath("templates/python_security_check.py.txt").read_text()
    # The script carries no secrets; stdin stays reserved for secret payloads.
    command = _as_user(user, home, {}, [str(python), "-I", "-c", script])
    return mark_read_only(server.shell(name=f"Verify {name} certifi/pip trust", commands=[command]))
