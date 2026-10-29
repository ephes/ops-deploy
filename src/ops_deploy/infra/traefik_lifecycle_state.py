"""Strict metadata for the two legacy Traefik lifecycle operations.

Only ENOENT is absence. No configuration, ACME state or recovery-record body
is read here. The ordinary deploy's existing probe interface is unchanged.
"""

from __future__ import annotations

import json
import shlex
from typing import cast

from pyinfra.api import DeployError

from ops_deploy.helpers.probes import probe
from ops_deploy.infra.traefik_deploy import TRANSACTION_STATE

PATH_SCRIPT = """import json, os, stat, sys
path = sys.argv[1]
try:
    details = os.lstat(path)
except FileNotFoundError:
    value = None
else:
    value = {'mode': details.st_mode, 'uid': details.st_uid, 'gid': details.st_gid}
print(json.dumps(value))
"""
NAMES_SCRIPT = "import json,os,sys; print(json.dumps(sorted(os.listdir(sys.argv[1]))))"


def path_state(path: str) -> dict[str, int] | None:
    """lstat only; never answer absence on a permissions/tool/transport error."""

    raw = probe(shlex.join(["python3", "-I", "-c", PATH_SCRIPT, path]), name="Traefik lifecycle path metadata")
    try:
        value = json.loads(raw) if raw is not None else ...
    except (ValueError, TypeError):
        value = ...
    if value is not None and (
        not isinstance(value, dict)
        or set(value) != {"mode", "uid", "gid"}
        or not all(type(item) is int for item in value.values())
    ):
        raise DeployError("Traefik lifecycle path metadata could not be established")
    return cast("dict[str, int] | None", value)


def refuse_managed(required: bool, what: str) -> None:
    """Both original guard conditions, without reading transaction records."""

    if required or path_state(TRANSACTION_STATE) is not None:
        raise DeployError(
            f"{what}: this host requires the guarded Traefik transaction workflow. "
            "Full deploy, restore and removal cannot bypass pending or recovery records."
        )


def names_in(path: str) -> list[str]:
    """Names in one directory only, for original empty-root/temporary cleanup."""

    raw = probe(shlex.join(["python3", "-I", "-c", NAMES_SCRIPT, path]), name="Traefik lifecycle directory names")
    try:
        value = json.loads(raw) if raw is not None else None
    except (ValueError, TypeError):
        value = None
    if not isinstance(value, list) or any(
        not isinstance(name, str) or not name or "/" in name or name in {".", ".."} for name in value
    ):
        raise DeployError("Traefik lifecycle directory metadata could not be established")
    return cast("list[str]", value)
