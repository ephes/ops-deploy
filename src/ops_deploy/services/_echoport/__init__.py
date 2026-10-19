"""The Echoport backup target upsert every service shares.

``files/echoport_target.py`` runs inside Echoport's ``manage.py shell``; its
header lists the parameters. :func:`target_code` puts them in front of it,
:func:`target_shell` wraps that in the echoport user's shell, and
:func:`upsert_target` is the probe-then-apply step around both.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pyinfra.operations import server

from ops_deploy.helpers.probes import last_line, probe, verify_probe, when_present
from ops_deploy.helpers.python import _as_user

TARGET_SCRIPT = (Path(__file__).parent / "files" / "echoport_target.py").read_text()
ECHOPORT_USER = "echoport"
ECHOPORT_SITE = PurePosixPath("/home/echoport/site")


def target_code(params: Mapping[str, Any], mode: Literal["check", "apply"]) -> str:
    """The script with ``PARAMS`` (``params`` plus ``mode``) in front, as ``manage.py shell -c`` takes it."""

    data = json.dumps({**params, "mode": mode})
    return f"PARAMS = {data!r}\nimport json as _j\nPARAMS = _j.loads(PARAMS)\n{TARGET_SCRIPT}"


def target_shell(
    params: Mapping[str, Any],
    mode: Literal["check", "apply"],
    *,
    user: str = ECHOPORT_USER,
    site: PurePosixPath = ECHOPORT_SITE,
) -> str:
    """``manage.py shell -c <target_code>`` in ``site`` as ``user`` (a subshell, so it may be piped into)."""

    run = _as_user(user, PurePosixPath("/home") / user, {}, [".venv/bin/python", "manage.py", "shell", "-c"])
    return f"(cd {shlex.quote(str(site))} && {run} {shlex.quote(target_code(params, mode))})"


def upsert_target(
    params: Mapping[str, Any],
    *,
    name: str,
    missing: str,
    user: str = ECHOPORT_USER,
    site: PurePosixPath = ECHOPORT_SITE,
) -> None:
    """Probe in check mode; apply only when the probe does not say ``unchanged``.

    Without Echoport on the host the apply fails the run with ``missing``.
    """

    check = when_present(
        [site / "manage.py"], last_line(target_shell(params, "check", user=user, site=site)), otherwise="missing"
    )
    state = probe(check, name=name)
    if (state or "").strip() == "unchanged":
        return
    manage = shlex.quote(str(site / "manage.py"))
    server.shell(
        name=name,
        commands=[
            f"test -f {manage} || {{ echo {shlex.quote(missing)} >&2; exit 1; }}",
            target_shell(params, "apply", user=user, site=site) + " </dev/null",
        ],
    )
    if state is None:
        verify_probe(check, name=name, expect="unchanged")
