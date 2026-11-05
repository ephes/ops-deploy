"""A register playbook's own Nyxmon check script, with a check mode (graphyard's backup freshness check).

graphyard's register playbook upserts its Nyxmon check with a script of its
own (run as the Nyxmon user with ``python3 -`` and the database and service in
the environment). It differs from ``nyxmon_site_checks`` and from
``_nyxmon_json_metrics``: it re-enables a disabled check only when another
field differs, and the playbook skips it when the Nyxmon database is missing.
So the port keeps the script (``files/nyxmon/<name>.py``, its values from
``VALUES``) and ``files/runner_nyxmon.py`` runs it in a check mode (the
database opened read only; ``unchanged``, ``pending`` or the refusal) and in
apply mode:

- while planning, the database is looked for as the playbook's ``stat`` does:
  without it nothing is planned (the playbook's "skipping" message);
- otherwise the check runs; a refusal stops the deploy before any write and
  ``unchanged`` adds no operation;
- otherwise the script runs once and the check runs again, which must then say
  ``unchanged``.

The script and its values (the check data, which may carry a monitor login
under a harmless name) reach the host on stdin, never in argv; the
environment the playbook sets (the database path and the service name) is in
argv, as the playbook's task sets it. :class:`NyxmonScript` still refuses
top-level value names that look like a secret. The check works only for a
script that opens its database with ``sqlite3.connect(...)``, which
:class:`NyxmonScript` requires.
"""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator
from pyinfra import host, logger
from pyinfra.api import DeployError

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.probes import last_line, probe, verify_probe
from ops_deploy.helpers.python import _as_user
from ops_deploy.ops import secret_stdin
from ops_deploy.services._echoport_runner.target import _SECRET_NAME

PRELUDE = (Path(__file__).parent / "files" / "runner_nyxmon.py").read_text()
PACKAGE = "ops_deploy.services._echoport_runner"
NO_DATABASE = "no-database"


def nyxmon_scripts() -> tuple[str, ...]:
    """The playbook Nyxmon scripts kept here (``files/nyxmon/<name>.py``), by name."""

    folder = files(PACKAGE).joinpath("files", "nyxmon")
    return tuple(sorted(entry.name.removesuffix(".py") for entry in folder.iterdir() if entry.name.endswith(".py")))


def nyxmon_script(name: str) -> str:
    """The text of ``files/nyxmon/<name>.py``: the playbook's script with its values read from ``VALUES``."""

    if name not in nyxmon_scripts():
        raise ValueError(f"{name!r} is not a kept Nyxmon check script")
    return files(PACKAGE).joinpath("files", "nyxmon", f"{name}.py").read_text()


class NyxmonScript(RoleConfig):
    """One playbook Nyxmon script: the check's name (for messages), the script, its values and environment."""

    name: Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[^\n]+$")]
    script: str = Field(min_length=1)
    values: Mapping[str, Any]
    service_name: Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[^\n]+$")]
    db_path: PurePosixPath = PurePosixPath("/home/nyxmon/site/db.sqlite3")
    user: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")] = "nyxmon"

    @field_validator("values")
    @classmethod
    def _no_secrets(cls, values: Mapping[str, Any]) -> Mapping[str, Any]:
        # Top-level names only: graphyard's whole check list is one JSON text.
        for key in values:
            if _SECRET_NAME.search(str(key)):
                raise ValueError("Nyxmon script values must not hold a secret (names that look like one are refused)")
        json.dumps(values)  # JSON only
        return values

    @field_validator("script")
    @classmethod
    def _connects_through_the_module(cls, script: str) -> str:
        # The check opens the database read only by replacing ``sqlite3.connect``;
        # a script holding its own reference to ``connect`` would write.
        if "sqlite3.connect(" not in script or "from sqlite3 import" in script:
            raise ValueError("the Nyxmon script must open its database with sqlite3.connect(...)")
        return script

    @property
    def environment(self) -> dict[str, str]:
        """The playbook task's ``environment``."""

        return {"NYXMON_DB_PATH": str(self.db_path), "NYXMON_SERVICE_NAME": self.service_name}


# The prelude reads ``PARAMS`` from its first stdin line (base64 JSON), so the check data stays off argv.
CODE = f"import base64 as _b, json as _j, sys as _s\nPARAMS = _j.loads(_b.b64decode(_s.stdin.readline()))\n{PRELUDE}"


def nyxmon_stdin(script: NyxmonScript, mode: Literal["check", "apply"]) -> str:
    """The stdin line carrying ``PARAMS`` (mode, script, values) for :data:`CODE`."""

    params = {"mode": mode, "script": script.script, "values": script.values}
    return base64.b64encode(json.dumps(params).encode()).decode() + "\n"


def nyxmon_command(script: NyxmonScript) -> str:
    """``python3 -I -c <CODE>`` as the Nyxmon user with the playbook's environment (``PARAMS`` on stdin)."""

    home = PurePosixPath("/home") / script.user
    return _as_user(script.user, home, script.environment, ["python3", "-I", "-c", CODE])


def _check_command(script: NyxmonScript) -> str:
    db = shlex.quote(str(script.db_path))
    return f"if [ -e {db} ]; then {last_line(nyxmon_command(script))}; else echo {NO_DATABASE}; fi"


def upsert_nyxmon_script(script: NyxmonScript) -> None:
    """The playbook's Nyxmon steps: skip without a database, else check, apply when not ``unchanged``, check again."""

    label = f"Nyxmon check {script.name}"
    check = _check_command(script)
    payload = nyxmon_stdin(script, "check")
    answer = (probe(check, name=label, stdin=payload) or "").strip()
    if answer == NO_DATABASE:
        # The playbook: "Nyxmon DB not found ..., skipping ... provisioning."
        logger.info(f"{host.print_prefix}Nyxmon database not found at {script.db_path}; skipping {label}")
        return
    if answer.startswith("refused:"):
        raise DeployError(f"{label}: {answer}")
    if answer == "unchanged":
        return
    secret_stdin(
        name=f"Upsert {label}",
        command=(
            f"out=$( {nyxmon_command(script)} ) || exit 1; "
            '[ "$(printf "%s\\n" "$out" | tail -n 1)" = applied ] '
            "|| { echo 'the Nyxmon script did not apply' >&2; exit 1; }"
        ),
        content=SecretContent(nyxmon_stdin(script, "apply")),
    )
    verify_probe(check, name=label, expect="unchanged", stdin=payload)


__all__ = [
    "CODE",
    "NO_DATABASE",
    "PRELUDE",
    "NyxmonScript",
    "nyxmon_command",
    "nyxmon_script",
    "nyxmon_scripts",
    "nyxmon_stdin",
    "upsert_nyxmon_script",
]
