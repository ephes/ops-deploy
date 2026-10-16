"""Shared by the graphyard deploys: field types, the role templates, plan-time probes.

The field types, :class:`Part` and :func:`probe` are logyard's: the two stacks
share the Grafana container and the Docker network, and their configs use the
same vocabulary.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Sequence
from functools import cache
from pathlib import PurePosixPath
from typing import Annotated, Any

import jinja2
from pydantic import Field
from pyinfra.api.operation import OperationMeta
from pyinfra.operations.util import any_changed

from ops_deploy.services.logyard._common import Hostname, ImageRef, Part, Port, Url, Word, probe

__all__ = [
    "EnvValue",
    "Hostname",
    "ImageRef",
    "NumericId",
    "Part",
    "Port",
    "Url",
    "Word",
    "absolute",
    "gate",
    "present",
    "probe",
    "render_role",
    "runuser",
    "to_nice_json",
]

TEMPLATE_PACKAGE = "ops_deploy.services.graphyard"

# Written unquoted into the env file, which systemd reads and bash sources: no
# line breaks, quotes, backslashes, ``$``, backticks or whitespace.
EnvValue = Annotated[str, Field(pattern=r"^[^\s\"'\\$`]*$")]
# A numeric uid or gid (container users have no name on the host).
NumericId = Annotated[str, Field(pattern=r"^[0-9]+$")]


def absolute(value: PurePosixPath) -> PurePosixPath:
    if not value.is_absolute() or ".." in value.parts or value == PurePosixPath("/"):
        raise ValueError("paths must be absolute, without '..', and not '/'")
    return value


def _as_bool(value: Any) -> bool:
    return value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")


def _to_nice_json(value: Any) -> str:
    # Ansible's to_nice_json: indent 4, sorted keys, no trailing spaces.
    return json.dumps(value, indent=4, sort_keys=True, separators=(",", ": "))


@cache
def _environment() -> jinja2.Environment:
    """The role templates, rendered with the options and filters of Ansible's ``template`` module."""

    env = jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["bool"] = _as_bool
    env.filters["to_json"] = lambda value: json.dumps(value)
    env.filters["to_nice_json"] = _to_nice_json
    return env


def render_role(template: str, variables: dict[str, Any]) -> str:
    return _environment().get_template(template).render(**variables)


to_nice_json = _to_nice_json


def runuser(user: str, argv: list[str], *, env: dict[str, str] | None = None) -> str:
    """``argv`` run as ``user`` (the roles' ``become_user``), with ``env`` set."""

    assignments = [f"{key}={value}" for key, value in (env or {}).items()]
    return shlex.join(["runuser", "-u", user, "--", "env", *assignments, *argv])


def gate(planned: bool, triggers: Sequence[OperationMeta | None] = ()) -> dict[str, Any] | None:
    """Global arguments for a step that runs when planning found it needed, or after a trigger changed.

    ``{}``: it runs (a check lists it as a change); ``{"_if": ...}``: it runs
    only if a trigger changed (a conditional change in a check); ``None``: it
    is not needed and is left out, so a check does not list it at all.
    """

    if planned:
        return {}
    ops = present(triggers)
    return {"_if": any_changed(*ops)} if ops else None


def present(ops: Sequence[OperationMeta | None]) -> list[OperationMeta]:
    return [op for op in ops if op is not None]
