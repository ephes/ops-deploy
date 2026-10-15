"""Shared by the logyard deploys: field types, the role templates, plan-time probes."""

from __future__ import annotations

import base64
import json
from functools import cache
from pathlib import Path
from typing import Annotated, Any

import jinja2
from pydantic import BaseModel, ConfigDict, Field
from pyinfra import host
from pyinfra.facts.server import Command

TEMPLATE_PACKAGE = "ops_deploy.services.logyard"
FILES = Path(__file__).parent / "files"

# Rendered into YAML, unit files and shell commands: plain words only.
Word = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")]
ImageRef = Annotated[str, Field(pattern=r"^[a-z0-9][A-Za-z0-9._/:@-]*$")]
Url = Annotated[str, Field(pattern=r"^https?://[^\s\"'\\$`%]+$")]
Port = Annotated[int, Field(ge=1, le=65535)]
Seconds = Annotated[int, Field(ge=1, le=86400)]
# Systemd specifiers (``%``), backslashes and line breaks would change meaning
# inside the units' ``Environment=`` lines; the unit template escapes quotes.
UnitValue = Annotated[str, Field(pattern=r"^[^\\%\r\n]+$")]
Hostname = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")]


class Part(BaseModel):
    """A nested config section: unknown keys fail, instances are frozen."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)


def _as_bool(value: Any) -> bool:
    return value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")


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
    env.filters["ternary"] = lambda value, yes, no=None: yes if value else no
    env.filters["to_json"] = lambda value: json.dumps(value)
    env.filters["b64encode"] = lambda value: base64.b64encode(value.encode()).decode()
    return env


def render_role(template: str, variables: dict[str, Any]) -> str:
    return _environment().get_template(template).render(**variables)


def probe(command: str) -> str:
    """Stdout of a read-only command, gathered while planning; empty when it fails."""

    return str(host.get_fact(Command, command=f"{command} 2>/dev/null || true") or "")
