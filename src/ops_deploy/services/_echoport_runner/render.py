"""The runner templates of ops-library's ``echoport_backup`` role, rendered as Ansible's ``template`` renders them.

``templates/`` holds the role's ``templates/*.py.j2`` unchanged (with the
includes ``_work_dir.py.j2`` and ``_sqlite_backup.py.j2``). The ops-library
templates remain the source of runner code; ``tests/test_ops_library_drift.py``
fails when one of them changes. The templates in :data:`FORKED` are the
exception: they have moved on from ops-library's, ops-deploy is their source,
and ops-library's copy serves only the Ansible rollback of their register
playbook (the drift test then notices a change of that copy instead).

Ansible renders with ``trim_blocks``, strips the template's final newline as
Jinja2 does by default and restores one when the template ended in a newline
and the result does not. The filters the templates use beyond plain Jinja2
(``to_json``, ``bool``, ``regex_replace``) behave as ansible-core's for the
values a runner config holds: strings, numbers, booleans, lists and mappings
of them. ``tests/test_echoport_runner_parity.py`` compares the renderings with
files rendered by ``ansible-playbook`` itself. A playbook's inline text
(:func:`render_text`) may also use ``quote`` (ansible-core's, ``shlex.quote``).
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Mapping
from functools import cache
from importlib.resources import files
from typing import Any

import jinja2
from jinja2 import meta

PACKAGE = "ops_deploy.services._echoport_runner"
# The role's templates that are no runner of their own.
INCLUDES = frozenset({"_work_dir.py.j2", "_sqlite_backup.py.j2"})
# Runner templates changed here after the registration moved to pyinfra
# (2026-11-09: restores onto a fresh install); ops-library's copies are the
# Ansible rollback's and stay as they were.
FORKED = frozenset({"minecraft_java_backup.py.j2", "unifi_backup.py.j2", "villakunterbunt_staging_backup.py.j2"})

_TRUE = {"yes", "on", "true", "1"}


def to_json(value: Any, **kwargs: Any) -> str:
    """ansible-core's ``to_json``: ``json.dumps`` with its defaults (ASCII, ``", "`` and ``": "``)."""

    return json.dumps(value, **kwargs)


def ansible_bool(value: Any) -> bool:
    """ansible-core's ``bool``: ``yes``/``on``/``true``/``1`` in any case (and ``True``, ``1``) are true."""

    if isinstance(value, str):
        return value.lower() in _TRUE
    if isinstance(value, int):
        return str(value).lower() in _TRUE
    return bool(value == 1)


def quote(value: Any = "") -> str:
    """ansible-core's ``quote``: ``shlex.quote`` of the value as text (``None`` is the empty text)."""

    return shlex.quote("" if value is None else str(value))


def regex_replace(value: Any = "", pattern: str = "", replacement: str = "") -> str:
    """ansible-core's ``regex_replace`` without flags: ``re.sub`` over the value as text."""

    return re.sub(pattern, replacement, str(value))


@cache
def _environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=False,
        autoescape=False,
    )
    env.filters["to_json"] = to_json
    env.filters["bool"] = ansible_bool
    env.filters["regex_replace"] = regex_replace
    return env


@cache
def _text_environment() -> jinja2.Environment:
    env = jinja2.Environment(
        undefined=jinja2.StrictUndefined, trim_blocks=True, keep_trailing_newline=True, autoescape=False
    )
    env.filters["to_json"] = to_json
    env.filters["bool"] = ansible_bool
    env.filters["regex_replace"] = regex_replace
    env.filters["quote"] = quote
    return env


def text_names(text: str) -> frozenset[str]:
    """The names a playbook's inline text (a task's ``content:``) reads."""

    return frozenset(meta.find_undeclared_variables(_text_environment().parse(text)))


def render_text(text: str, variables: Mapping[str, Any]) -> str:
    """A playbook's inline text (a task's ``content:``) rendered as Ansible templates a module argument.

    The trailing newline stays, as Ansible keeps it for module arguments; an
    undefined name raises.
    """

    return _text_environment().from_string(text).render(**variables)


def runner_templates() -> tuple[str, ...]:
    """The vendored runner templates (without the includes), sorted."""

    return tuple(
        sorted(
            entry.name
            for entry in files(PACKAGE).joinpath("templates").iterdir()
            if entry.name.endswith(".py.j2") and entry.name not in INCLUDES
        )
    )


def render_runner(template: str, variables: Mapping[str, Any]) -> str:
    """``templates/<template>`` rendered with the play's ``variables``; an undefined name raises.

    ``variables`` are the values Ansible would see, already resolved (no
    ``{{ }}`` left in them). A name the template reads with ``default(...)``
    may be left out, as the playbooks leave it out.
    """

    if template in INCLUDES or template not in runner_templates():
        raise ValueError(f"{template!r} is not a vendored runner template")
    env = _environment()
    assert env.loader is not None
    source = env.loader.get_source(env, template)[0]
    text = env.get_template(template).render(**variables)
    if source.endswith("\n") and not text.endswith("\n"):
        text += "\n"
    return text
