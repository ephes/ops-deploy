"""The role's variable namespace: its vendored defaults, the playbook's values, Ansible's Jinja.

``files/deploy_defaults.yml`` and ``files/remove_defaults.yml`` are the
roles' ``defaults/main.yml``, byte for byte (``tests/test_ops_library_drift.py``
compares them). A default that refers to other variables (``{{ openclaw_home
}}/site``) is resolved lazily against the final namespace, as Ansible does,
so a playbook value such as ``openclaw_data_dir`` moves every path below it.

:func:`environment` is a Jinja environment with the Ansible filters and tests
the role's expressions use; :mod:`.validate` evaluates the role's own assert
expressions with it.
"""

from __future__ import annotations

import contextlib
import json
import re
import shlex
import warnings
from collections.abc import Iterable, Mapping
from functools import cache
from pathlib import Path
from typing import Any

import jinja2
import yaml

FILES = Path(__file__).parent / "files"
_WHOLE = re.compile(r"^\{\{(?P<expression>(?:(?!\{\{|\}\}).)*)\}\}$", re.DOTALL)
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


@cache
def defaults(role: str = "deploy") -> dict[str, Any]:
    """The role's ``defaults/main.yml`` (``deploy`` or ``remove``), unresolved."""

    loaded: dict[str, Any] = yaml.safe_load((FILES / f"{role}_defaults.yml").read_text())
    return loaded


def ansible_bool(value: Any) -> bool:
    """Ansible's ``bool`` filter (``to_bool``), including its deprecated ``== 1`` fallback."""

    check: Any = value.lower() if isinstance(value, str) else str(value).lower() if isinstance(value, int) else value
    try:
        if check in {"yes", "on", "true", "1"}:
            return True
        if check in {"no", "off", "false", "0"}:
            return False
        return bool(check == 1)
    except TypeError:
        return False


def semver_key(version: str) -> tuple[int, int, int, int, tuple[Any, ...]]:
    """Sort key of ``version is version(..., version_type='semver')`` (pre-releases sort first)."""

    match = _SEMVER.fullmatch(version)
    if match is None:
        raise ValueError(f"{version!r} is not a semantic version")
    major, minor, patch, pre = match.groups()
    pre_key = tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split(".")) if pre else ()
    return int(major), int(minor), int(patch), 0 if pre else 1, pre_key


def version_at_least(version: str, minimum: str) -> bool:
    """``(version | regex_replace('^v', '')) is version(minimum, '>=', version_type='semver')``."""

    return semver_key(re.sub(r"^v", "", version)) >= semver_key(minimum)


def _version(value: Any, other: str, operator: str = "eq", version_type: str = "loose") -> bool:
    if version_type != "semver":
        raise ValueError("only semver version tests are used by the role")
    left, right = semver_key(str(value)), semver_key(other)
    return {
        ">=": left >= right,
        "ge": left >= right,
        ">": left > right,
        "gt": left > right,
        "<=": left <= right,
        "le": left <= right,
        "<": left < right,
        "lt": left < right,
        "==": left == right,
        "eq": left == right,
        "!=": left != right,
        "ne": left != right,
    }[operator]


def dict2items(value: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [{"key": key, "value": item} for key, item in value.items()]


def _subelements(value: Iterable[Mapping[str, Any]], key: str) -> list[tuple[Any, Any]]:
    return [(item, sub) for item in value for sub in item[key]]


@cache
def environment() -> jinja2.Environment:
    """Jinja with the Ansible filters and tests the role's expressions use."""

    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)
    env.filters.update(
        bool=ansible_bool,
        regex_replace=lambda value, pattern, replacement="": re.sub(pattern, replacement, str(value)),
        dict2items=dict2items,
        subelements=_subelements,
        to_json=json.dumps,
        quote=lambda value: shlex.quote(str(value)),
    )
    env.tests.update(
        regex=lambda value, pattern: re.search(pattern, str(value)) is not None,
        match=lambda value, pattern: re.match(pattern, str(value)) is not None,
        search=lambda value, pattern: re.search(pattern, str(value)) is not None,
        version=_version,
    )
    return env


def evaluate(expression: str, context: Mapping[str, Any]) -> Any:
    """One Jinja expression (no braces) against ``context``."""

    with warnings.catch_warnings():
        # The role's regexes put ``\\s`` in Jinja string literals; Jinja warns, Ansible as well.
        warnings.simplefilter("ignore", DeprecationWarning)
        compiled = environment().compile_expression(expression, undefined_to_none=False)
    return compiled(**context)


def resolve(
    overrides: Mapping[str, Any], *, role: str = "deploy", extra: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """The role's variables: ``overrides`` over its defaults, templated defaults resolved lazily.

    ``extra`` holds the variables outside the role that its defaults read
    (``metrics_httpd_impl``). A value that is one ``{{ expression }}`` keeps
    the expression's type, as with Ansible's templating.
    """

    unknown = sorted(set(overrides) - set(defaults(role)))
    if unknown:
        raise ValueError(f"not variables of the openclaw_{role} role: {', '.join(unknown)}")
    raw: dict[str, Any] = {**defaults(role), **overrides}
    done: dict[str, Any] = {}
    active: set[str] = set()

    def value(name: str) -> Any:
        if name in done:
            return done[name]
        if name in active:
            raise ValueError(f"{name} refers to itself")
        active.add(name)
        try:
            item = raw[name]
            done[name] = render(item) if name not in overrides else item
        finally:
            active.discard(name)
        return done[name]

    class Lazy(dict[str, Any]):
        def __missing__(self, key: str) -> Any:
            if key in raw:
                return value(key)
            if extra is not None and key in extra:
                return extra[key]
            raise KeyError(key)

    def render(item: Any) -> Any:
        if not isinstance(item, str) or "{{" not in item:
            return item
        names = set(re.findall(r"\b([a-z_][a-z0-9_]*)\b", item))
        context = Lazy()
        for name in names:
            with contextlib.suppress(KeyError):
                context[name] = context[name]
        whole = _WHOLE.fullmatch(item.strip())
        if whole:
            return evaluate(whole.group("expression"), context)
        return environment().from_string(item).render(context)

    return {name: value(name) for name in raw}
