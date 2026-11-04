"""The role's ``tasks/validate.yml``, evaluated as the role evaluates it.

``files/validate.yml`` is the role's file, byte for byte. Every
``ansible.builtin.assert`` task in it runs here with its ``when``, ``loop``
and ``vars`` against the resolved variables (:mod:`.variables`), so the port
accepts exactly what the role accepts. The two asserts on registered ``stat``
results (the ``mc`` client binary, the prepared CA bundle) need the host:
:func:`host_checks` returns them as shell tests, which the deploy runs as
read-only operations before any change.

A failure names the task and the first failing expression, never a value:
several of the asserts read credentials (the role marks them ``no_log``).
"""

from __future__ import annotations

import shlex
from functools import cache
from typing import Any

import yaml

from ops_deploy.services.openclaw.variables import FILES, ansible_bool, evaluate

HOST_REGISTERED = ("openclaw_weeknotes_s3_mc_stat", "openclaw_ca_bundle")


class ValidationError(ValueError):
    """An assert of the role's validate.yml failed (message without values)."""


@cache
def tasks() -> list[dict[str, Any]]:
    loaded: list[dict[str, Any]] = yaml.safe_load((FILES / "validate.yml").read_text())
    return loaded


def _conditions(value: Any) -> list[str]:
    if value is None:
        return []
    return [str(item) for item in value] if isinstance(value, list) else [str(value)]


def _template(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str) and value.strip().startswith("{{") and value.strip().endswith("}}"):
        return evaluate(value.strip()[2:-2], context)
    return value


def _true(expression: str, context: dict[str, Any]) -> bool:
    result = evaluate(expression, context)
    if not isinstance(result, bool):
        # ansible-core 2.19+ refuses a conditional that is not a boolean.
        raise TypeError("conditional result is not a boolean")
    return result


def run_asserts(
    tasks: list[dict[str, Any]], variables: dict[str, Any], *, skip: tuple[str, ...] = HOST_REGISTERED
) -> None:
    """Evaluate every ``ansible.builtin.assert`` of ``tasks`` (with ``when``, ``loop`` and ``vars``).

    Asserts that name a variable of ``skip`` (results the host registers) are
    left out. Raises :class:`ValidationError` naming the task and expression.
    """

    for task in tasks:
        check = task.get("ansible.builtin.assert")
        if check is None:
            continue
        expressions = _conditions(check["that"])
        if any(name in expression for expression in expressions for name in skip):
            continue
        try:
            items = _template(task["loop"], dict(variables)) if "loop" in task else [None]
            for item in items:
                scoped = dict(variables) if item is None else {**variables, "item": item}
                # Task vars are templated per item, in order (they may read ``item`` and each other).
                for key, value in (task.get("vars") or {}).items():
                    scoped[key] = _template(value, scoped)
                if not all(_true(condition, scoped) for condition in _conditions(task.get("when"))):
                    continue
                for expression in expressions:
                    if not _true(expression, scoped):
                        raise ValidationError(f"{task['name']}: `{expression.strip()}` is false")
        except ValidationError:
            raise
        except Exception as error:
            # Undefined variables and type errors fail the role's assert too.
            raise ValidationError(f"{task['name']}: {type(error).__name__}") from None


def validate(variables: dict[str, Any]) -> None:
    """Run every assert of validate.yml that needs no host; raise :class:`ValidationError`."""

    run_asserts(tasks(), variables)


def host_checks(variables: dict[str, Any]) -> list[tuple[str, str]]:
    """(task name, shell test) of the stat-based asserts that apply to ``variables``."""

    checks: list[tuple[str, str]] = []
    if ansible_bool(variables["openclaw_weeknotes_enabled"]) and variables["openclaw_weeknotes_backend"] == "s3":
        mc = shlex.quote(str(variables["openclaw_weeknotes_s3_mc_host_path"]))
        checks.append(("validate | Weeknotes S3 client binary is executable", f"test -e {mc} && test -x {mc}"))
    if len(variables["openclaw_ca_store_path"]) > 0:
        bundle = shlex.quote(str(variables["openclaw_ca_store_path"]) + "/bundle.pem")
        checks.append(
            (
                "validate | Require prepared replacement CA bundle before activation",
                f"test -f {bundle} && test ! -L {bundle}",
            )
        )
    return checks


__all__ = ["ValidationError", "host_checks", "run_asserts", "validate"]
