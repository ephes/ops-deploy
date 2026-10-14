"""Render Jinja2 templates shipped inside service packages."""

from __future__ import annotations

from functools import cache
from typing import Any

import jinja2


@cache
def _environment(package: str) -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader(package, "templates"),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render(package: str, template: str, **context: Any) -> str:
    """Render ``templates/<template>`` from ``package``; undefined names raise."""

    return _environment(package).get_template(template).render(**context)
