"""Render Jinja2 templates shipped inside service packages."""

from __future__ import annotations

from functools import cache
from typing import Any

import jinja2


def template_loader(package: str) -> jinja2.BaseLoader:
    """``package``'s ``templates`` directory, then ``ops_deploy.helpers``' (the shared ``_edge.j2``).

    Every environment that renders a Traefik route uses this loader, so a route
    template can ``{% import "_edge.j2" as edge %}`` whichever package it lives in.
    A package's own template of the same name wins; none shadows a helper template.
    """

    return jinja2.ChoiceLoader([jinja2.PackageLoader(p, "templates") for p in (package, "ops_deploy.helpers")])


@cache
def _environment(package: str) -> jinja2.Environment:
    # Jinja's default autoescape=False: these are config files, not HTML.
    return jinja2.Environment(
        loader=template_loader(package), undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )


def render(package: str, template: str, **context: Any) -> str:
    """Render ``templates/<template>`` from ``package``; undefined names raise."""

    return _environment(package).get_template(template).render(**context)
