"""HSTS checks shared by the route tests: no ``preload``, lifetimes unchanged.

ops-library ``abae172`` (2026-10-19) removed ``stsPreload: true`` from every
role Traefik template; the owner decided against browser preload
registration. The ports follow: no route ops-deploy renders advertises
``preload``, and the remaining HSTS settings stay as they were.
"""

from typing import Any

import yaml


def hsts_headers(route: str, seconds: int = 15552000) -> list[dict[str, Any]]:
    """The route's HSTS header middlewares; fails on ``stsPreload`` or a changed lifetime."""

    middlewares = yaml.safe_load(route)["http"]["middlewares"]
    found = [m["headers"] for m in middlewares.values() if "stsSeconds" in m.get("headers", {})]
    assert found, "the route sets no HSTS header"
    for headers in found:
        assert "stsPreload" not in headers
        assert headers["stsSeconds"] == seconds
        assert headers["stsIncludeSubdomains"] is True
    return found
