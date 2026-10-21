"""No route ops-deploy writes opts its domain into browser HSTS preload.

ops-library ``abae172`` removed ``stsPreload: true`` from every role Traefik
template (the owner decided against preload registration on 2026-10-19). The
ports' own templates and the vendored role copies follow; the per-service
tests check each rendered route with :func:`tests.hsts.hsts_headers`.
"""

from pathlib import Path

import pytest
from pydantic import SecretStr

from ops_deploy.helpers.traefik import BasicAuth, RouteRenderer, TraefikRoute, render_route
from ops_deploy.services.native_app.render import render_route as render_native_route
from tests.hsts import hsts_headers

ROOT = Path(__file__).parents[1]
TEMPLATES = sorted((ROOT / "src" / "ops_deploy").rglob("*.j2")) + sorted((ROOT / "tests" / "parity").rglob("*.j2"))
HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_template_enables_preload(template: Path) -> None:
    # Omit the setting entirely, as the roles do (no variable-driven opt-in).
    assert "stsPreload" not in template.read_text()


def test_templates_were_found() -> None:
    assert len(TEMPLATES) > 50


AUTH = BasicAuth(user="admin", password=SecretStr("fixture-password"))


@pytest.mark.parametrize(
    ("route", "auth_hash"),
    [
        (TraefikRoute(name="app", host="app.example.com", app_port=8000), None),
        (TraefikRoute(name="app", host="app.example.com", app_port=8000, basic_auth=AUTH), HASH),
        (TraefikRoute(name="app", host="app.example.com", app_port=8000, internal_only=True), None),
    ],
    ids=["public", "basic-auth", "internal"],
)
@pytest.mark.parametrize("renderer", [render_route, render_native_route], ids=["helper", "native_app"])
def test_routes_send_hsts_without_preload(renderer: RouteRenderer, route: TraefikRoute, auth_hash: str | None) -> None:
    assert len(hsts_headers(renderer(route, auth_hash))) == 1
