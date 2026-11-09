"""Default HSTS has no preload; two typed mail UI opt-ins preserve host intent."""

from pathlib import Path

import pytest
from pydantic import SecretStr

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import BasicAuth, RouteRenderer, TraefikRoute, render_route
from ops_deploy.services._mail_web.render import render as render_mail_web
from ops_deploy.services.native_app.render import render_route as render_native_route
from ops_deploy.services.postfixadmin import PostfixAdminConfig
from ops_deploy.services.snappymail import SnappyMailConfig
from tests.hsts import hsts_headers

ROOT = Path(__file__).parents[1]
TEMPLATES = sorted((ROOT / "src" / "ops_deploy").rglob("*.j2")) + sorted((ROOT / "tests" / "parity").rglob("*.j2"))
HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_template_enables_preload(template: Path) -> None:
    mail_routes: dict[str, PostfixAdminConfig | SnappyMailConfig] = {
        "src/ops_deploy/services/postfixadmin/templates/traefik-postfixadmin.yml.j2": PostfixAdminConfig(
            traefik_host="admin.example.test", admin_email="admin@example.test"
        ),
        "src/ops_deploy/services/snappymail/templates/traefik-snappymail.yml.j2": SnappyMailConfig(
            traefik_host="mail.example.test", imap_host="imap.example.test", smtp_host="smtp.example.test"
        ),
    }
    cfg = mail_routes.get(str(template.relative_to(ROOT)))
    if cfg is None:
        assert "stsPreload" not in template.read_text()
        return
    values = SecretValues(
        SecretRef("fixture.yml"),
        {"db_password": "fixture-only", "setup_password": "fixture-only", "admin_password": "fixture-only"},
    )
    assert cfg.traefik_sts_preload is False
    assert "stsPreload" not in render_mail_web(cfg, values)["route"]
    assert (
        render_mail_web(cfg.model_copy(update={"traefik_sts_preload": True}), values)["route"].count("stsPreload: true")
        == 1
    )


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
