"""Every Traefik route deletes the request headers a client must not choose.

Traefik passes any request header a client sends to the backend. Backends that
trust a proxy-set user (``Remote-User`` and friends), an alternative client
address (``True-Client-IP``, ``Forwarded``) or a path prefix (``SCRIPT_NAME``,
``X-Forwarded-Prefix``) see Traefik as their loopback peer, so a client could
pick its identity, its address for rate limits or the path the application
resolves. ``helpers/templates/_edge.j2`` lists those headers once; every route
template imports it and emits the list with empty values (Traefik's headers
middleware deletes a header whose configured value is empty).

This drift test keeps every route template on the macro:

- each route template under ``src/ops_deploy`` has a rendered sample here
  (a golden file or a render from the service's test fixtures);
- every router that reaches a backend over HTTPS runs a headers middleware that
  deletes the full list, before any middleware that rewrites the path;
- no middleware sets one of the listed headers to a value;
- a template that can be rendered several times on one host (one file per
  route) gives the deleting middleware a per-route name: Traefik's file
  provider drops a middleware that two files define differently, which would
  break every router using it while a host has old and new files.

Routers on the plain ``web`` entry point only are skipped: every static config
redirects ``web`` to ``web-secure`` before routing. Routers whose service is
Traefik's own (``noop@internal``) reach no backend.

``X-Forwarded-For``, ``X-Real-Ip`` and ``X-Forwarded-Host/-Port/-Proto/-Server``
are not in the list: no entry point trusts a forwarded header, so Traefik
replaces what the client sent with its own values, and deleting them would
remove those.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.core.templates import template_loader
from ops_deploy.helpers.traefik import BasicAuth, TraefikRoute, render_route
from ops_deploy.services._mail_web.render import render as render_mail_web
from ops_deploy.services.daybook_operations_api.render import render_route as render_operations_route
from ops_deploy.services.django_site import Route
from ops_deploy.services.django_site.render import render as render_django
from ops_deploy.services.mailgun_relay.deploy import render_role as render_mailgun
from ops_deploy.services.native_app.render import render_route as render_native_route
from ops_deploy.services.openclaw import layout as openclaw_layout
from ops_deploy.services.postfixadmin import PostfixAdminConfig
from ops_deploy.services.rustfs import RustfsConfig
from ops_deploy.services.rustfs.deploy import render as render_rustfs
from ops_deploy.services.snappymail import SnappyMailConfig
from ops_deploy.services.static_site import StaticSiteConfig
from ops_deploy.services.static_site.deploy import render_route as render_static_route
from tests.django_site_split_fixtures import make_source as make_split_source
from tests.django_site_split_fixtures import split_config
from tests.static_site_fixtures import make_source as make_static_source
from tests.test_daybook_operations_api import config as operations_config
from tests.test_django_site_postgres import config as django_config
from tests.test_mailgun_relay import config as mailgun_config
from tests.test_openclaw_golden import role_variables as openclaw_variables

ROOT = Path(__file__).parents[1]
PACKAGE = ROOT / "src" / "ops_deploy"
GOLDEN = Path(__file__).parent / "golden"

# The design's list (auth-rate-limiting design 2026-11-17, section 3.3), in the macro's order.
EDGE_DELETED_HEADERS = (
    # Identity: a backend configured for proxy authentication would take the user from these.
    "Remote-User",
    "Remote-Email",
    "Remote-Name",
    "Remote-Groups",
    "X-Remote-User",
    "X-Forwarded-User",
    "X-Forwarded-Email",
    "X-Forwarded-Groups",
    "X-Forwarded-Preferred-Username",
    "X-Auth-Request-User",
    "X-Auth-Request-Email",
    "X-WEBAUTH-USER",
    # Client address: alternatives to X-Forwarded-For that a library may prefer.
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Client-IP",
    "X-Cluster-Client-IP",
    "Fastly-Client-IP",
    "X-Original-Forwarded-For",
    "Forwarded",
    # Forwarded headers Traefik does not own (scheme and path prefix).
    "X-Forwarded-Prefix",
    "X-Forwarded-Uri",
    "X-Forwarded-Method",
    "X-Forwarded-Ssl",
    "X-Forwarded-Protocol",
    "X-Forwarded-Scheme",
    "X-Url-Scheme",
    "X-Script-Name",
    # WSGI environ: gunicorn takes these two from its loopback peer, which is Traefik.
    "SCRIPT_NAME",
    "PATH_INFO",
)
TRAEFIK_OWNED = ("X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto")
# Middleware types that change the path the backend sees; they set X-Forwarded-Prefix themselves.
PATH_REWRITES = {"stripPrefix", "stripPrefixRegex", "replacePath", "replacePathRegex", "addPrefix"}
# Templates whose routers all answer with Traefik's own service.
REDIRECT_ONLY = {"services/zellij_ingress/templates/zellij-traefik.yml.j2"}

HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"
AUTH = BasicAuth(user="admin", password=SecretStr("fixture-password"))
MAIL_SECRETS = SecretValues(
    SecretRef("fixture.yml"),
    {"db_password": "fixture-only", "setup_password": "fixture-only", "admin_password": "fixture-only"},
)

Sample = Callable[[Path], list[str]]


def route_templates() -> list[str]:
    return sorted(str(path.relative_to(PACKAGE)) for path in PACKAGE.rglob("*.j2") if "routers:" in path.read_text())


def goldens(*pattern: str) -> Sample:
    def sample(_tmp: Path) -> list[str]:
        paths = sorted(path for glob in pattern for path in GOLDEN.glob(glob))
        assert paths, f"no golden file matches {pattern}"
        return [path.read_text() for path in paths]

    return sample


def helper_routes(name: str = "app") -> list[str]:
    host = f"{name}.example.com"
    return [
        render_route(TraefikRoute(name=name, host=host, app_port=8000), None),
        render_route(TraefikRoute(name=name, host=host, app_port=8000, basic_auth=AUTH), HASH),
        render_route(TraefikRoute(name=name, host=host, app_port=8000, internal_only=True), None),
    ]


def native_routes(name: str = "app") -> list[str]:
    host = f"{name}.example.com"
    return [
        render_native_route(TraefikRoute(name=name, host=host, app_port=8000), None),
        render_native_route(TraefikRoute(name=name, host=host, app_port=8000, basic_auth=AUTH), HASH),
        render_native_route(TraefikRoute(name=name, host=host, app_port=8000, internal_only=True), None),
    ]


def django_routes(tmp: Path, fqdn: str = "school.example.com", *, wagtail: bool, service: str = "marina") -> list[str]:
    tmp.mkdir(parents=True, exist_ok=True)
    route = Route(
        fqdn=fqdn,
        host_rule=f"Host(`{fqdn}`)",
        wagtail=wagtail,
        public_reason="Public school website",
    )
    return [render_django("route.traefik.yml.j2", django_config(tmp, route=route, service_name=service))]


def django_frontend_route(tmp: Path) -> list[str]:
    return [render_django("route.traefik.yml.j2", split_config(make_split_source(tmp)))]


def static_routes(tmp: Path, name: str = "static-site") -> list[str]:
    tmp.mkdir(parents=True, exist_ok=True)
    base = StaticSiteConfig(source_path=make_static_source(tmp), traefik_host=f"{name}.test.example")
    return [
        render_static_route(base.model_copy(update={"service_name": name})),
        render_static_route(
            base.model_copy(update={"service_name": name, "traefik_allowed_networks": ("100.64.0.0/10",)})
        ),
    ]


SAMPLES: dict[str, Sample] = {
    "helpers/templates/traefik_route.yml.j2": lambda _tmp: [*helper_routes(), *goldens("traefik_route/*.yml")(_tmp)],
    "services/archive/templates/archive.traefik.yml.j2": goldens("archive/*/archive.traefik.yml"),
    "services/chesslab/templates/chesslab.traefik.yml.j2": goldens("chesslab/*/chesslab.traefik.yml"),
    "services/daybook_operations_api/templates/traefik.yml.j2": lambda _tmp: [
        render_operations_route(operations_config(domain="operations.example.test"))
    ],
    "services/delve/templates/delve-traefik.yml.j2": goldens("delve/*/delve-traefik.yml"),
    "services/django_site/templates/route.traefik.yml.j2": lambda tmp: [
        *django_routes(tmp, wagtail=False),
        *django_frontend_route(tmp / "split"),
    ],
    "services/django_site/templates/wagtail-route.traefik.yml.j2": lambda tmp: django_routes(tmp, wagtail=True),
    "services/echoport/templates/traefik-echoport.yml.j2": goldens("echoport/*/traefik-echoport.yml"),
    "services/gotosocial/templates/traefik.yml.j2": goldens("gotosocial/*/traefik.yml"),
    "services/graphyard/templates/traefik-graphyard.yml.j2": goldens("graphyard/ingress/*/traefik-graphyard.yml"),
    "services/homeassistant/templates/homeassistant.traefik.yml.j2": goldens(
        "homeassistant/*/homeassistant.traefik.yml"
    ),
    "services/homelab/templates/traefik.yml.j2": goldens("homelab/*/homelab.yml"),
    "services/jellyfin/templates/jellyfin-traefik.yml.j2": goldens("jellyfin/*/jellyfin.yml"),
    "services/livekit/templates/livekit-traefik.yml.j2": goldens("livekit/livekit.yml"),
    "services/logyard/templates/traefik-logyard.yml.j2": goldens("logyard/ingress/*/traefik-logyard.yml"),
    "services/mailgun_relay/templates/traefik-mailgun-relay.yml.j2": lambda _tmp: [
        render_mailgun("traefik-mailgun-relay.yml.j2", mailgun_config(ingress_enabled=True))
    ],
    "services/mastodon/templates/traefik.yml.j2": goldens("mastodon/traefik.yml"),
    "services/metube/templates/metube-traefik.yml.j2": goldens("metube/*/metube-traefik.yml"),
    "services/native_app/templates/route.yml.j2": lambda _tmp: native_routes(),
    "services/opaq_app/templates/opaq-app.traefik.yml.j2": goldens("opaq_app/*/traefik.yml"),
    "services/openclaw/templates/openclaw-traefik.yml.j2": lambda _tmp: [
        openclaw_layout.route_file(openclaw_variables(case)).content.decode()
        for case in ("production", "audio-disabled")
    ],
    "services/opsgate/templates/opsgate-traefik.yml.j2": goldens("mac_ingress/opsgate-*.yml"),
    "services/paperless/templates/paperless.traefik.yml.j2": goldens("paperless/*/paperless.traefik.yml"),
    "services/postfixadmin/templates/traefik-postfixadmin.yml.j2": lambda _tmp: [
        render_mail_web(
            PostfixAdminConfig(traefik_host="admin.example.test", admin_email="admin@example.test"), MAIL_SECRETS
        )["route"]
    ],
    "services/recorder/templates/recorder-traefik.yml.j2": goldens("recorder/recorder-traefik.yml"),
    "services/rustfs/templates/traefik-rustfs.yml.j2": lambda _tmp: [
        render_rustfs(
            "traefik-rustfs.yml.j2", RustfsConfig(expose_via_traefik=True, traefik_api_host="objects.example.test")
        )
    ],
    "services/snappymail/templates/traefik-snappymail.yml.j2": lambda _tmp: [
        render_mail_web(
            SnappyMailConfig(
                traefik_host="mail.example.test", imap_host="imap.example.test", smtp_host="smtp.example.test"
            ),
            MAIL_SECRETS,
        )["route"]
    ],
    "services/static_site/templates/static-site.traefik.yml.j2": lambda tmp: [
        *static_routes(tmp),
        *goldens("static_site/*/static-site.traefik.yml")(tmp),
    ],
    "services/unifi/templates/unifi.traefik.yml.j2": goldens("unifi/unifi.traefik.yml"),
    "services/vaultwarden/templates/traefik-vaultwarden.yml.j2": goldens("vaultwarden/*/traefik-vaultwarden.yml"),
    "services/voxhelm/templates/voxhelm-traefik.yml.j2": goldens("mac_ingress/voxhelm-*.yml"),
    "services/weeknotes_home/templates/weeknotes-home.traefik.yml.j2": goldens(
        "weeknotes_home/*/weeknotes-home.traefik.yml"
    ),
    "services/work_app/templates/work-app.traefik.yml.j2": goldens("work_app/*/traefik.yml"),
    "services/zellij_ingress/templates/zellij-traefik.yml.j2": goldens("zellij_ingress/*.yml"),
}


def request_headers(middleware: Any) -> dict[str, Any]:
    if not isinstance(middleware, dict):
        return {}
    return (middleware.get("headers") or {}).get("customRequestHeaders") or {}


def deletes_all(middleware: Any) -> bool:
    headers = request_headers(middleware)
    return all(name in headers and headers[name] == "" for name in EDGE_DELETED_HEADERS)


def hygiene_middlewares(text: str) -> set[str]:
    middlewares = yaml.safe_load(text)["http"].get("middlewares") or {}
    return {name for name, middleware in middlewares.items() if deletes_all(middleware)}


def violations(text: str) -> list[str]:
    http = yaml.safe_load(text)["http"]
    middlewares = http.get("middlewares") or {}
    hygiene = hygiene_middlewares(text)
    listed = {name.lower() for name in EDGE_DELETED_HEADERS}
    found: list[str] = []
    for name, middleware in middlewares.items():
        for header, value in request_headers(middleware).items():
            if header.lower() in listed and value != "":
                found.append(f"middleware {name} sets {header}")
    for name, router in http["routers"].items():
        if str(router["service"]).endswith("@internal"):
            continue
        entrypoints = router.get("entryPoints")
        if entrypoints and set(entrypoints) <= {"web"}:
            continue
        chain = list(router.get("middlewares") or [])
        # A plain-HTTP router that redirects first answers before the backend.
        if "tls" not in router and chain and "redirectScheme" in (middlewares.get(chain[0]) or {}):
            continue
        positions = [index for index, item in enumerate(chain) if item in hygiene]
        if not positions:
            found.append(f"router {name} reaches {router['service']} without the edge header deletion")
            continue
        for index, item in enumerate(chain):
            kinds = set(middlewares.get(item) or {})
            if kinds & PATH_REWRITES and index < positions[0]:
                found.append(f"router {name}: {item} rewrites the path before the edge header deletion")
    return found


def test_every_route_template_has_a_sample() -> None:
    assert route_templates() == sorted(SAMPLES)
    assert len(SAMPLES) >= 34


@pytest.mark.parametrize("template", sorted(SAMPLES))
def test_every_router_deletes_the_edge_headers(template: str, tmp_path: Path) -> None:
    renders = SAMPLES[template](tmp_path)
    assert renders
    for text in renders:
        assert violations(text) == []
        if template not in REDIRECT_ONLY:
            assert hygiene_middlewares(text)


@pytest.mark.parametrize("template", sorted(set(SAMPLES) - REDIRECT_ONLY))
def test_route_templates_use_the_shared_macro(template: str) -> None:
    source = (PACKAGE / template).read_text()

    assert '{% import "_edge.j2" as edge' in source or '{%- import "_edge.j2" as edge' in source
    assert "edge.request_headers(" in source
    # The list lives in the macro only.
    assert "SCRIPT_NAME" not in source


def test_the_macro_emits_the_list_with_empty_values() -> None:
    env = jinja2.Environment(loader=template_loader("ops_deploy.helpers"), undefined=jinja2.StrictUndefined)
    module: Any = env.get_template("_edge.j2").module
    text = "customRequestHeaders:" + str(module.request_headers(2))
    headers = yaml.safe_load(text)["customRequestHeaders"]

    assert list(headers) == list(EDGE_DELETED_HEADERS)
    assert set(headers.values()) == {""}
    assert not set(TRAEFIK_OWNED) & set(headers)


def test_every_template_package_can_import_the_macro() -> None:
    for template in SAMPLES:
        package = "ops_deploy." + ".".join(Path(template).parts[:-2])
        env = jinja2.Environment(loader=template_loader(package))
        assert env.get_template("_edge.j2").module


@pytest.mark.parametrize(
    "pair",
    [
        lambda _tmp: (helper_routes("one"), helper_routes("two")),
        lambda _tmp: (native_routes("one"), native_routes("two")),
        lambda tmp: (
            django_routes(tmp / "a", "one.example.com", wagtail=False, service="one"),
            django_routes(tmp / "b", "two.example.com", wagtail=False, service="two"),
        ),
        lambda tmp: (
            django_routes(tmp / "a", "one.example.com", wagtail=True, service="one"),
            django_routes(tmp / "b", "two.example.com", wagtail=True, service="two"),
        ),
        lambda tmp: (static_routes(tmp / "a", "one"), static_routes(tmp / "b", "two")),
    ],
    ids=["helper", "native_app", "django_site", "django_site-wagtail", "static_site"],
)
def test_routes_of_one_host_never_share_the_deleting_middleware(
    pair: Callable[[Path], tuple[list[str], list[str]]], tmp_path: Path
) -> None:
    first, second = pair(tmp_path)
    names_first = set().union(*(hygiene_middlewares(text) for text in first))
    names_second = set().union(*(hygiene_middlewares(text) for text in second))

    assert names_first
    assert names_second
    assert not names_first & names_second
