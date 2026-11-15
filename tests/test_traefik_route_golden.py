"""``render_route`` output stays byte for byte what the hosts' route files hold.

Every service's file below ``/etc/traefik/dynamic`` comes from
``render_route``; the renders are recorded under ``tests/golden/traefik_route``
(see ``tests/goldens.py``). Traefik watches that directory, so a changed byte
is a rewrite and a reload on every host at the next deploy.
"""

from pathlib import Path

import pytest
from pydantic import SecretStr

from ops_deploy.helpers.traefik import BasicAuth, HealthCheck, RedirectRegex, TraefikRoute, render_route
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "traefik_route"
HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"
AUTH = BasicAuth(user="admin", password=SecretStr("fixture-password"))
HOST = "app.example.com"


@pytest.mark.parametrize("auth", [True, False])
@pytest.mark.parametrize(("cert_resolver", "middlewares"), [("", ()), ("letsencrypt", ("ratelimit@file", "extra"))])
def test_plain_route_is_golden(auth: bool, cert_resolver: str, middlewares: tuple[str, ...]) -> None:
    route = TraefikRoute(
        name="nyxmon",
        title="Nyxmon",
        host=HOST,
        app_port=10017,
        basic_auth=AUTH if auth else None,
        cert_resolver=cert_resolver,
        middlewares=middlewares,
    )
    name = f"plain-{'auth' if auth else 'open'}-{cert_resolver or 'default'}.yml"

    assert_golden(GOLDEN / name, render_route(route, HASH if auth else None))


@pytest.mark.parametrize("auth", [True, False])
def test_route_with_redirect_and_health_check_is_golden(auth: bool) -> None:
    route = TraefikRoute(
        name="fastdeploy",
        title="FastDeploy",
        host=HOST,
        app_port=9999,
        basic_auth=AUTH if auth else None,
        frame_options="SAMEORIGIN",
        redirect=RedirectRegex(regex="^(https?://[^/]+)/$", replacement="${1}/static/index.html"),
        health_check=HealthCheck(),
    )
    name = f"redirect-health-{'auth' if auth else 'open'}.yml"

    assert_golden(GOLDEN / name, render_route(route, HASH if auth else None))


def test_rendered_route_ends_with_one_newline() -> None:
    ours = render_route(TraefikRoute(name="nyxmon", host=HOST, app_port=10017), None)

    assert ours.endswith('"\n')
    assert not ours.endswith("\n\n")
