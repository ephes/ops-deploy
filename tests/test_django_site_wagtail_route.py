"""A Wagtail site's route sends HSTS without preload."""

from pathlib import Path

from ops_deploy.services.django_site import Route
from ops_deploy.services.django_site.render import render
from tests.hsts import hsts_headers
from tests.test_django_site_postgres import config


def test_wagtail_route_sends_hsts_without_preload(tmp_path: Path) -> None:
    route = Route(
        fqdn="school.example.com",
        host_rule="Host(`school.example.com`)",
        wagtail=True,
        public_reason="Public school website",
    )

    assert len(hsts_headers(render("route.traefik.yml.j2", config(tmp_path, route=route)))) == 1
