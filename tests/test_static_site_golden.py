"""static_site's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/static_site`` were recorded when these
renders still equalled the retired static_site_deploy role's output;
identical bytes mean the next deploy rewrites nothing and restarts nothing
(see tests/goldens.py).
"""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.static_site import StaticSiteConfig
from ops_deploy.services.static_site.deploy import render_route, render_server, render_unit
from tests.goldens import assert_golden
from tests.static_site_fixtures import make_source

GOLDEN = Path(__file__).parent / "golden" / "static_site"


VARIANTS: dict[str, dict[str, Any]] = {
    "defaults": {},
    "benchmarks": {
        "service_name": "benchmarks-static",
        "port": 10061,
        "traefik_cert_resolver": "letsencrypt",
        "restrict_to_required_files": True,
    },
    "allowlist": {"traefik_allowed_networks": ("10.0.0.0/8", "fd7a:115c:a1e0::/48"), "private": True},
}


def make(tmp_path: Path, **overrides: Any) -> StaticSiteConfig:
    return StaticSiteConfig(source_path=make_source(tmp_path), traefik_host="static.test.example", **overrides)


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_host_files_are_golden(tmp_path: Path, name: str) -> None:
    cfg = make(tmp_path, **VARIANTS[name])

    assert_golden(GOLDEN / name / "static-site.service", render_unit(cfg))
    assert_golden(GOLDEN / name / "static-site-httpd.py", render_server(cfg))
    assert_golden(GOLDEN / name / "static-site.traefik.yml", render_route(cfg))
