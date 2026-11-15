"""gotosocial's host files stay byte for byte what hosts have today.

``tests/fixtures/gotosocial/<case>.json`` holds the inputs (named like the
retired gotosocial_deploy role's variables) and ``tests/golden/gotosocial/
<case>/`` the four files that role rendered from them, which the port still
renders byte for byte. Identical bytes mean the next deploy rewrites neither
``config.yaml``, the unit, the admin wrapper nor the route, and so does not
restart GoToSocial (see tests/goldens.py).
"""

import json
from pathlib import Path

import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.services.gotosocial import (
    GotosocialConfig,
    render_admin_wrapper,
    render_config,
    render_route,
    render_unit,
)
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "gotosocial"
INPUTS = Path(__file__).parent / "fixtures" / "gotosocial"
CASE_NAMES = ["defaults", "full", "ipv6"]


def case(name: str) -> tuple[GotosocialConfig, SecretStr | None]:
    """The case's role variables as a config (and the SMTP password, a deploy argument)."""

    variables = json.loads((INPUTS / f"{name}.json").read_text())
    fields = {key.removeprefix("gotosocial_"): value for key, value in variables.items()}
    password = fields.pop("smtp_password", None)
    return GotosocialConfig(**fields), SecretStr(password) if password is not None else None


@pytest.mark.parametrize("name", CASE_NAMES)
def test_host_files_are_golden(name: str) -> None:
    cfg, password = case(name)

    assert_golden(GOLDEN / name / "config.yaml", render_config(cfg, password).reveal().decode())
    assert_golden(GOLDEN / name / "gotosocial.service", render_unit(cfg))
    assert_golden(GOLDEN / name / "gotosocial-admin.sh", render_admin_wrapper(cfg))
    assert_golden(GOLDEN / name / "traefik.yml", render_route(cfg))


def test_full_case_merges_extra_config_recursively() -> None:
    cfg, _ = case("full")
    rendered = yaml.safe_load(render_config(cfg, None).reveal())

    assert rendered["cache"] == {"memory-target": "100MiB", "visibility-mem-ratio": 2}
    assert rendered["http-client"] == {"timeout": "30s", "allow-ips": ["10.0.0.0/8"]}


def test_the_ipv6_case_derives_paths_from_the_roots() -> None:
    cfg, _ = case("ipv6")
    config = yaml.safe_load(render_config(cfg, None).reveal())

    assert config["db-address"] == "/srv/gts-data/sqlite.db"
    assert config["web-asset-base-dir"] == "/srv/gts/current/web/assets/"
    assert cfg.release_dir == "/srv/gts/releases/0.22.3"
    assert cfg.layout_marker_path == "/srv/gts-data/.ops-domain-layout"
