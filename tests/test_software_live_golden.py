"""The software_live units and timers are the bytes hosts have (recorded from the role's renders)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.software_live.common import render
from tests.goldens import assert_golden
from tests.test_software_live import config

GOLDEN = Path(__file__).parent / "golden" / "software_live"
POLICY = {
    "host": "fixture",
    "os": {"expected_id": "ubuntu", "product": "ubuntu"},
    "postgresql": {"expected": False},
    "traefik": {"expected": False, "unit": "traefik.service", "desired_version": None},
    "apt_max_age_seconds": 172800,
}
CASES: dict[str, dict[str, Any]] = {
    "defaults": {"policy": POLICY, "auth_user": "nyxmon", "rust_version": "0.1.1"},
    "custom-shadow": {
        "policy": POLICY,
        "auth_user": "nyxmon",
        "rust_version": "0.1.2",
        "user": "observer",
        "group": "observer",
        "config_dir": "/etc/fixture-software-live",
        "data_dir": "/var/lib/fixture-software-live",
        "install_dir": "/usr/local/lib/fixture-software-live",
        "port": 19110,
        "on_calendar": "*:2/20",
        "shadow_port": 19119,
        "shadow_on_calendar": "*:4/20",
        "impl": "rust",
        "rust_shadow": True,
    },
}
TEMPLATES = [
    "collector.service.j2",
    "collector.timer.j2",
    "endpoint.service.j2",
    "shadow-collector.service.j2",
    "shadow-collector.timer.j2",
    "shadow-endpoint.service.j2",
]


@pytest.mark.parametrize("case", sorted(CASES))
@pytest.mark.parametrize("template", TEMPLATES)
def test_render_matches_golden(case: str, template: str) -> None:
    assert_golden(GOLDEN / case / template.removesuffix(".j2"), render(template, config(**CASES[case])))
