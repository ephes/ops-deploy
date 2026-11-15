"""os_apt_maintenance's units and programs stay byte for byte what hosts have.

``tests/golden/os_apt_maintenance/<case>/`` holds the renders (first recorded
from the role's own output; see ``tests/goldens.py``). A changed byte rewrites
the file and restarts the endpoint or reschedules the timers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.os_apt_maintenance import OsAptMaintenanceConfig
from ops_deploy.services.os_apt_maintenance.deploy import render_role
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "os_apt_maintenance"
TEMPLATES = sorted(
    path.name
    for path in (Path(__file__).parents[1] / "src/ops_deploy/services/os_apt_maintenance/templates").glob("*.j2")
)
CASES: dict[str, dict[str, Any]] = {
    "weekly": {"host_id": "fixture-host", "auth_user": "nyxmon"},
    "custom": {
        "host_id": "fixture-two",
        "auth_user": "monitor",
        "user": "fixturemetrics",
        "group": "fixturemetrics",
        "state_dir": "/srv/apt-state",
        "state_file": "/srv/apt-state/custom.json",
        "lock_file": "/run/fixture-apt.lock",
        "script_path": "/usr/local/sbin/fixture-apt",
        "server_path": "/usr/local/bin/fixture-http.py",
        "htpasswd_dir": "/etc/fixture-apt",
        "port": 19106,
        "path": "/fixture/state",
        "timer_on_calendar": "Mon *-*-* 03:15:00",
        "timer_randomized_delay_sec": "15m",
        "timer_accuracy_sec": "5m",
        "timer_persistent": False,
        "refresh_timer_on_calendar": "*-*-* 09:15:00",
        "refresh_timer_randomized_delay_sec": "20m",
        "refresh_timer_accuracy_sec": "2m",
        "refresh_timer_persistent": False,
        "update_cache": False,
        "autoremove": False,
        "autoclean": False,
        "ip_allow": ["100.64.0.0/10", "192.0.2.0/24"],
    },
}


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("template", TEMPLATES)
def test_rendered_files_are_golden(case: str, template: str) -> None:
    config = OsAptMaintenanceConfig.model_validate({"secrets": "secrets/fixture.yml", **CASES[case]})
    assert_golden(GOLDEN / case / template.removesuffix(".j2"), render_role(template, config, "100.64.0.7"))
