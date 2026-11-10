"""Periodic timers must keep a next elapse after a reboot or a late timer restart.

With only OnBootSec=/OnUnitActiveSec= a timer started after OnBootSec has
passed, whose service last ran in an earlier boot, shows NEXT n/a and never
fires again. OnActiveSec= and an OnCalendar= backstop prevent that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ops_deploy.services.dns.config import DnsConfig
from ops_deploy.services.fractal_monitoring.config import ReplicationLagConfig
from ops_deploy.services.rustfs.config import RustfsReplicationMonitor

SERVICES = Path(__file__).parents[1] / "src/ops_deploy/services"
TIMERS = [
    "dns/templates/ddns-update.timer.j2",
    "fractal_monitoring/templates/minio-replication-lag-check.timer.j2",
    "rustfs/templates/rustfs-replication-monitor.timer.j2",
    "torrent_vpn_metrics_endpoint/templates/torrent-vpn-metrics-collector.timer.j2",
]


@pytest.mark.parametrize("template", TIMERS)
def test_monotonic_timer_has_restart_anchor_and_calendar_backstop(template: str) -> None:
    lines = (SERVICES / template).read_text().splitlines()
    for key in ("OnBootSec=", "OnActiveSec=", "OnUnitActiveSec=", "OnCalendar="):
        assert any(line.startswith(key) for line in lines), (template, key)
    assert "Persistent=true" in lines


def test_calendar_backstop_defaults() -> None:
    assert DnsConfig.model_fields["ddns_on_calendar"].default == "*:0/5"
    assert ReplicationLagConfig.model_fields["timer_on_calendar"].default == "*:0/5"
    assert RustfsReplicationMonitor.model_fields["timer_on_calendar"].default == "*:0/5"
