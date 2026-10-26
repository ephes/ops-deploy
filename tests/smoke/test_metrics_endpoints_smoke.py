"""Owned Linux fixture: first/repeat, normal input updates and retained Basic Auth.

METRICS_ENDPOINT_SMOKE=1 SMOKE_VM=<owned fixture> just smoke
 tests/smoke/test_metrics_endpoints_smoke.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.metrics_endpoint import MetricsEndpointConfig, deploy_metrics_endpoint
from ops_deploy.services.torrent_vpn_metrics_endpoint import (
    TorrentVpnMetricsEndpointConfig,
    deploy_torrent_vpn_metrics_endpoint,
)
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import SmokeHost

pytestmark = pytest.mark.skipif(os.environ.get("METRICS_ENDPOINT_SMOKE") != "1", reason="owned endpoint fixture opt-in")
VALUE = "fixture-endpoint-password"
VALUES = SecretValues(SecretRef("fixture/metrics.yml"), {"endpoint_password": VALUE})
HTTP = r"""
import base64,json,sys,urllib.request,urllib.error
cfg=json.load(sys.stdin)
headers={}
if cfg['password'] is not None:
    headers['Authorization']='Basic '+base64.b64encode(('monitor:'+cfg['password']).encode()).decode()
try:
    with urllib.request.urlopen(urllib.request.Request(cfg['url'],headers=headers),timeout=10) as result:
        print(json.dumps({'status':result.status,'body':json.load(result)}))
except urllib.error.HTTPError as error:
    print(json.dumps({'status':error.code}))
"""


def test_linux_first_update_repeat(smoke_host: SmokeHost) -> None:
    receipt: dict[str, Any] = {"phases": {}}

    def record() -> None:
        if name := os.environ.get("METRICS_ENDPOINT_SMOKE_RECEIPT"):
            Path(name).write_text(json.dumps(receipt, indent=2) + "\n")

    def apply(deploy: Any, cfg: Any, label: str) -> SshRun:
        run = run_deploy_ssh(deploy, cfg, VALUES, host_name=smoke_host.name, host_data=smoke_host.host_data)
        receipt["phases"][label] = {
            "succeeded": run.succeeded,
            "error": str(run.error) if run.error else None,
            "seconds": run.seconds,
            "mutating_changed_ops": run.mutating_changed_ops,
        }
        record()
        assert run.succeeded, (run.error, [op for op in run.ops if not op.succeeded])
        return run

    def request(cfg: Any, password: str | None = VALUE) -> dict[str, Any]:
        result = smoke_host.run(
            shlex.join(["python3", "-I", "-c", HTTP]),
            input=json.dumps({"url": f"http://127.0.0.1:{cfg.port}{cfg.path}", "password": password}),
        )
        return json.loads(result.stdout)  # type: ignore[no-any-return]

    mail = MetricsEndpointConfig(
        secrets=VALUES.ref,
        auth_user="monitor",
        bind="127.0.0.1",
        service_name="metrics-fixture",
        port=19100,
        htpasswd_dir="/etc/metrics-fixture",
        queue_path="/var/lib/metrics-fixture-queue",
        vmail_path="/var/lib",
        services=("ssh",),
        script_path="/usr/local/bin/metrics-fixture.sh",
        server_path="/usr/local/bin/metrics-fixture-httpd.py",
    )
    vpn = TorrentVpnMetricsEndpointConfig(
        secrets=VALUES.ref,
        auth_user="monitor",
        bind="127.0.0.1",
        service_name="vpn-metrics-fixture",
        port=19102,
        htpasswd_dir="/etc/vpn-metrics-fixture",
        site_path="/var/lib/vpn-metrics-fixture",
        collector_path="/usr/local/bin/vpn-metrics-fixture-collect",
        server_path="/usr/local/bin/vpn-metrics-fixture-httpd.py",
        timer_name="vpn-metrics-fixture-collector",
        timer_interval=3600,
    )
    smoke_host.run(
        "mkdir -p /var/lib/metrics-fixture-queue/active /var/lib/metrics-fixture-queue/deferred; "
        "chmod 0700 /var/lib/metrics-fixture-queue/active /var/lib/metrics-fixture-queue/deferred; "
        "touch /var/lib/metrics-fixture-queue/active/one /var/lib/metrics-fixture-queue/deferred/two"
    )
    try:
        first = apply(deploy_metrics_endpoint, mail, "mail-first")
        assert first.mutating_changed_ops
        assert request(mail, None)["status"] == 401
        assert request(mail, "wrong")["status"] == 401
        for suffix in ("\n", "\r\n", "\0tail"):
            assert request(mail, VALUE + suffix)["status"] == 401
        assert request(mail)["body"]["mail"]["queue_total"] == 2
        auth_hash = smoke_host.out("sha256sum /etc/metrics-fixture/htpasswd")
        pid = smoke_host.out("systemctl show -p MainPID --value metrics-fixture")
        assert apply(deploy_metrics_endpoint, mail, "mail-repeat").mutating_changed_ops == []
        assert smoke_host.out("systemctl show -p MainPID --value metrics-fixture") == pid
        changed = mail.model_copy(update={"services": ("ssh", "cron")})
        updated = apply(deploy_metrics_endpoint, changed, "mail-update")
        assert any("Restart metrics-fixture.service" in op for op in updated.mutating_changed_ops)
        assert "cron" in request(changed)["body"]["services"]
        assert smoke_host.out("sha256sum /etc/metrics-fixture/htpasswd") == auth_hash
        assert apply(deploy_metrics_endpoint, changed, "mail-update-repeat").mutating_changed_ops == []
        first = apply(deploy_torrent_vpn_metrics_endpoint, vpn, "vpn-first")
        assert first.mutating_changed_ops
        body = request(vpn)["body"]
        assert body["error"] is True  # no VPN/Docker stack in this isolated fixture
        assert 0 <= body["meta"]["age_seconds"] < 120
        assert request(vpn, None)["status"] == 401
        vpn_pid = smoke_host.out("systemctl show -p MainPID --value vpn-metrics-fixture")
        assert apply(deploy_torrent_vpn_metrics_endpoint, vpn, "vpn-repeat").mutating_changed_ops == []
        changed_vpn = vpn.model_copy(update={"script_timeout": 11})
        updated = apply(deploy_torrent_vpn_metrics_endpoint, changed_vpn, "vpn-update")
        assert any("Initialize torrent VPN metrics" in op for op in updated.mutating_changed_ops)
        assert smoke_host.out("systemctl show -p MainPID --value vpn-metrics-fixture") == vpn_pid
        assert apply(deploy_torrent_vpn_metrics_endpoint, changed_vpn, "vpn-update-repeat").mutating_changed_ops == []
        source = smoke_host.out("sha256sum /usr/local/bin/metrics-fixture-httpd.py").split()[0]
        from ops_deploy.services.metrics_endpoint.deploy import render_role

        assert source == hashlib.sha256(render_role("metrics_httpd.py.j2", changed, "127.0.0.1").encode()).hexdigest()
        receipt["functional"] = {
            "mail_queue_total": 2,
            "auth_missing": 401,
            "auth_wrong": 401,
            "auth_success": 200,
            "vpn_fixture_error": True,
            "vpn_payload_fresh": True,
            "wrapper_sha256": source,
        }
        record()
    finally:
        smoke_host.run(
            "systemctl disable --now metrics-fixture vpn-metrics-fixture "
            "vpn-metrics-fixture-collector.timer 2>/dev/null || true",
            check=False,
        )
