"""Selected policy/admission, original resources and dedicated SQL continuity."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.infra.tailscale import TailscaleConfig, TailscaleMetricsConfig
from ops_deploy.infra.tailscale.metrics import schema
from ops_deploy.infra.tailscale.nyxmon import TailscaleNyxmonTarget, check_row
from ops_deploy.infra.tailscale.render import render

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    "values",
    [
        dict(package_version="latest; true"),
        dict(repo_base="https://user:password@example.test"),
        dict(args_extra=("--auth-key=must-use-stdin",)),
        dict(args_extra=("--authkey=must-use-stdin",)),
        dict(args_extra=("-authkey", "must-use-stdin")),
        dict(binary="/usr/bin/../private/tailscale"),
    ],
)
def test_core_rejects_unsafe_native_or_credential_paths(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TailscaleConfig(hostname="owned-node", **values)


def test_latest_retains_present_policy_and_original_false_preferences() -> None:
    cfg = TailscaleConfig(hostname="owned-node")
    assert cfg.package_version == "latest"
    assert not cfg.accept_dns
    assert not cfg.accept_routes
    assert not cfg.manual_up
    assert cfg.repo_base == "https://pkgs.tailscale.com"


@pytest.mark.parametrize(
    "values",
    [
        dict(ip_address_allow=("0.0.0.0/0",)),
        dict(ip_address_allow=("::/0",)),
        dict(require_default_ipv4_route=True),
        dict(warning_days=1, critical_days=3),
        dict(timer_on_calendar=""),
    ],
)
def test_endpoint_retains_original_filter_route_timer_threshold_admission(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TailscaleMetricsConfig(**values)


def test_original_exporter_and_timer_policy_are_rendered_without_source_edits() -> None:
    cfg = TailscaleMetricsConfig(require_effective_ip_filter=True)
    script = render(cfg, "tailscale_metrics_exporter.py")
    compile(script, "owned-exporter", "exec")
    assert "WARNING_DAYS = 3" in script
    assert "CRITICAL_DAYS = 1" in script
    timer = render(cfg, "tailscale-metrics-collector.timer")
    assert "OnActiveSec=300\n" in timer
    assert "OnCalendar=*:0/5\n" in timer
    unit = render(cfg, "tailscale-metrics-endpoint.service")
    assert "cgroup_inet_ingress" in unit
    assert "cgroup_inet_egress" in unit
    assert "IPAddressDeny=any\n" in unit
    assert all(not rule.equals_true for rule in schema())  # Fresh error telemetry remains valid; no forced refresh.


def test_tailscale_nyxmon_rule_order_and_optional_policy_are_exact() -> None:
    target = TailscaleNyxmonTarget(
        hostname="owned",
        url="http://192.0.2.20:9107/.well-known/tailscale",
        require_self_online=True,
        require_default_ipv4_route=True,
        require_mdraid_healthy=True,
        notify_consecutive_failures=4,
        max_age_seconds=600,
        check_interval=300,
    )
    row = check_row(target, SecretStr("synthetic-only"))
    data = row["data"]
    assert isinstance(data, dict)
    assert [check["path"] for check in data["checks"]] == [
        "$.summary.backend_running",
        "$.summary.self_online",
        "$.summary.default_ipv4_route_present",
        "$.summary.mdraid_healthy",
        "$.summary.key_expiry_critical_ok",
        "$.summary.key_expiry_warning_ok",
        "$.meta.age_seconds",
    ]
    assert data["notification_policy"] == {"consecutive_failures": 4}
    assert data["checks"][-1] == dict(path="$.meta.age_seconds", op="<", value=600, severity="critical")


def sql_fixture(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.executescript(
            "CREATE TABLE service (id INTEGER PRIMARY KEY, name TEXT); "
            "CREATE TABLE health_check (id INTEGER PRIMARY KEY,name TEXT,service_id INTEGER,check_type TEXT,"
            "url TEXT,check_interval INTEGER,status TEXT,next_check_time INTEGER,processing_started_at INTEGER,"
            "disabled INTEGER,data TEXT); INSERT INTO service VALUES (1,'Tailscale'); "
            "INSERT INTO health_check VALUES (1,'Tailscale key expiry (owned)',1,'old','http://old',"
            "5,'critical',1234,5678,1,'{}'); "
            "INSERT INTO health_check VALUES (2,'unrelated',1,'sentinel','http://unrelated',10,'warning',999,888,1,'{}');"
        )


def sql_run(path: Path, action: str) -> subprocess.CompletedProcess[str]:
    cfg = dict(
        db_path=str(path),
        user=pwd.getpwuid(os.geteuid()).pw_name,
        service_name="Tailscale",
        checks=[
            check_row(
                TailscaleNyxmonTarget(hostname="owned", url="http://192.0.2.20:9107/.well-known/tailscale"),
                SecretStr("synthetic-only"),
            )
        ],
    )
    return subprocess.run(
        [sys.executable, "-I", "-B", str(ROOT / "src/ops_deploy/infra/files/tailscale_nyxmon.py"), action],
        input=json.dumps(cfg),
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_dedicated_sql_changes_only_original_configuration_columns(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"
    sql_fixture(path)
    before = path.read_bytes()
    assert sql_run(path, "check").stdout.strip() == "pending"
    assert path.read_bytes() == before
    result = sql_run(path, "apply")
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT status,next_check_time,processing_started_at,disabled FROM health_check WHERE id=1"
        ).fetchone() == ("critical", 1234, 5678, 1)
        assert db.execute("SELECT check_type,url,check_interval FROM health_check WHERE id=2").fetchone() == (
            "sentinel",
            "http://unrelated",
            10,
        )
    current = (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ctime_ns)
    assert sql_run(path, "check").stdout.strip() == "current"
    assert (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ctime_ns) == current


def test_sql_missing_and_corrupt_are_distinct_without_creation(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"
    assert sql_run(path, "check").stdout.strip() == "absent"
    assert not path.exists()
    path.write_bytes(b"not a database")
    before = path.read_bytes()
    result = sql_run(path, "apply")
    assert result.returncode != 0
    assert "suppressed" in result.stderr
    assert path.read_bytes() == before
    assert "synthetic-only" not in result.stdout + result.stderr


def test_vendored_tailscale_resource_hashes() -> None:
    receipt = json.loads((ROOT / "tests/parity/tailscale_sources.json").read_text())
    for name, expected in receipt["resources"].items():
        path = ROOT / "src/ops_deploy/infra/tailscale/templates" / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected


def test_paired_tailscale_role_resource_hashes() -> None:
    library = os.environ.get("OPS_LIBRARY_PATH")
    if not library:
        pytest.skip("Explicit paired ops-library checkout required for selected original-role provenance")
    receipt = json.loads((ROOT / "tests/parity/tailscale_sources.json").read_text())
    for name, expected in receipt["resources"].items():
        path = Path(library) / "roles/tailscale_metrics_endpoint/templates" / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected


def test_missing_binary_defers_preferences_until_native_prerequisites(monkeypatch: pytest.MonkeyPatch) -> None:
    from pyinfra.api import DeployError

    from ops_deploy.infra.tailscale import deploy as module

    class Missing:
        def get_fact(self, *args: Any, **kwargs: Any) -> None:
            return None

    monkeypatch.setattr(module, "host", Missing())
    monkeypatch.setattr(
        module, "probe", lambda *args, **kwargs: pytest.fail("No failing native probe before package install")
    )
    commands = list(cast(Any, module.preferences).__wrapped__(TailscaleConfig(hostname="owned").model_dump_json()))
    assert len(commands) == 1
    assert "apply-prefs" in commands[0].get_raw_value()

    class Present:
        def get_fact(self, *args: Any, **kwargs: Any) -> str:
            return "/usr/bin/tailscale"

    monkeypatch.setattr(module, "host", Present())
    monkeypatch.setattr(module, "probe", lambda *args, **kwargs: None)
    with pytest.raises(DeployError, match="unavailable"):
        list(cast(Any, module.preferences).__wrapped__(TailscaleConfig(hostname="owned").model_dump_json()))
