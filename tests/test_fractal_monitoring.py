"""Bounded collector gates, original resources and alerting input contracts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.infra.mail_relay_client import MailRelayClientConfig
from ops_deploy.infra.smartd import SmartdConfig, SmartdDevice
from ops_deploy.infra.smartd.render import render as smartd_render
from ops_deploy.infra.zed import ZedConfig
from ops_deploy.services.fractal_monitoring.config import BackupEndpointConfig, SchemaRule, StorageEndpointConfig
from ops_deploy.services.fractal_monitoring.render import render

ROOT = Path(__file__).parents[1]
FILES = ROOT / "src/ops_deploy/services/fractal_monitoring/files"


def script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location("owned_monitoring_helper", FILES / name)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_smartd_overrides_keep_original_command_policy() -> None:
    cfg = SmartdConfig(
        mail_to="root",
        devices=(
            SmartdDevice(name="owned", device="/dev/owned", type="sat", no_spinup=True, short_schedule="S/../.././05"),
        ),
        opts="--interval=7200",
    )
    text = smartd_render(cfg)
    assert "/dev/owned -d sat -n standby -a -o on -S on -s (S/../.././05|L/../../6/03) -W 4,40,45 -m root\n" in text
    assert "smartctl" not in text


@pytest.mark.parametrize(
    "override",
    [
        dict(relayhost="mail; touch /tmp/x"),
        dict(relayhost="ok", port=0),
        dict(relayhost="ok", myorigin="localhost"),
        dict(relayhost="ok", postfix_settings={"invalid key": "value"}),
    ],
)
def test_relay_rejects_unsafe_or_invalid_settings(override: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        MailRelayClientConfig(**override)


def test_tls_false_preserves_unowned_tls_level() -> None:
    cfg = MailRelayClientConfig(relayhost="127.0.0.1", myhostname="owned", myorigin="owned.invalid")
    assert "smtp_tls_security_level" not in cfg.desired()
    assert cfg.desired()["inet_interfaces"] == "loopback-only"
    assert cfg.model_copy(update={"use_tls": True}).desired()["smtp_tls_security_level"] == "may"


@pytest.mark.parametrize(
    "value",
    [dict(scrub_pools=("pool/child",)), dict(email_to="a\nZED_EMAIL_PROG=evil"), dict(scrub_spindown_enabled=True)],
)
def test_zed_rejects_invalid_policy_before_operations(value: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ZedConfig(**{"email_to": "root", **value})


@pytest.mark.parametrize(
    "value",
    [
        dict(service_name="../evil"),
        dict(timer_name="bad timer"),
        dict(port=0),
        dict(path="/foo;bad"),
        dict(json_path="/tmp/../bad"),
        dict(timer_interval=0),
    ],
)
def test_endpoint_rejects_unsafe_template_values(value: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        StorageEndpointConfig(**value)


def test_endpoint_derived_paths_and_account_follow_original_defaults() -> None:
    cfg = BackupEndpointConfig(user="owned", data_dir="/var/lib/owned", htpasswd_dir="/etc/owned")
    assert (cfg.group, cfg.json_path, cfg.cache_json_path, cfg.htpasswd_path) == (
        "owned",
        "/var/lib/owned/backup.json",
        "/var/lib/owned/backup.json",
        "/etc/owned/htpasswd",
    )


def test_http_scripts_and_collectors_compile_without_hardware_calls() -> None:
    cases: list[tuple[StorageEndpointConfig | BackupEndpointConfig, tuple[str, ...]]] = [
        (StorageEndpointConfig(), ("storage_metrics_httpd.py",)),
        (BackupEndpointConfig(), ("backup_metrics_httpd.py", "backup_metrics_exporter.py")),
    ]
    for cfg, names in cases:
        for name in names:
            compile(render(cfg, name), name, "exec")


def test_fresh_compatible_error_payload_does_not_force_recollection(tmp_path: Path) -> None:
    helper = script("endpoint_host.py")
    cache = tmp_path / "cached.json"
    cache.write_text(json.dumps({"summary": {"ok": False}, "error": "owned unavailable dataset"}))
    cfg = dict(
        json_path=str(cache),
        freshness_sec=600,
        schema=[SchemaRule(path=("summary", "ok"), kind="boolean", equals_true=True).model_dump()],
    )
    before = cache.stat()
    assert helper.cache_current(cfg) is True
    assert helper.schema_valid({"summary": {"ok": False}}, cfg["schema"]) is False
    after = cache.stat()
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    os.utime(cache, (time.time() - 700, time.time() - 700))
    assert helper.cache_current(cfg) is False
    cache.write_text('{"summary":{"ok":1}}')
    assert helper.cache_current(cfg) is False
    cache.write_text('{"summary":{"ok":false},"meta":"old incompatible meta"}')
    assert helper.cache_current(cfg) is True  # HTTP derives meta from mtime, replacing that field.


@pytest.mark.parametrize("body", ["null", "[]", "invalid", '{"summary":{}}'])
def test_missing_or_incompatible_report_requires_refresh(tmp_path: Path, body: str) -> None:
    helper = script("endpoint_host.py")
    path = tmp_path / "report.json"
    cfg = dict(json_path=str(path), freshness_sec=600, schema=[dict(path=["summary", "ok"], kind="boolean")])
    assert helper.cache_current(cfg) is False
    path.write_text(body)
    assert helper.cache_current(cfg) is False


@pytest.mark.parametrize("value", [True, False, None, 1, 1.5, "1", float("inf")])
def test_schema_distinguishes_booleans_from_numbers(value: Any) -> None:
    helper = script("endpoint_host.py")
    rule = dict(path=["value"], kind="number_or_none")
    assert helper.schema_valid(dict(value=value), [rule]) is (
        value is None or (type(value) in (int, float) and value != float("inf"))
    )


def test_symlinked_cache_is_refused_without_following(tmp_path: Path) -> None:
    helper = script("endpoint_host.py")
    target = tmp_path / "target"
    target.write_text("{}")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        helper.cache_current(dict(json_path=str(link), freshness_sec=600, schema=[]))


def test_unknown_rollout_debt_refuses_instead_of_claiming_current(tmp_path: Path) -> None:
    helper = script("endpoint_host.py")
    path = tmp_path / "debt"
    path.write_text('{"unknown":true}')
    with pytest.raises(ValueError, match="unknown rollout debt"):
        helper.debt(dict(debt=str(path)))


def test_credential_database_failure_is_not_a_password_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = script("endpoint_host.py")
    path = tmp_path / "htpasswd"
    path.write_text("malformed owned fixture\n")
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    class Result:
        returncode = 7

    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **kw: Result())
    with pytest.raises(ValueError, match="left intact"):
        helper.auth_current(dict(htpasswd_path=str(path), auth_user="owned", password="unused-owned-fixture"))
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def nyxmon_fixture(path: Path) -> None:
    import sqlite3

    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE service(id INTEGER PRIMARY KEY,name TEXT);
        CREATE TABLE health_check(id INTEGER PRIMARY KEY,name TEXT,service_id INTEGER,
          check_type TEXT,url TEXT,check_interval INTEGER,data TEXT,disabled INTEGER,
          status TEXT,next_check_time INTEGER,processing_started_at INTEGER);
        INSERT INTO service VALUES(1,'other');
        INSERT INTO health_check VALUES(1,'unrelated',1,'http','http://unrelated.invalid',50,'{}',0,'running',88,99);
        INSERT INTO health_check VALUES(2,'Fractal Storage Health (HTTP)',1,'http','http://legacy.invalid',50,'{}',0,'critical',88,99);
        """)


def test_original_nyxmon_global_legacy_retirement_and_current_row_continuity(tmp_path: Path) -> None:
    import sqlite3

    helper = script("nyxmon_check.py")
    path = tmp_path / "checks.sqlite3"
    nyxmon_fixture(path)
    data: dict[str, Any] = dict(
        url="http://owned.invalid",
        auth=dict(username="nyxmon", password="owned-unused"),
        checks=[dict(path="$.value", op=">", value="2.5")],
    )
    assert helper.upsert_check(str(path), "Fractal Storage", data) is True
    assert data["checks"][0]["value"] == 2.5
    with sqlite3.connect(path) as conn:
        legacy = conn.execute(
            "SELECT disabled,status,next_check_time,processing_started_at FROM health_check WHERE id=2"
        ).fetchone()
        assert legacy == (1, "idle", 0, 0)
        unrelated = conn.execute(
            "SELECT status,next_check_time,processing_started_at FROM health_check WHERE id=1"
        ).fetchone()
        assert unrelated == ("running", 88, 99)
        conn.execute(
            "UPDATE health_check SET status='running',next_check_time=123,processing_started_at=456 "
            "WHERE name='Fractal Storage'"
        )
    assert helper.current(str(path), "Fractal Storage", data) is True
    assert helper.upsert_check(str(path), "Fractal Storage", data) is False
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT status,next_check_time,processing_started_at FROM health_check WHERE name='Fractal Storage'"
        ).fetchone()
        assert row == ("running", 123, 456)
        # A short-lived boolean probe leaves no database keeper/lock behind.
        conn.execute("BEGIN EXCLUSIVE")
        conn.rollback()


def test_original_nyxmon_changed_or_disabled_row_resets_processing_only_when_updated(tmp_path: Path) -> None:
    import sqlite3

    helper = script("nyxmon_check.py")
    path = tmp_path / "checks.sqlite3"
    nyxmon_fixture(path)
    data = dict(url="http://owned.invalid", checks=[dict(path="$.value", op="==", value=True)])
    helper.upsert_check(str(path), "Fractal Backup", data)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE health_check SET disabled=1,status='running',next_check_time=123,processing_started_at=456 "
            "WHERE name='Fractal Backup'"
        )
    assert helper.current(str(path), "Fractal Backup", data) is False
    assert helper.upsert_check(str(path), "Fractal Backup", data) is True
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT disabled,status,next_check_time,processing_started_at FROM health_check WHERE name='Fractal Backup'"
        ).fetchone()
        assert row == (0, "idle", 0, 0)
    data["url"] = "http://changed.invalid"
    assert helper.current(str(path), "Fractal Backup", data) is False
    assert helper.upsert_check(str(path), "Fractal Backup", data) is True


def test_original_nyxmon_numeric_string_validation_does_not_accept_string_boolean(tmp_path: Path) -> None:
    helper = script("nyxmon_check.py")
    path = tmp_path / "checks.sqlite3"
    nyxmon_fixture(path)
    data = dict(url="http://owned.invalid", checks=[dict(path="$.value", op=">", value="true")])
    with pytest.raises(ValueError, match="numeric"):
        helper.upsert_check(str(path), "Fractal Storage", data)


def test_nyxmon_missing_database_refuses_without_creating_or_echoing_login(tmp_path: Path) -> None:
    import subprocess

    path = tmp_path / "absent.sqlite3"
    password = "owned-unused-sensitive-control"
    result = subprocess.run(
        ["python3", str(FILES / "nyxmon_check.py"), "apply", str(path), "Fractal Storage"],
        input=json.dumps(dict(url="http://owned.invalid", auth=dict(username="nyxmon", password=password))),
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert not path.exists()
    assert password not in result.stdout + result.stderr


def test_recent_lag_error_is_not_polled_until_freshness_expires(tmp_path: Path) -> None:
    from datetime import UTC, datetime, timedelta

    helper = script("endpoint_host.py")
    status = tmp_path / "status.json"
    marker = tmp_path / "parity.marker"
    job = dict(name="owned", bucket="owned", monitor_state_dir=str(tmp_path))
    cfg = dict(jobs=[job], destination_endpoint="http://owned.invalid:9001", freshness_sec=600)
    report = dict(
        job_name="owned",
        bucket="owned",
        destination_endpoint=cfg["destination_endpoint"],
        level="critical",
        checked_at=datetime.now(UTC).isoformat(),
        error="owned unavailable heartbeat",
    )
    status.write_text(json.dumps(report))
    marker.touch()
    before = (status.stat().st_mtime_ns, marker.stat().st_mtime_ns)
    assert helper.lag_cache_current(cfg) is True
    assert before == (status.stat().st_mtime_ns, marker.stat().st_mtime_ns)
    report["checked_at"] = (datetime.now(UTC) - timedelta(seconds=700)).isoformat()
    status.write_text(json.dumps(report))
    assert helper.lag_cache_current(cfg) is False


def test_exact_mc_binary_is_not_fetched_or_replaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    helper = script("endpoint_host.py")
    target = tmp_path / "mc"
    target.write_bytes(b"owned executable bytes")
    target.chmod(0o755)
    before = target.stat()
    monkeypatch.setattr(helper, "Path", lambda value: target if str(value) == "/usr/local/bin/mc" else Path(value))

    def no_network(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("current exact binary must never fetch")

    monkeypatch.setattr(helper, "urlopen", no_network)
    helper.install_mc(
        dict(mc_sha256=hashlib.sha256(target.read_bytes()).hexdigest(), mc_url="https://unreachable.invalid/mc")
    )
    after = target.stat()
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def test_wrong_mc_download_checksum_preserves_prior_binary_and_cleans_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from io import BytesIO

    helper = script("endpoint_host.py")
    target = tmp_path / "mc"
    target.write_bytes(b"prior owned binary")
    before = target.stat()
    monkeypatch.setattr(helper, "Path", lambda value: target if str(value) == "/usr/local/bin/mc" else Path(value))
    monkeypatch.setattr(helper, "urlopen", lambda *a, **kw: BytesIO(b"wrong download body"))
    with pytest.raises(ValueError, match="checksum mismatch"):
        helper.install_mc(dict(mc_sha256="0" * 64, mc_url="https://owned.invalid/mc"))
    assert target.read_bytes() == b"prior owned binary"
    after = target.stat()
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    assert list(tmp_path.glob(".monitoring-mc-*")) == []


def test_original_collector_and_unit_source_bytes_are_retained() -> None:
    oracle = json.loads((ROOT / "tests/parity/fractal_monitoring_sources.json").read_text())
    for name, digest in oracle["sha256"].items():
        path = ROOT / "src/ops_deploy" / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name


@pytest.mark.parametrize("pending", [False, True])
@pytest.mark.parametrize("dropin_present", [False, True])
@pytest.mark.parametrize("family", ["storage", "backup"])
def test_endpoint_default_plan_and_execute_never_read_incomplete_results(
    pending: bool, dropin_present: bool, family: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ops_deploy.services.fractal_monitoring import deploy as implementation
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    cfg = StorageEndpointConfig() if family == "storage" else BackupEndpointConfig()

    def states(command: str, *, name: str, stdin: str | None = None) -> str:
        if name in {"Declared monitoring path metadata admission", "Endpoint account metadata"}:
            return "current"
        if name == "Cached metrics endpoint configuration/auth/refresh state":
            return "pending" if pending else "current"
        if name == "Selected cached HTTP endpoint rollout state":
            assert stdin is not None
            return "pending" if pending or json.loads(stdin)["force_restart"] else "current"
        raise AssertionError(name)

    monkeypatch.setattr(implementation, "probe", states)
    responses = {
        **fakehost.UBUNTU,
        **fakehost.deb_installed("python3", "apache2-utils"),
        **fakehost.system_account("metrics", "/home/metrics", shell="/usr/sbin/nologin"),
        **fakehost.stat(cfg.data_dir, group="metrics", mode="drwxr-x---"),
        **fakehost.stat(cfg.htpasswd_dir, group="metrics", mode="drwxr-x---"),
    }
    if dropin_present:
        responses.update(
            fakehost.file(f"/etc/systemd/system/{cfg.service_name}.service.d/metrics-httpd-impl.conf", "[Service]\n")
        )
    rows = [dict(path=cfg.exporter_path, content="owned fake exporter\n", mode=0o755, refresh=True)]
    run = run_deploy_fake(
        lambda: implementation.deploy_endpoint(cfg, rows, (), "owned-unused-wiring-login"), responses=responses
    )
    assert run.succeeded
    assert not any("/etc/shadow" in event.value for event in run.events)
    finish = next(op for op in run.ops if "HTTP server once" in op.name)
    assert finish.changed is (pending or dropin_present)
    assert all("owned-unused-wiring-login" not in " ".join(op.args) for op in run.ops)


@pytest.mark.parametrize(
    "value",
    [
        dict(pools=("owned",), pool_capacity_thresholds={"other": {"warning_ratio": 0.8, "critical_ratio": 0.9}}),
        dict(pools=("owned",), pool_capacity_thresholds={"owned": {"warning_ratio": 0.9, "critical_ratio": 0.8}}),
        dict(
            pool_capacity_thresholds={"owned": {"warning_ratio": 0.8, "critical_ratio": 0.9, "warning_free_bytes": 10}}
        ),
        dict(disks=({"name": "owned", "device": "/dev/owned", "type": "typo"},)),
        dict(filesystems=({"name": "owned", "path": "relative"},)),
        dict(zfs_datasets=({"name": "owned", "dataset": "pool/a"}, {"name": "owned", "dataset": "pool/b"})),
        dict(zfs_datasets=({"name": "owned"},)),
        dict(timemachine_bundle_dirs=("/owned", "/owned")),
        dict(timemachine_bundle_dirs=("/",)),
        dict(quiet_hours_cache_max_age_sec=0),
    ],
)
def test_exporter_restores_original_admission_contracts(value: dict[str, Any]) -> None:
    from ops_deploy.services.fractal_monitoring.config import StorageExporterConfig

    with pytest.raises(ValidationError):
        StorageExporterConfig(**value)


def test_declared_path_admission_refuses_links_and_nonregular_scratch_before_bodies(tmp_path: Path) -> None:
    helper = script("endpoint_host.py")
    root = tmp_path / "root"
    root.mkdir()
    target = tmp_path / "other"
    target.mkdir()
    (root / "linked").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="linked"):
        helper.admit([dict(path=str(root / "linked/report.json"), kind="file", required=False)])
    helper.admit([dict(path=str(root / "missing/report.json"), kind="file", required=False)])
    with pytest.raises(ValueError, match="required existing exporter"):
        helper.admit([dict(path=str(root / "missing-exporter"), kind="file", required=True)])


def test_enabled_exporter_is_independent_of_disabled_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    from ops_deploy.core.secrets import SecretRef, SecretValues
    from ops_deploy.infra.mail_relay_client import MailRelayClientConfig
    from ops_deploy.services.fractal_monitoring import deploy as implementation
    from ops_deploy.services.fractal_monitoring.config import FractalMonitoringConfig, StorageExporterConfig
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    def states(command: str, *, name: str, stdin: str | None = None) -> str:
        return "100.64.0.7" if name == "Fractal alert relay Tailscale identity" else "current"

    monkeypatch.setattr(implementation, "probe", states)
    cfg = FractalMonitoringConfig(
        relay=MailRelayClientConfig(enabled=False),
        smartd=SmartdConfig(enabled=False),
        zed=ZedConfig(enabled=False),
        exporter=StorageExporterConfig(bin_path="/usr/local/bin/owned-exporter"),
        storage=StorageEndpointConfig(enabled=False),
        backup=BackupEndpointConfig(enabled=False),
        expected_tailscale_ipv4="100.64.0.7",
        expected_relay_ipv4="100.64.0.2",
        storage_schema=(),
        backup_schema=(),
    )
    secrets = SecretValues(
        SecretRef("secrets/owned.yml"), {implementation.CREDENTIAL_FIELD: "owned-unused-independent-login"}
    )
    run = run_deploy_fake(
        implementation.deploy_fractal_monitoring,
        cfg=cfg,
        secrets=secrets,
        responses={**fakehost.UBUNTU, **fakehost.deb_installed("python3")},
    )
    assert run.succeeded
    assert any(path == cfg.exporter.bin_path for path, body in run.uploads)
    assert any(op.name.endswith("Ensure original exporter pool-cache directory") for op in run.ops)
    assert not any("Reconcile storage cached resources" in op.name for op in run.ops)


@pytest.mark.parametrize(
    "role",
    [
        "mail_relay_client",
        "smartd",
        "zed",
        "nyxmon_storage_exporter",
        "storage_metrics_endpoint",
        "backup_metrics_endpoint",
    ],
)
def test_s4_original_role_behavior_provenance(role: str) -> None:
    import os

    from tests.test_ops_library_drift import role_digest

    path = os.environ.get("OPS_LIBRARY_PATH")
    if not path:
        pytest.skip("paired S4 role provenance requires explicit OPS_LIBRARY_PATH")
    oracle = json.loads((ROOT / "tests/parity/fractal_monitoring_sources.json").read_text())
    assert role_digest(Path(path) / "roles" / role) == oracle["role_behavior_sha256"][role]
