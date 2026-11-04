"""RustFS bucket replication, noncurrent expiry and the replication monitor.

Plans run against a fake host; the helper's inspection runs against a fake S3
answer table; the monitor script runs against a fake SigV4 client. The real
two-server round trip is ``tests/test_rustfs_replication_local.py``.
"""

from __future__ import annotations

import json
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.services.rustfs import (
    RustfsBucket,
    RustfsConfig,
    RustfsCredentials,
    RustfsIdentity,
    RustfsMonitorJob,
    RustfsPolicy,
    RustfsReplication,
    RustfsReplicationMonitor,
    RustfsUserCredentials,
    deploy_rustfs,
)
from ops_deploy.services.rustfs.deploy import RESOURCE, iam_payload, monitor_jobs, render
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.test_rustfs import facts

PREFIX = "Deploy RustFS | "
FILES = Path(str(RESOURCE.joinpath("files")))


def user(access: str, secret: str) -> RustfsUserCredentials:
    return RustfsUserCredentials(access=SecretStr(access), secret=SecretStr(secret))


ROOT = user("fixture-root", "fixture-root-value")
REPLICATOR = user("fixture-replicator", "fixture-replicator-value")
MONITOR = user("fixture-monitor", "fixture-monitor-value")
JOBS = (
    RustfsMonitorJob(name="backups", bucket="backups"),
    RustfsMonitorJob(
        name="obsidian",
        bucket="obsidian",
        heartbeat=False,
        heartbeat_status_bucket="backups",
        heartbeat_key="_replication-health/jobs/obsidian.json",
    ),
)
BUCKETS = tuple(RustfsBucket(name=job.bucket, noncurrent_expiry_days=7) for job in JOBS)
READ = RustfsPolicy(
    name="monitor",
    document={
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::backups"]}],
    },
)
REPLICA = RustfsConfig(
    bind_host="100.64.0.10",
    required_mount="/fast/rustfs",
    data_dir="/fast/rustfs/data",
    buckets=BUCKETS,
    policies=(READ,),
    identities=(RustfsIdentity(name="monitor", policies=("monitor",), proof="backups"),),
    monitor=RustfsReplicationMonitor(role="replica", jobs=JOBS),
)
REPLICA_CREDS = RustfsCredentials(root=ROOT, identities={"monitor": MONITOR}, monitor=MONITOR)
SOURCE = RustfsConfig(
    buckets=BUCKETS,
    replications=tuple(
        RustfsReplication(
            bucket=job.bucket,
            rule_id=f"replica-{job.bucket}",
            endpoint="replica.example:9020",
            target_bucket=job.bucket,
        )
        for job in JOBS
    ),
    monitor=RustfsReplicationMonitor(role="source", jobs=JOBS, replica_endpoint="http://replica.example:9020"),
)
SOURCE_CREDS = RustfsCredentials(root=ROOT, replication=REPLICATOR, monitor=MONITOR)


def monitor_facts(cfg: RustfsConfig, creds: RustfsCredentials) -> dict[str, Any]:
    monitor = cfg.monitor
    assert monitor is not None
    result = {
        **facts(cfg, creds),
        **fakehost.directory("/fast/rustfs"),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory("/etc"),
        **fakehost.directory(monitor.library_dir),
        **fakehost.file(f"{monitor.library_dir}/rustfs_iam_host.py", (FILES / "iam_host.py").read_text()),
        **fakehost.file(monitor.script_path, (FILES / "replication_monitor.py").read_text(), mode="-rwxr-xr-x"),
        **fakehost.file(monitor.jobs_path, monitor_jobs(cfg)),
        **fakehost.file(monitor.env_file, render("rustfs-replication-monitor.env.j2", cfg, creds), mode="-rw-------"),
        **fakehost.file(
            f"/etc/systemd/system/{monitor.unit}.service", render("rustfs-replication-monitor.service.j2", cfg)
        ),
        **fakehost.file(
            f"/etc/systemd/system/{monitor.unit}.timer", render("rustfs-replication-monitor.timer.j2", cfg)
        ),
        **fakehost.service(f"{monitor.unit}.timer"),
    }
    if monitor.role == "replica":
        result.update(fakehost.directory(monitor.state_root))
    return result


def execute(cfg: RustfsConfig, responses: dict[str, Any], creds: RustfsCredentials) -> FakeRun:
    return run_deploy_fake(deploy_rustfs, cfg, creds, responses=responses)


@pytest.mark.parametrize(("cfg", "creds"), [(REPLICA, REPLICA_CREDS), (SOURCE, SOURCE_CREDS)])
def test_converged_monitor_host_has_zero_managed_operations(cfg: RustfsConfig, creds: RustfsCredentials) -> None:
    run = execute(cfg, monitor_facts(cfg, creds), creds)
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    for command in run.executed_commands:
        for secret in ("fixture-root-value", "fixture-replicator-value", "fixture-monitor-value"):
            assert secret not in command


def test_fresh_monitor_installs_script_jobs_secret_and_enables_its_timer() -> None:
    response = facts(REPLICA, REPLICA_CREDS)
    response.update(fakehost.directory("/fast/rustfs"))
    run = execute(REPLICA, response, REPLICA_CREDS)
    assert run.succeeded, run.error
    names = [name.removeprefix(PREFIX) for name in run.mutating_changed_ops]
    for expected in (
        "Install /usr/local/lib/rustfs-replication-monitor/rustfs_iam_host.py",
        "Install /usr/local/bin/rustfs-replication-monitor",
        "Write RustFS replication monitor jobs",
        "Write RustFS replication monitor environment",
        "Ensure RustFS replication monitor state",
        "Install systemd unit rustfs-replication-lag-check.service",
        "Install systemd unit rustfs-replication-lag-check.timer",
        "Enable rustfs-replication-lag-check.timer",
    ):
        assert expected in names
    # The probe never runs during a deploy; only its timer starts.
    assert not any("start rustfs-replication-lag-check.service" in command for command in run.executed_commands)
    assert not any("fixture-monitor-value" in command for command in run.executed_commands)


def test_units_bind_the_right_credentials_and_arguments() -> None:
    source = render("rustfs-replication-monitor.service.j2", SOURCE)
    assert "EnvironmentFile=/etc/default/rustfs\n" in source
    assert "EnvironmentFile=/etc/default/rustfs-replication-monitor\n" in source
    assert (
        "ExecStart=/usr/bin/python3 -I -B /usr/local/bin/rustfs-replication-monitor heartbeat "
        "http://127.0.0.1:9020 http://replica.example:9020 /etc/rustfs-replication-monitor.json"
    ) in source
    assert "ReadWritePaths" not in source
    assert "Environment=RUSTFS_MONITOR_LIBRARY=/usr/local/lib/rustfs-replication-monitor\n" in source
    replica = render("rustfs-replication-monitor.service.j2", REPLICA)
    # The probe reads with the monitor identity only, never with root.
    assert "EnvironmentFile=/etc/default/rustfs\n" not in replica
    assert (
        "probe http://100.64.0.10:9020 /var/lib/rustfs-replication-monitor /etc/rustfs-replication-monitor.json"
    ) in replica
    assert "ReadWritePaths=/var/lib/rustfs-replication-monitor" in replica
    timer = render("rustfs-replication-monitor.timer.j2", REPLICA)
    assert "OnUnitActiveSec=300" in timer
    assert "OnBootSec=120" in timer
    env = render("rustfs-replication-monitor.env.j2", REPLICA, REPLICA_CREDS)
    assert 'RUSTFS_MONITOR_ACCESS_KEY="fixture-monitor"' in env
    assert 'RUSTFS_MONITOR_SECRET_KEY="fixture-monitor-value"' in env
    assert "fixture-root" not in env
    rows = json.loads(monitor_jobs(SOURCE))
    assert [row["heartbeat_bucket"] for row in rows] == ["backups", "backups"]
    assert "fixture" not in monitor_jobs(SOURCE)


def test_replica_listens_on_its_peer_address() -> None:
    assert REPLICA.endpoint == "http://100.64.0.10:9020"
    assert 'RUSTFS_ADDRESS="100.64.0.10:9020"' in render("rustfs.env.j2", REPLICA, REPLICA_CREDS)


def test_payload_carries_replications_and_their_remote_identity() -> None:
    payload = json.loads(iam_payload(SOURCE, SOURCE_CREDS))
    assert payload["replication"] == {"access": "fixture-replicator", "secret": "fixture-replicator-value"}
    assert [item["rule_id"] for item in payload["replications"]] == ["replica-backups", "replica-obsidian"]
    assert {bucket["noncurrent_expiry_days"] for bucket in payload["buckets"]} == {7}


@pytest.mark.parametrize(
    ("cfg", "creds", "message"),
    [
        (SOURCE, RustfsCredentials(root=ROOT, monitor=MONITOR), "replication credentials"),
        (SOURCE, RustfsCredentials(root=ROOT, replication=REPLICATOR), "monitor credentials"),
        (REPLICA, RustfsCredentials(root=ROOT, identities={"monitor": MONITOR}), "monitor credentials"),
    ],
)
def test_credentials_must_match_declarations(cfg: RustfsConfig, creds: RustfsCredentials, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        execute(cfg, monitor_facts(cfg, SOURCE_CREDS if cfg is SOURCE else REPLICA_CREDS), creds)


@pytest.mark.parametrize(
    "change",
    [
        {"bind_host": "0.0.0.0"},
        {"bind_host": "replica.example"},
        {"bind_host": "100.064.0.1"},
        {"buckets": (RustfsBucket(name="backups", versioning=False), BUCKETS[1])},
        {"replications": (*SOURCE.replications, SOURCE.replications[0])},
        {"monitor": {"role": "source", "jobs": [job.model_dump() for job in JOBS]}},
        {"monitor": {"role": "replica", "jobs": [{"name": "x", "bucket": "other"}]}},
        {"replications": SOURCE.replications[:1]},
        {"replications": (SOURCE.replications[0].model_copy(update={"target_bucket": "elsewhere"}),
                          SOURCE.replications[1])},
        {"monitor": {"role": "source", "jobs": [job.model_dump() for job in JOBS],
                     "replica_endpoint": "https://replica.example:9020"}},
    ],
)  # fmt: skip
def test_incoherent_replication_configuration_refused(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        RustfsConfig(**{**SOURCE.model_dump(), **change})


@pytest.mark.parametrize(
    "job",
    [
        {"heartbeat": False},
        {"heartbeat": False, "heartbeat_status_bucket": "obsidian"},
        {"heartbeat": False, "heartbeat_status_bucket": "backups"},
        {"heartbeat_status_bucket": "backups"},
        {"heartbeat_key": "/abs"},
        {"heartbeat_key": "a/../b"},
        {"warning_hours": 6, "critical_hours": 2},
    ],
)
def test_incoherent_monitor_jobs_refused(job: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        RustfsMonitorJob(name="obsidian", bucket="obsidian", **job)


def test_monitor_job_set_rules() -> None:
    with pytest.raises(ValidationError, match="another job's bucket"):
        RustfsReplicationMonitor(role="replica", jobs=JOBS[1:])
    with pytest.raises(ValidationError, match="unique"):
        RustfsReplicationMonitor(role="replica", jobs=(JOBS[0], JOBS[0]))
    with pytest.raises(ValidationError, match="two monitor intervals"):
        RustfsReplicationMonitor(
            role="replica",
            jobs=(RustfsMonitorJob(name="b", bucket="backups", parity_critical_hours=0.1),),
        )


# --- the helper's inspection against a fake S3/admin answer table ---------------------------------


def helper() -> types.ModuleType:
    module = types.ModuleType("rustfs_iam_host")
    exec(compile((FILES / "iam_host.py").read_text(), "iam_host", "exec"), module.__dict__)
    return module


ARN = "arn:rustfs:replication:us-east-1:dep:backups"
NS = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'
LIFECYCLE = (
    f"<LifecycleConfiguration {NS}><Rule><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>"
    "</Expiration><Filter><Prefix></Prefix></Filter><ID>replicated-noncurrent-expiry</ID><NoncurrentVersionExpiration>"
    "<NoncurrentDays>7</NoncurrentDays></NoncurrentVersionExpiration><Status>Enabled</Status></Rule>"
    "</LifecycleConfiguration>"
)
VERSIONED = f"<VersioningConfiguration {NS}><Status>Enabled</Status></VersioningConfiguration>"


def replication_xml(rule_id: str = "replica-backups", arn: str = ARN, delete_markers: str = "Enabled") -> str:
    return (
        "<ReplicationConfiguration><Role></Role><Rule><DeleteMarkerReplication><Status>"
        f"{delete_markers}</Status></DeleteMarkerReplication><DeleteReplication><Status>Enabled</Status>"
        f"</DeleteReplication><Destination><Bucket>{arn}</Bucket></Destination><ExistingObjectReplication><Status>"
        "Enabled</Status></ExistingObjectReplication><Filter><Prefix></Prefix></Filter>"
        f"<ID>{rule_id}</ID><Priority>1</Priority><SourceSelectionCriteria><ReplicaModifications><Status>Enabled"
        "</Status></ReplicaModifications></SourceSelectionCriteria><Status>Enabled</Status></Rule>"
        "</ReplicationConfiguration>"
    )


def target(access: str = "fixture-replicator") -> dict[str, Any]:
    return {
        "arn": ARN,
        "type": "replication",
        "endpoint": "replica.example:9020",
        "targetbucket": "backups",
        "secure": False,
        "credentials": {"accessKey": access, "secretKey": ""},
    }


def converged() -> dict[tuple[str, str, str], tuple[int, bytes]]:
    return {
        ("HEAD", "/backups", ""): (200, b""),
        ("GET", "/backups", "versioning="): (200, VERSIONED.encode()),
        ("GET", "/backups", "lifecycle="): (200, LIFECYCLE.encode()),
        ("GET", "/rustfs/admin/v3/list-remote-targets", "bucket=backups"): (200, json.dumps([target()]).encode()),
        ("GET", "/backups", "replication="): (200, replication_xml().encode()),
    }


def inspect(answers: dict[tuple[str, str, str], tuple[int, bytes]]) -> list[str]:
    module = helper()
    cfg = RustfsConfig(buckets=BUCKETS[:1], replications=SOURCE.replications[:1])

    def request(
        self: Any,
        method: str,
        path: str,
        access: str,
        secret: str,
        query: Any = (),
        body: bytes = b"",
        headers: Any = None,
    ) -> tuple[int, bytes]:
        key = (method, path, "&".join(f"{k}={v}" for k, v in query))
        return answers[key]

    module.Api.request = request
    payload = json.loads(iam_payload(cfg, RustfsCredentials(root=ROOT, replication=REPLICATOR)))
    return [action for action, _ in module.inspect(module.Server(payload), payload)]


def test_converged_replication_has_nothing_pending() -> None:
    assert inspect(converged()) == []


@pytest.mark.parametrize(
    ("change", "pending"),
    [
        ({("GET", "/backups", "lifecycle="): (404, b"<Error><Code>NoSuchLifecycleConfiguration</Code></Error>")},
         ["lifecycle"]),
        ({("GET", "/backups", "lifecycle="): (200, LIFECYCLE.replace("<NoncurrentDays>7", "<NoncurrentDays>9")
                                              .encode())}, ["lifecycle"]),
        ({("GET", "/rustfs/admin/v3/list-remote-targets", "bucket=backups"): (200, b"[]")},
         ["target", "replication"]),
        ({("GET", "/rustfs/admin/v3/list-remote-targets", "bucket=backups"): (200, json.dumps([target("old")])
                                                                              .encode())}, ["target_credentials"]),
        ({("GET", "/backups", "replication="): (404, b"<Error><Code>ReplicationConfigurationNotFoundError</Code>"
                                                   b"</Error>")}, ["replication"]),
        ({("GET", "/backups", "replication="): (200, replication_xml(arn="arn:other").encode())}, ["replication"]),
        ({("GET", "/backups", "replication="): (200, replication_xml(delete_markers="Disabled").encode())},
         ["replication"]),
    ],
)  # fmt: skip
def test_drift_is_planned(change: dict[Any, Any], pending: list[str]) -> None:
    assert inspect({**converged(), **change}) == pending


@pytest.mark.parametrize(
    "change",
    [
        {("GET", "/backups", "lifecycle="): (200, LIFECYCLE.replace("replicated-noncurrent-expiry", "other").encode())},
        {("GET", "/backups", "replication="): (200, replication_xml(rule_id="foreign").encode())},
        {("GET", "/backups", "replication="): (200, replication_xml().replace("<Role></Role>", "<Role>arn:x</Role>")
                                               .encode())},
        {("GET", "/backups", "replication="): (500, b"<Error><Code>InternalError</Code></Error>")},
        {("GET", "/rustfs/admin/v3/list-remote-targets", "bucket=backups"): (200, json.dumps([target(), target()])
                                                                             .encode())},
        {("GET", "/rustfs/admin/v3/list-remote-targets", "bucket=backups"): (200, b"{")},
        {("GET", "/backups", "lifecycle="): (200, b"<not-xml")},
    ],
)  # fmt: skip
def test_foreign_or_unknown_state_refuses(change: dict[Any, Any]) -> None:
    with pytest.raises(Exception, match=r"refusing|failed|malformed|ambiguous") as error:
        inspect({**converged(), **change})
    assert type(error.value).__name__ == "Refused"


def test_fresh_bucket_plans_everything_without_further_reads() -> None:
    answers = {("HEAD", "/backups", ""): (404, b"")}
    assert inspect(answers) == ["bucket", "lifecycle", "target", "replication"]


# --- the monitor script against a fake client -----------------------------------------------------


class FakeApi:
    iam: ClassVar[Any] = None
    objects: ClassVar[dict[tuple[str, str], tuple[bytes, str]]] = {}
    puts: ClassVar[list[tuple[str, bytes]]] = []
    metrics: ClassVar[dict[str, Any]] = {"queued": {"curr": {"count": 0.0, "bytes": 0.0}}}
    fail: ClassVar[set[str]] = set()

    def __init__(self, endpoint: str, region: str, remote: bool = False) -> None:
        self.endpoint = endpoint

    def request(self, method: str, path: str, access: str, secret: str, query: Any = (), body: bytes = b"",
                headers: Any = None) -> tuple[int, bytes]:  # fmt: skip
        if self.endpoint in self.fail:
            raise self.iam.Refused("server request failed or timed out")
        query = dict(query)
        if path.endswith("replicationmetrics"):
            return 200, json.dumps(self.metrics).encode()
        bucket, _, key = path.lstrip("/").partition("/")
        if method == "PUT":
            self.puts.append((path, body))
            return 200, b""
        if key:
            found = self.objects.get((bucket, key))
            return (200, found[0]) if found else (404, b"<Error><Code>NoSuchKey</Code></Error>")
        rows = sorted(
            (k, v) for (b, k), v in self.objects.items() if b == bucket and k.startswith(query.get("prefix", ""))
        )
        contents = "".join(
            f"<Contents><Key>{k}</Key><Size>{len(v[0])}</Size><LastModified>{v[1]}</LastModified></Contents>"
            for k, v in rows
        )
        return 200, f"<ListBucketResult {NS}>{contents}<IsTruncated>false</IsTruncated></ListBucketResult>".encode()


@pytest.fixture
def monitor(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    iam = helper()
    FakeApi.iam = iam
    FakeApi.objects, FakeApi.puts, FakeApi.fail = {}, [], set()
    iam.Api = FakeApi  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "rustfs_iam_host", iam)
    module = types.ModuleType("replication_monitor")
    exec(compile((FILES / "replication_monitor.py").read_text(), "replication_monitor", "exec"), module.__dict__)
    for key, value in {
        "RUSTFS_ACCESS_KEY": "fixture-root",
        "RUSTFS_SECRET_KEY": "fixture-root-value",
        "RUSTFS_MONITOR_ACCESS_KEY": "fixture-monitor",
        "RUSTFS_MONITOR_SECRET_KEY": "fixture-monitor-value",
    }.items():
        monkeypatch.setenv(key, value)
    return module


def rows() -> list[dict[str, Any]]:
    return list(json.loads(monitor_jobs(SOURCE)))


def stamp(age: timedelta) -> str:
    return (datetime.now(UTC) - age).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def test_heartbeat_measures_both_sides_and_writes_status_objects(monitor: types.ModuleType) -> None:
    FakeApi.objects = {
        ("backups", "a"): (b"12345", stamp(timedelta())),
        ("obsidian", "n.md"): (b"x", stamp(timedelta())),
    }
    assert monitor.heartbeat(monitor.library(), "http://127.0.0.1:9020", "http://replica.example:9020", rows()) == 0
    written = {path: json.loads(body) for path, body in FakeApi.puts}
    assert set(written) == {
        "/backups/_replication-health/heartbeat.json",
        "/backups/_replication-health/jobs/obsidian.json",
    }
    obsidian = written["/backups/_replication-health/jobs/obsidian.json"]
    assert obsidian["bucket"] == "obsidian"
    assert obsidian["parity_ok"] is True
    assert obsidian["source_objects"] == obsidian["destination_objects"] == 1


def test_heartbeat_failure_names_the_bucket_but_no_secret(
    monitor: types.ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    FakeApi.fail = {"http://replica.example:9020"}
    assert monitor.heartbeat(monitor.library(), "http://127.0.0.1:9020", "http://replica.example:9020", rows()) == 2
    err = capsys.readouterr().err
    assert "bucket=backups" in err
    assert "server request failed" in err
    assert "fixture" not in err
    assert FakeApi.puts == []


def test_heartbeat_counts_an_empty_source_against_a_nonempty_replica(monitor: types.ModuleType) -> None:
    class Sides(FakeApi):
        def request(self, method: str, path: str, *args: Any, **kwargs: Any) -> tuple[int, bytes]:
            if method == "GET" and path == "/backups" and self.endpoint.startswith("http://replica"):
                FakeApi.objects[("backups", "left-behind")] = (b"x" * 10, stamp(timedelta()))
                try:
                    return super().request(method, path, *args, **kwargs)
                finally:
                    del FakeApi.objects[("backups", "left-behind")]
            return super().request(method, path, *args, **kwargs)

    monitor.library().Api = Sides
    assert monitor.heartbeat(monitor.library(), "http://127.0.0.1:9020", "http://replica.example:9020", rows()) == 0
    backups = json.loads(dict(FakeApi.puts)["/backups/_replication-health/heartbeat.json"])
    assert backups["source_size_bytes"] == 0
    assert backups["size_diff_percent"] == 100.0
    assert backups["parity_ok"] is False


def test_server_error_codes_stay_out_of_diagnostics(
    monitor: types.ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    class Denied(FakeApi):
        def request(self, *args: Any, **kwargs: Any) -> tuple[int, bytes]:
            return 403, b"<Error><Code>LeakedValue</Code></Error>"

    monitor.library().Api = Denied
    assert monitor.heartbeat(monitor.library(), "http://127.0.0.1:9020", "http://replica.example:9020", rows()) == 2
    err = capsys.readouterr().err
    assert "answered 403" in err
    assert "LeakedValue" not in err


def heartbeat_object(bucket: str, **values: Any) -> bytes:
    payload = {"bucket": bucket, "parity_ok": True, "queued_count": 0, "object_delta": 0, "object_delta_tolerance": 200,
               "size_diff_percent": 0.0, "parity_tolerance_percent": 0.1, "size_diff_bytes": 0,
               "parity_size_delta_tolerance_bytes": 0, **values}  # fmt: skip
    return json.dumps(payload).encode()


def test_probe_keeps_minio_status_contract_and_markers(monitor: types.ModuleType, tmp_path: Path) -> None:
    FakeApi.objects = {
        ("backups", "_replication-health/heartbeat.json"): (heartbeat_object("backups"), stamp(timedelta(minutes=3))),
        ("backups", "_replication-health/jobs/obsidian.json"): (
            heartbeat_object("obsidian", parity_ok=False, queued_count=4),
            stamp(timedelta(hours=3)),
        ),
    }
    assert monitor.probe(monitor.library(), "http://100.64.0.10:9020", str(tmp_path), rows()) == 2
    backups = json.loads((tmp_path / "backups/status.json").read_text())
    assert backups["level"] == "ok"
    assert backups["lag_basis"] == "heartbeat_in_bucket"
    assert 170 <= backups["lag_seconds"] <= 200
    obsidian = json.loads((tmp_path / "obsidian/status.json").read_text())
    assert obsidian["level"] == "critical"
    assert obsidian["critical_reasons"] == ["replication_queue_nonzero"]
    assert obsidian["lag_basis"] == "status_object_in_heartbeat_bucket"
    lag = (tmp_path / "obsidian/lag.marker").stat().st_mtime
    assert abs(datetime.now(UTC).timestamp() - lag - 3 * 3600) < 60
    # The parity marker exists from the first run (grace), then follows parity_ok.
    assert (tmp_path / "obsidian/parity.marker").exists()
    assert set(backups) == set(obsidian)


def test_probe_records_a_missing_or_foreign_heartbeat(monitor: types.ModuleType, tmp_path: Path) -> None:
    FakeApi.objects = {
        ("backups", "_replication-health/heartbeat.json"): (heartbeat_object("other"), stamp(timedelta())),
    }
    assert monitor.probe(monitor.library(), "http://100.64.0.10:9020", str(tmp_path), rows()) == 2
    backups = json.loads((tmp_path / "backups/status.json").read_text())
    obsidian = json.loads((tmp_path / "obsidian/status.json").read_text())
    assert backups["error"] == "heartbeat object describes another bucket"
    assert obsidian["error"] == "heartbeat object is absent on the replica"
    assert backups["critical_reasons"] == ["probe_error"]
    assert not (tmp_path / "backups/lag.marker").exists()


@pytest.mark.parametrize(
    ("values", "lag_hours", "level", "reasons"),
    [
        ({}, 1, "ok", []),
        ({}, 3, "warning", []),
        ({}, 7, "critical", ["lag_exceeds_critical_threshold"]),
        ({"parity_ok": False, "object_delta": 300}, 0, "critical", ["object_delta_exceeds_tolerance"]),
        ({"parity_ok": False, "size_diff_percent": 5.0}, 0, "critical", ["size_delta_exceeds_tolerance"]),
        ({"parity_ok": False, "size_diff_percent": 5.0, "size_diff_bytes": 10, "parity_size_delta_tolerance_bytes": 20},
         0, "critical", ["parity_not_ok"]),
    ],
)  # fmt: skip
def test_evaluation_matches_the_minio_probe(
    monitor: types.ModuleType, values: dict[str, Any], lag_hours: float, level: str, reasons: list[str]
) -> None:
    payload = {**json.loads(heartbeat_object("backups")), **values}
    assert monitor.evaluate(rows()[0], payload, int(lag_hours * 3600)) == (level, reasons)
