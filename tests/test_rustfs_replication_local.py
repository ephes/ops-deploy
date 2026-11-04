"""Bucket replication and its monitor between two real RustFS 1.0.4 servers.

Skipped unless ``RUSTFS_BINARY`` names the pinned release executable
(``just test-rustfs-replication <binary>``). Starts a source and a replica
server as the current user on free loopback ports with private data
directories, runs the IAM/replication helper (check, apply, check) on both as
the deploy does, then the heartbeat writer and the lag/parity probe, and
checks what the fake tests cannot: replicated objects, overwrites, deletes and
existing objects, paginated counts, the status files, replicator rotation, the
refusal of foreign lifecycle rules and that no credential reaches any output.
Loopback targets need ``RUSTFS_REPLICATION_ALLOW_LOOPBACK_TARGET`` on the
source; production replicates to the replica's Tailnet name and never sets it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

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
)
from ops_deploy.services.rustfs.config import BINARY_SHA256
from ops_deploy.services.rustfs.deploy import RESOURCE, iam_payload, monitor_jobs

BINARY = os.environ.get("RUSTFS_BINARY", "")
pytestmark = pytest.mark.skipif(not BINARY, reason="set RUSTFS_BINARY to the pinned RustFS 1.0.4 executable")

FILES = Path(str(RESOURCE.joinpath("files")))
SECRETS = ("source-root-value", "replica-root-value", "replicator-value-1", "replicator-value-2", "monitor-value-1")


def user(access: str, secret: str) -> RustfsUserCredentials:
    return RustfsUserCredentials(access=SecretStr(access), secret=SecretStr(secret))


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_ready(port: int) -> None:
    for _ in range(90):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                sock.sendall(b"GET /health/ready HTTP/1.0\r\n\r\n")
                if b" 200 " in sock.recv(64):
                    return
        except OSError:
            pass
        time.sleep(1)
    raise AssertionError(f"RustFS on {port} did not become ready")


@pytest.fixture(scope="module")
def servers(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, int]]:
    assert hashlib.sha256(Path(BINARY).read_bytes()).hexdigest() in BINARY_SHA256, "not the pinned binary"
    processes = []
    ports = {"source": free_port(), "replica": free_port()}
    try:
        for name, port in ports.items():
            root = tmp_path_factory.mktemp(name)
            (root / "data").mkdir()
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(root),
                "RUSTFS_ACCESS_KEY": f"{name}-root",
                "RUSTFS_SECRET_KEY": f"{name}-root-value",
                "RUSTFS_VOLUMES": str(root / "data"),
                "RUSTFS_ADDRESS": f"127.0.0.1:{port}",
                "RUSTFS_REGION": "us-east-1",
                "RUSTFS_CONSOLE_ENABLE": "false",
                "RUSTFS_FTP_ENABLE": "false",
                "RUSTFS_FTPS_ENABLE": "false",
                "RUSTFS_SFTP_ENABLE": "false",
                "RUSTFS_WEBDAV_ENABLE": "false",
                "RUSTFS_CHECK_UPDATE": "false",
                "RUSTFS_OBS_ENDPOINT": "",
            }
            if name == "source":
                env["RUSTFS_REPLICATION_ALLOW_LOOPBACK_TARGET"] = "true"
            log = (root / "log").open("w")
            processes.append(
                subprocess.Popen([BINARY, "server"], cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
            )
        for port in ports.values():
            wait_ready(port)
        yield ports
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=60)


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
REPLICATOR_POLICY = RustfsPolicy(
    name="replica-replicator",
    document={
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetReplicationConfiguration", "s3:ListBucket", "s3:ListBucketMultipartUploads",
                    "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration",
                ],
                "Resource": [f"arn:aws:s3:::{job.bucket}" for job in JOBS],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ReplicateTags", "s3:AbortMultipartUpload", "s3:GetObject", "s3:GetObjectVersion",
                    "s3:GetObjectVersionTagging", "s3:PutObject", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
                    "s3:DeleteObject", "s3:ReplicateObject", "s3:ReplicateDelete",
                ],
                "Resource": [f"arn:aws:s3:::{job.bucket}/*" for job in JOBS],
            },
        ],
    },
)  # fmt: skip
MONITOR_POLICY = RustfsPolicy(
    name="replica-monitor",
    document={
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{job.bucket}" for job in JOBS],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{job.heartbeat_bucket}/{job.heartbeat_key}" for job in JOBS],
            },
        ],
    },
)
MONITOR = user("replica-monitor", "monitor-value-1")


def replica_config(port: int) -> RustfsConfig:
    return RustfsConfig(
        api_port=port,
        buckets=BUCKETS,
        policies=(REPLICATOR_POLICY, MONITOR_POLICY),
        identities=(
            RustfsIdentity(name="replicator", policies=("replica-replicator",), proof="backups"),
            RustfsIdentity(name="monitor", policies=("replica-monitor",), proof="backups"),
        ),
        monitor=RustfsReplicationMonitor(role="replica", jobs=JOBS),
    )


def source_config(port: int, replica: int) -> RustfsConfig:
    return RustfsConfig(
        api_port=port,
        buckets=BUCKETS,
        replications=tuple(
            RustfsReplication(
                bucket=job.bucket,
                rule_id=f"replica-{job.bucket}",
                endpoint=f"127.0.0.1:{replica}",
                target_bucket=job.bucket,
            )
            for job in JOBS
        ),
        monitor=RustfsReplicationMonitor(role="source", jobs=JOBS, replica_endpoint=f"http://127.0.0.1:{replica}"),
    )


def helper(action: str, cfg: RustfsConfig, creds: RustfsCredentials) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(FILES / "iam_host.py"), action],
        input=iam_payload(cfg, creds),
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert not any(secret in result.stdout + result.stderr for secret in SECRETS)
    assert result.returncode == 0, result.stdout
    return dict(json.loads(result.stdout))


def library() -> types.ModuleType:
    module = types.ModuleType("rustfs_iam_host")
    exec(compile((FILES / "iam_host.py").read_text(), "iam_host", "exec"), module.__dict__)
    return module


def monitor_run(args: list[str], env: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    lib = tmp_path / "lib"
    lib.mkdir(exist_ok=True)
    (lib / "rustfs_iam_host.py").write_text((FILES / "iam_host.py").read_text())
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(FILES / "replication_monitor.py"), *args],
        env={"PATH": "/usr/bin:/bin", "RUSTFS_MONITOR_LIBRARY": str(lib), **env},
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert not any(secret in result.stdout + result.stderr for secret in SECRETS)
    return result


def wait_for(predicate: Any, what: str, timeout: int = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(1)
    raise AssertionError(f"timed out waiting for {what}")


def test_replication_and_monitor_round_trip(servers: dict[str, int], tmp_path: Path) -> None:
    replica, source = replica_config(servers["replica"]), source_config(servers["source"], servers["replica"])
    replicator = user("replicator-1", "replicator-value-1")
    replica_creds = RustfsCredentials(
        root=user("replica-root", "replica-root-value"),
        identities={"replicator": replicator, "monitor": MONITOR},
        monitor=MONITOR,
    )
    source_creds = RustfsCredentials(
        root=user("source-root", "source-root-value"), replication=replicator, monitor=MONITOR
    )
    iam = library()
    src = iam.Api(source.endpoint, "us-east-1")
    dst = iam.Api(replica.endpoint, "us-east-1")
    src_root, dst_root = ("source-root", "source-root-value"), ("replica-root", "replica-root-value")

    # Replica first (buckets, identities), then the source with its targets and rules.
    for cfg, creds in ((replica, replica_creds), (source, source_creds)):
        pending = helper("check", cfg, creds)["pending"]
        assert pending > 0
        assert helper("apply", cfg, creds) == {"pending": pending, "changed": True}
        assert helper("check", cfg, creds) == {"pending": 0, "changed": False}

    # Existing, new, overwritten and deleted objects reach the replica.
    for index in range(1105):
        assert src.request("PUT", f"/backups/many/{index:05d} ä x", *src_root, body=b"y" * 10)[0] == 200
    src.request("PUT", "/obsidian/Notes/a.md", *src_root, body=b"first")
    src.request("PUT", "/obsidian/Notes/a.md", *src_root, body=b"second version")
    assert src.request("DELETE", "/backups/many/00000 ä x", *src_root)[0] == 204
    wait_for(lambda: dst.request("GET", "/obsidian/Notes/a.md", *dst_root)[1] == b"second version", "overwrite")
    wait_for(lambda: dst.request("GET", "/backups/many/00000 ä x", *dst_root)[0] == 404, "delete marker")

    # Heartbeat on the source, probe on the replica.
    jobs = tmp_path / "jobs.json"
    jobs.write_text(monitor_jobs(source))
    monitor_env = {"RUSTFS_MONITOR_ACCESS_KEY": "replica-monitor", "RUSTFS_MONITOR_SECRET_KEY": "monitor-value-1"}
    source_env = {**monitor_env, "RUSTFS_ACCESS_KEY": "source-root", "RUSTFS_SECRET_KEY": "source-root-value"}
    beat = monitor_run(["heartbeat", source.endpoint, f"http://127.0.0.1:{servers['replica']}", str(jobs)], source_env,
                       tmp_path)  # fmt: skip
    assert beat.returncode == 0, beat.stderr
    state = tmp_path / "state"
    wait_for(
        lambda: monitor_run(["probe", replica.endpoint, str(state), str(jobs)], monitor_env, tmp_path).returncode == 0,
        "probe ok",
    )
    backups = json.loads((state / "backups/status.json").read_text())
    obsidian = json.loads((state / "obsidian/status.json").read_text())
    assert backups["level"] == obsidian["level"] == "ok"
    assert backups["source_objects"] == backups["destination_objects"] == 1104
    assert obsidian["source_objects"] == obsidian["destination_objects"] == 1
    for job in ("backups", "obsidian"):
        assert (state / job / "lag.marker").exists()
        assert (state / job / "parity.marker").exists()

    # The monitor identity reads but cannot write or delete on the replica.
    monitor_creds = ("replica-monitor", "monitor-value-1")
    assert dst.request("PUT", "/backups/x", *monitor_creds, body=b"x")[0] == 403
    assert dst.request("DELETE", "/backups/_replication-health/heartbeat.json", *monitor_creds)[0] == 403

    # Rotating the replicator (new access key) updates the source's targets in place.
    rotated = user("replicator-2", "replicator-value-2")
    replica_rotated = replica_creds.model_copy(update={"identities": {"replicator": rotated, "monitor": MONITOR}})
    helper("apply", replica, replica_rotated)
    source_rotated = source_creds.model_copy(update={"replication": rotated})
    assert helper("check", source, source_rotated)["pending"] == 2
    helper("apply", source, source_rotated)
    assert helper("check", source, source_rotated) == {"pending": 0, "changed": False}
    src.request("PUT", "/backups/after-rotation", *src_root, body=b"z")
    wait_for(lambda: dst.request("GET", "/backups/after-rotation", *dst_root)[0] == 200, "replication after rotation")

    # A lifecycle rule this deployment does not own refuses instead of being replaced.
    foreign = (
        b'<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>other</ID>'
        b"<Status>Enabled</Status><Filter><Prefix>tmp/</Prefix></Filter><Expiration><Days>3</Days></Expiration>"
        b"</Rule></LifecycleConfiguration>"
    )
    md5 = base64.b64encode(hashlib.md5(foreign).digest()).decode()
    assert src.request("PUT", "/obsidian", *src_root, query=[("lifecycle", "")], body=foreign,
                       headers={"content-md5": md5})[0] == 200  # fmt: skip
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(FILES / "iam_host.py"), "check"],
        input=iam_payload(source, source_rotated),
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 1
    assert (
        result.stdout.strip() == "refused: bucket has lifecycle rules outside this deployment; refusing to replace them"
    )
