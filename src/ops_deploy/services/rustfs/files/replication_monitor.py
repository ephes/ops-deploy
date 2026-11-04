#!/usr/bin/python3 -I
"""RustFS replication heartbeat writer (source) and lag/parity probe (replica).

Same contract as the MinIO replica monitor: the source writes one heartbeat
object per job with the replication queue and both sides' object count and
size; the replica judges lag by the age of the replicated object and keeps
``<state_root>/<job>/{status.json,lag.marker,parity.marker}`` for file-age
checks. Talks SigV4 through the RustFS deploy's helper (``rustfs_iam_host``
next to this script's library directory). Credentials come from the
environment and never reach argv, stdout, stderr or a status file; errors
carry only the helper's constant diagnostics.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

LIBRARY = "/usr/local/lib/rustfs-replication-monitor"
REGION = "us-east-1"
PAGE = 1000


def library():
    sys.path.insert(0, os.environ.get("RUSTFS_MONITOR_LIBRARY", LIBRARY))
    import rustfs_iam_host

    return rustfs_iam_host


def credentials(prefix):
    access, secret = os.environ.get(prefix + "ACCESS_KEY"), os.environ.get(prefix + "SECRET_KEY")
    if not access or not secret:
        raise SystemExit(prefix + "ACCESS_KEY or " + prefix + "SECRET_KEY missing from environment")
    return access, secret


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Bucket:
    """One bucket's objects through one identity."""

    def __init__(self, iam, api, creds, name):
        self.iam, self.api, self.creds, self.name = iam, api, creds, name

    def get(self, key, query=()):
        status, data = self.api.request("GET", f"/{self.name}/{key}" if key else "/" + self.name, *self.creds,
                                        query=list(query))  # fmt: skip
        if status != 200:
            raise self.iam.Refused(f"GET {self.name} answered {status}")
        return data

    def put(self, key, body):
        status, _ = self.api.request("PUT", f"/{self.name}/{key}", *self.creds, body=body,
                                        headers={"content-type": "application/json"})  # fmt: skip
        if status != 200:
            raise self.iam.Refused(f"PUT {self.name} answered {status}")

    def listing(self, prefix=None):
        """(key, size, last modified) of every current object, all pages."""
        token = None
        while True:
            query = [("list-type", "2"), ("max-keys", str(PAGE))]
            if prefix is not None:
                query.append(("prefix", prefix))
            if token:
                query.append(("continuation-token", token))
            root = self.iam.parse_xml(self.get("", query), "object listing is malformed")
            for item in root.findall("Contents"):
                yield self.iam.text(item, "Key"), int(self.iam.text(item, "Size") or 0), self.iam.text(
                    item, "LastModified"
                )
            if self.iam.text(root, "IsTruncated") != "true":
                return
            token = self.iam.text(root, "NextContinuationToken")
            if not token:
                raise self.iam.Refused("truncated object listing without a continuation token")

    def usage(self):
        objects = size = 0
        for _key, length, _modified in self.listing():
            objects += 1
            size += length
        return objects, size


def queue(iam, api, creds, bucket):
    status, data = api.request("GET", iam.ADMIN + "replicationmetrics", *creds, query=[("bucket", bucket)])
    if status != 200:
        raise iam.Refused(f"replication metrics answered {status}")
    current = ((iam.parse_json(data, "replication metrics are malformed").get("queued") or {}).get("curr")) or {}
    return int(current.get("count", 0)), int(current.get("bytes", 0))


def heartbeat(iam, local_endpoint, replica_endpoint, jobs):
    root = credentials("RUSTFS_")
    monitor = credentials("RUSTFS_MONITOR_")
    local = iam.Api(local_endpoint, REGION)
    replica = iam.Api(replica_endpoint, REGION, remote=True)
    exit_code = 0
    for job in jobs:
        bucket = job["bucket"]
        try:
            queued_count, queued_bytes = queue(iam, local, root, bucket)
            src_objects, src_size = Bucket(iam, local, root, bucket).usage()
            dst_objects, dst_size = Bucket(iam, replica, monitor, bucket).usage()
            size_diff_bytes = abs(dst_size - src_size)
            # An empty source with a nonempty replica is a full size mismatch.
            size_diff_percent = size_diff_bytes * 100.0 / src_size if src_size > 0 else 100.0 if dst_size else 0.0
            object_delta = abs(dst_objects - src_objects)
            size_ok = size_diff_percent <= job["parity_tolerance_percent"]
            if job["parity_size_delta_tolerance_bytes"] > 0:
                size_ok = size_ok or size_diff_bytes <= job["parity_size_delta_tolerance_bytes"]
            payload = {
                "checked_at": utc_now(),
                "job_name": job["name"],
                "bucket": bucket,
                "heartbeat": job["heartbeat"],
                "heartbeat_bucket": job["heartbeat_bucket"],
                "heartbeat_key": job["heartbeat_key"],
                "queued_count": queued_count,
                "queued_bytes": queued_bytes,
                "parity_ok": queued_count == 0 and object_delta <= job["parity_object_delta_tolerance"] and size_ok,
                "source_objects": src_objects,
                "destination_objects": dst_objects,
                "object_delta": object_delta,
                "object_delta_tolerance": job["parity_object_delta_tolerance"],
                "size_diff_bytes": size_diff_bytes,
                "source_size_bytes": src_size,
                "destination_size_bytes": dst_size,
                "size_diff_percent": size_diff_percent,
                "parity_tolerance_percent": job["parity_tolerance_percent"],
                "parity_size_delta_tolerance_bytes": job["parity_size_delta_tolerance_bytes"],
            }
            Bucket(iam, local, root, job["heartbeat_bucket"]).put(
                job["heartbeat_key"], json.dumps(payload, separators=(",", ":")).encode()
            )
        except Exception as error:  # noqa: BLE001 - keep other jobs progressing on partial failure
            print(f"heartbeat job failed for bucket={bucket}: {safe(iam, error)}", file=sys.stderr)
            exit_code = 2
    return exit_code


def safe(iam, error):
    """Only the helper's constant diagnostics; anything else may carry data."""
    return str(error) if isinstance(error, iam.Refused) else type(error).__name__


def atomic_write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def touch(path, epoch):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    os.utime(path, (epoch, epoch))


def evaluate(job, payload, lag_seconds):
    """Level and reasons exactly as the MinIO replica probe decides them."""
    warning, critical = int(job["warning_hours"] * 3600), int(job["critical_hours"] * 3600)
    level = "critical" if lag_seconds >= critical else "warning" if lag_seconds >= warning else "ok"
    reasons = ["lag_exceeds_critical_threshold"] if lag_seconds >= critical else []
    if not payload["parity_ok"]:
        level = "critical"
        if payload["queued_count"] != 0:
            reasons.append("replication_queue_nonzero")
        if payload["object_delta"] > payload["object_delta_tolerance"]:
            reasons.append("object_delta_exceeds_tolerance")
        size_ok = payload["size_diff_percent"] <= payload["parity_tolerance_percent"]
        if payload["parity_size_delta_tolerance_bytes"] > 0:
            size_ok = size_ok or payload["size_diff_bytes"] <= payload["parity_size_delta_tolerance_bytes"]
        if not size_ok:
            reasons.append("size_delta_exceeds_tolerance")
        if not reasons:
            reasons.append("parity_not_ok")
    return level, reasons


NUMBERS = {
    "queued_count": int, "queued_bytes": int, "object_delta": int, "object_delta_tolerance": int,
    "source_objects": int, "destination_objects": int, "size_diff_bytes": int, "source_size_bytes": int,
    "destination_size_bytes": int, "size_diff_percent": float, "parity_tolerance_percent": float,
    "parity_size_delta_tolerance_bytes": int,
}  # fmt: skip


def probe(iam, local_endpoint, state_root, jobs):
    monitor = credentials("RUSTFS_MONITOR_")
    api = iam.Api(local_endpoint, REGION)
    exit_code = 0
    for job in jobs:
        state = Path(state_root) / job["name"]
        lag_marker, parity_marker, status_file = state / "lag.marker", state / "parity.marker", state / "status.json"
        status = {
            "checked_at": utc_now(),
            "destination_endpoint": local_endpoint,
            "job_name": job["name"],
            "bucket": job["bucket"],
            "heartbeat": job["heartbeat"],
            "heartbeat_bucket": job["heartbeat_bucket"],
            "heartbeat_key": job["heartbeat_key"],
            "lag_basis": "heartbeat_in_bucket" if job["heartbeat"] else "status_object_in_heartbeat_bucket",
            "warning_seconds": int(job["warning_hours"] * 3600),
            "critical_seconds": int(job["critical_hours"] * 3600),
            "required": job["required"],
            **{key: None for key in NUMBERS},
            "lag_seconds": None,
            "parity_ok": None,
            "critical_reasons": [],
            "level": "critical",
            "error": None,
        }
        try:
            bucket = Bucket(iam, api, monitor, job["heartbeat_bucket"])
            found = [row for row in bucket.listing(job["heartbeat_key"]) if row[0] == job["heartbeat_key"]]
            if not found:
                raise iam.Refused("heartbeat object is absent on the replica")
            modified = datetime.fromisoformat(found[0][2].replace("Z", "+00:00"))
            body = iam.parse_json(bucket.get(job["heartbeat_key"]), "heartbeat object is malformed")
            if body.get("bucket") != job["bucket"]:
                raise iam.Refused("heartbeat object describes another bucket")
            payload = {key: cast(body.get(key, 0)) for key, cast in NUMBERS.items()}
            payload["parity_ok"] = body.get("parity_ok") is True
            heartbeat_epoch = int(modified.timestamp())
            now = int(datetime.now(timezone.utc).timestamp())
            lag_seconds = now - heartbeat_epoch
            level, reasons = evaluate(job, payload, lag_seconds)
            touch(lag_marker, heartbeat_epoch)
            if payload["parity_ok"]:
                touch(parity_marker, now)
            status.update(payload, lag_seconds=lag_seconds, critical_reasons=reasons, level=level)
        except Exception as error:  # noqa: BLE001 - the status file records why this run failed
            status.update(parity_ok=False, critical_reasons=["probe_error"], error=safe(iam, error), level="critical")
        # A new job (or a wiped state dir) starts its parity grace at the first
        # run instead of paging at once while existing objects still replicate.
        if not parity_marker.exists():
            parity_marker.parent.mkdir(parents=True, exist_ok=True)
            parity_marker.touch()
        atomic_write_json(status_file, status)
        if status["level"] != "ok":
            print(
                "job={job_name} level={level} required={required} lag_seconds={lag_seconds} "
                "queued_count={queued_count} object_delta={object_delta}/{object_delta_tolerance} "
                "size_diff_bytes={size_diff_bytes} size_diff_percent={size_diff_percent} reasons={reasons} "
                "error={error}".format(**{**status, "reasons": ",".join(status["critical_reasons"]) or "-",
                                         "error": status["error"] or "-"}),
                file=sys.stderr,
            )  # fmt: skip
        if job["required"] and status["level"] == "critical":
            exit_code = 2
    return exit_code


def main(argv):
    usage = "usage: rustfs-replication-monitor heartbeat LOCAL REPLICA JOBS | probe LOCAL STATE_ROOT JOBS"
    if len(argv) != 5 or argv[1] not in ("heartbeat", "probe"):
        print(usage, file=sys.stderr)
        return 1
    iam = library()
    jobs = json.loads(Path(argv[4]).read_text(encoding="utf-8"))
    if not jobs:
        raise SystemExit("no RustFS replication monitor jobs configured")
    if argv[1] == "heartbeat":
        return heartbeat(iam, argv[2], argv[3], jobs)
    return probe(iam, argv[2], argv[3], jobs)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
