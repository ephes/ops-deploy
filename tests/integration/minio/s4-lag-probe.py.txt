#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

MC = "/usr/local/bin/mc"

# Values that must never reach stdout/stderr, the journal, or status.json.
_SECRETS: list[str] = []


def redact(text):
    """Replace every registered secret with a placeholder."""
    out = "" if text is None else str(text)
    for secret in _SECRETS:
        if secret:
            out = out.replace(secret, "***")
    return out


def mc_host_env(endpoint, user, password):
    """Build an MC_HOST_<alias> value so credentials never appear in argv.

    `mc alias set <alias> <url> <user> <pass>` puts the secret in the process
    command line, which is world-readable via /proc/<pid>/cmdline, and
    subprocess.CalledProcessError stringifies process.args — which is how the
    root password previously reached the journal and, from there, Loki.
    """
    parts = urlsplit(endpoint)
    netloc = "{}:{}@{}".format(quote(user, safe=""), quote(password, safe=""), parts.netloc)
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def run(args, *, input_text=None, capture_output=True):
    """Run a command, raising a redacted error so secrets cannot leak.

    `from None` drops the CalledProcessError context; chaining it would put
    the original process.args (and any secret in it) back into the traceback.
    The probe copies str(exc) into status.json and the journal line, so an
    unredacted message would be persisted and shipped to Loki.
    """
    try:
        return subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=capture_output,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "command {} failed with exit {}: {}".format(
                redact(" ".join(str(a) for a in args)),
                exc.returncode,
                redact(exc.stderr).strip() or "(no stderr)",
            )
        ) from None


def run_json(args):
    result = run(args)
    return json.loads(result.stdout)


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: minio-replication-lag-probe.py <destination-endpoint> <jobs-config>",
            file=sys.stderr,
        )
        return 1

    destination_endpoint, jobs_config_path = sys.argv[1:3]
    minio_root_user = os.environ.get("MINIO_ROOT_USER")
    minio_root_password = os.environ.get("MINIO_ROOT_PASSWORD")
    if not minio_root_user or not minio_root_password:
        raise SystemExit("MINIO_ROOT_USER or MINIO_ROOT_PASSWORD missing from environment")

    with open(jobs_config_path, "r", encoding="utf-8") as handle:
        jobs = json.load(handle)
    if not jobs:
        raise SystemExit("No MinIO replication monitor jobs configured")

    # Register secrets for redaction, then hand mc its credentials through the
    # MC_HOST_<alias> environment variable instead of `mc alias set` argv.
    _SECRETS.extend(s for s in (minio_root_password, minio_root_user) if s)
    os.environ["MC_HOST_dst"] = mc_host_env(destination_endpoint, minio_root_user, minio_root_password)

    overall_exit_code = 0

    for job in jobs:
        bucket = job["bucket"]
        job_name = job.get("name") or bucket.replace("-", "_")
        heartbeat_key = job.get("heartbeat_key") or "_replication-health/heartbeat.json"
        # heartbeat: false jobs have no object in their own bucket. Their queue and
        # parity are measured on macmini and replicated as a status object through
        # another bucket; its age stands in for the lag of this job.
        heartbeat_enabled = job.get("heartbeat", True) is not False
        heartbeat_bucket = bucket if heartbeat_enabled else job.get("heartbeat_status_bucket")
        state_dir = Path(job.get("monitor_state_dir") or f"/var/lib/minio-replication-monitor/{job_name}")
        warning_seconds = int(float(job.get("warning_hours", 2)) * 3600)
        critical_seconds = int(float(job.get("critical_hours", 6)) * 3600)
        required = bool(job.get("required", True))
        marker_file = state_dir / "lag.marker"
        # parity.marker carries the time of the last run that saw parity_ok.
        # A required file check (parity_critical_hours) turns a parity breach
        # that outlasts the grace into a critical Nyxmon result; shorter
        # breaches (nightly upload bursts) only show in status.json/journal.
        parity_marker_file = state_dir / "parity.marker"
        status_file = state_dir / "status.json"
        checked_at = utc_now()

        status = {
            "checked_at": checked_at,
            "destination_endpoint": destination_endpoint,
            "job_name": job_name,
            "bucket": bucket,
            "heartbeat": heartbeat_enabled,
            "heartbeat_bucket": heartbeat_bucket,
            "heartbeat_key": heartbeat_key,
            "lag_basis": (
                "heartbeat_in_bucket" if heartbeat_enabled else "status_object_in_heartbeat_bucket"
            ),
            "warning_seconds": warning_seconds,
            "critical_seconds": critical_seconds,
            "required": required,
            "queued_count": None,
            "queued_bytes": None,
            "lag_seconds": None,
            "parity_ok": None,
            "critical_reasons": [],
            "object_delta": None,
            "object_delta_tolerance": None,
            "source_objects": None,
            "destination_objects": None,
            "size_diff_bytes": None,
            "source_size_bytes": None,
            "destination_size_bytes": None,
            "size_diff_percent": None,
            "parity_tolerance_percent": None,
            "parity_size_delta_tolerance_bytes": None,
            "level": "critical",
            "error": None,
        }

        try:
            if not heartbeat_bucket or (not heartbeat_enabled and heartbeat_bucket == bucket):
                raise RuntimeError("heartbeat: false needs heartbeat_status_bucket (another bucket)")
            heartbeat_stat = run_json([MC, "stat", "--json", f"dst/{heartbeat_bucket}/{heartbeat_key}"])
            heartbeat_payload = json.loads(
                run([MC, "cat", f"dst/{heartbeat_bucket}/{heartbeat_key}"]).stdout
            )
            if heartbeat_payload.get("bucket", bucket) != bucket:
                raise RuntimeError(
                    "heartbeat object {}/{} describes bucket {!r}, not {!r}".format(
                        heartbeat_bucket, heartbeat_key, heartbeat_payload.get("bucket"), bucket
                    )
                )

            modified = datetime.fromisoformat(heartbeat_stat["lastModified"])
            heartbeat_epoch = int(modified.timestamp())
            now_epoch = int(datetime.now(timezone.utc).timestamp())
            lag_seconds = now_epoch - heartbeat_epoch
            queued_count = int(heartbeat_payload.get("queued_count", 0))
            queued_bytes = int(heartbeat_payload.get("queued_bytes", 0))
            parity_ok = bool(heartbeat_payload.get("parity_ok", False))
            object_delta = int(heartbeat_payload.get("object_delta", 0))
            object_delta_tolerance = int(heartbeat_payload.get("object_delta_tolerance", 0))
            source_objects = int(heartbeat_payload.get("source_objects", 0))
            destination_objects = int(heartbeat_payload.get("destination_objects", 0))
            size_diff_bytes = int(heartbeat_payload.get("size_diff_bytes", 0))
            source_size = int(heartbeat_payload.get("source_size_bytes", 0))
            destination_size = int(heartbeat_payload.get("destination_size_bytes", 0))
            size_diff_percent = float(heartbeat_payload.get("size_diff_percent", 0))
            parity_tolerance_percent = float(heartbeat_payload.get("parity_tolerance_percent", 0))
            parity_size_delta_tolerance_bytes = int(
                heartbeat_payload.get("parity_size_delta_tolerance_bytes", 0)
            )

            level = "ok"
            if lag_seconds >= critical_seconds:
                level = "critical"
            elif lag_seconds >= warning_seconds:
                level = "warning"

            critical_reasons = []
            if lag_seconds >= critical_seconds:
                critical_reasons.append("lag_exceeds_critical_threshold")
            if not parity_ok:
                level = "critical"
                if queued_count != 0:
                    critical_reasons.append("replication_queue_nonzero")
                if object_delta > object_delta_tolerance:
                    critical_reasons.append("object_delta_exceeds_tolerance")
                size_within_tolerance = size_diff_percent <= parity_tolerance_percent
                if parity_size_delta_tolerance_bytes > 0:
                    size_within_tolerance = (
                        size_within_tolerance
                        or size_diff_bytes <= parity_size_delta_tolerance_bytes
                    )
                if not size_within_tolerance:
                    critical_reasons.append("size_delta_exceeds_tolerance")
                if not critical_reasons:
                    critical_reasons.append("parity_not_ok")

            marker_file.parent.mkdir(parents=True, exist_ok=True)
            marker_file.touch(exist_ok=True)
            os.utime(marker_file, (heartbeat_epoch, heartbeat_epoch))
            if parity_ok:
                parity_marker_file.touch(exist_ok=True)
                os.utime(parity_marker_file, (now_epoch, now_epoch))

            status.update(
                {
                    "queued_count": queued_count,
                    "queued_bytes": queued_bytes,
                    "lag_seconds": lag_seconds,
                    "parity_ok": parity_ok,
                    "critical_reasons": critical_reasons,
                    "object_delta": object_delta,
                    "object_delta_tolerance": object_delta_tolerance,
                    "source_objects": source_objects,
                    "destination_objects": destination_objects,
                    "size_diff_bytes": size_diff_bytes,
                    "source_size_bytes": source_size,
                    "destination_size_bytes": destination_size,
                    "size_diff_percent": size_diff_percent,
                    "parity_tolerance_percent": parity_tolerance_percent,
                    "parity_size_delta_tolerance_bytes": parity_size_delta_tolerance_bytes,
                    "level": level,
                    "error": None,
                }
            )
        except Exception as exc:  # noqa: BLE001 - operator status payload should capture raw failure
            status["parity_ok"] = False
            status["critical_reasons"] = ["probe_error"]
            status["error"] = str(exc)
            status["level"] = "critical"

        # A new job (or a wiped state dir) starts its parity grace at the first
        # run instead of paging at once while existing objects still replicate.
        if not parity_marker_file.exists():
            parity_marker_file.parent.mkdir(parents=True, exist_ok=True)
            parity_marker_file.touch()

        atomic_write_json(status_file, status)

        # status.json is overwritten on every run, so a non-ok verdict leaves no
        # trace once the next run succeeds. Emit the deciding values to stderr so
        # the journal retains why a given run reported warning/critical.
        if status["level"] != "ok":
            print(
                "job={job} level={level} required={required} lag_seconds={lag} "
                "queued_count={queued} object_delta={odelta}/{otol} "
                "size_diff_bytes={sdelta} size_diff_percent={spct} "
                "reasons={reasons} error={error}".format(
                    job=status.get("job_name"),
                    level=status["level"],
                    required=required,
                    lag=status.get("lag_seconds"),
                    queued=status.get("queued_count"),
                    odelta=status.get("object_delta"),
                    otol=status.get("object_delta_tolerance"),
                    sdelta=status.get("size_diff_bytes"),
                    spct=status.get("size_diff_percent"),
                    reasons=",".join(status.get("critical_reasons") or []) or "-",
                    error=status.get("error") or "-",
                ),
                file=sys.stderr,
            )

        if required and status["level"] == "critical":
            overall_exit_code = 2

    return overall_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
