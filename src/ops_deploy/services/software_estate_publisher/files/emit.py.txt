#!/usr/bin/env python3
"""One local scan -> one immutable report. No network and no remote execution."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import collect
import outbox

MAX_BYTES = 8 * 1024 * 1024


def application_failed(app):
    if app.get("status") == "error":
        return True
    evidence = app.get("items")
    if not isinstance(evidence, dict):
        return False  # Bundle inventory has a list of items, not nested probes.
    return bool(evidence.get("coverage")) or any(
        evidence[name].get("status") != "ok"
        for name in ("git", "python")
        if name in evidence
    )


def envelope(observation, *, preserve_partial=False):
    if not isinstance(preserve_partial, bool):
        raise ValueError("preserve_partial must be a boolean")
    categories = {
        name: observation["categories"][name] for name in ("packages", "containers")
    }
    categories["units"] = observation["categories"]["services"]
    applications = list(observation["applications"])
    if "application_bundles" in observation["categories"]:
        applications.append(
            {
                "id": "macos-application-bundles",
                **observation["categories"]["application_bundles"],
            }
        )
    if any(application_failed(app) for app in applications):
        categories["applications"] = {
            "status": "error",
            "items": [],
            "error": "application_probe_failed",
        }
        if preserve_partial:
            categories["applications"]["partial_items"] = applications
    else:
        categories["applications"] = {"status": "ok", "items": applications}
    # Extra collector metadata is represented as an explicit coverage note in this pilot.
    return {
        "schema_version": 1,
        "host": observation["host"],
        "snapshot_id": str(uuid.uuid4()),
        "observed_at": datetime.fromtimestamp(
            observation["observed_at"], timezone.utc
        ).isoformat(),
        "collector": observation["collector"],
        "categories": categories,
        "gaps": observation["gaps"] + ["host_metadata:not_in_pilot_envelope"],
    }


def write_report(report, spool):
    data = (
        json.dumps(
            report,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        + b"\n"
    )
    if len(data) > MAX_BYTES:
        raise ValueError("report exceeds 8 MiB")
    spool = Path(spool)
    if any(part.is_symlink() for part in (spool.absolute(), *spool.absolute().parents)):
        raise ValueError("spool must not be a symlink")
    spool.mkdir(parents=True, exist_ok=True, mode=0o700)
    if spool.stat().st_uid != os.geteuid() or spool.stat().st_mode & 0o077:
        raise ValueError("spool must be owner-only and owned by the current user")
    with outbox.locked(spool):
        return publish_report(data, report, spool)


def publish_report(data, report, spool):
    if len(outbox.entries(spool)) >= outbox.MAX_REPORTS:
        raise ValueError(
            "pilot outbox full; preserve reports and reconcile delivery before cleanup"
        )
    target = spool / outbox.report_name(report["snapshot_id"])
    if target.exists():
        raise ValueError("snapshot file already exists")
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=spool)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        # Hard-link publication never replaces an existing report, even under races.
        os.link(temporary, target)
    finally:
        os.unlink(temporary)
    outbox.sync_directory(spool)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--spool", type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    if not isinstance(policy, dict) or not isinstance(policy.get("host"), str):
        raise ValueError("host policy required")
    print(
        write_report(
            envelope(
                collect.collect(policy),
                preserve_partial=policy.get("preserve_partial_applications", False),
            ),
            args.spool,
        )
    )


if __name__ == "__main__":
    main()
