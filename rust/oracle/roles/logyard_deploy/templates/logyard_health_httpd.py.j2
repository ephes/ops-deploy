#!/usr/bin/env python3
"""Expose a small JSON health and freshness contract for Logyard."""

from __future__ import annotations

import base64
import binascii
import json
import os
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen


BIND = os.environ.get("LOGYARD_HEALTH_BIND", "127.0.0.1")
PORT = int(os.environ.get("LOGYARD_HEALTH_PORT", "9105"))
PATH = os.environ.get("LOGYARD_HEALTH_PATH", "/.well-known/logyard")
LOKI_URL = os.environ.get("LOGYARD_LOKI_URL", "http://127.0.0.1:3101").rstrip("/")
SELECTOR = os.environ.get("LOGYARD_HEALTH_SELECTOR", '{host="macmini",source_type="journald"}')
WARNING_WINDOW_SECONDS = int(os.environ.get("LOGYARD_WARNING_WINDOW_SECONDS", "900"))
CRITICAL_WINDOW_SECONDS = int(os.environ.get("LOGYARD_CRITICAL_WINDOW_SECONDS", "3600"))
REQUEST_TIMEOUT_SECONDS = float(os.environ.get("LOGYARD_REQUEST_TIMEOUT_SECONDS", "10"))
SYSTEMCTL_TIMEOUT_SECONDS = float(os.environ.get("LOGYARD_HEALTH_SYSTEMCTL_TIMEOUT_SECONDS", "5"))
UNITS_B64 = os.environ.get("LOGYARD_HEALTH_UNITS_B64", "")

SYSTEMCTL_PROPERTIES = ("LoadState", "ActiveState", "SubState", "Result")


def _load_units() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Parse the configured unit list into (valid, rejected) entries.

    Entries are {"id": "<key>", "unit": "<systemd unit>"}. The id is a required,
    dot-free payload key: monitoring check paths are dot-delimited, so a key like
    "vector.service" could not be addressed unambiguously. Rejected entries are
    returned rather than dropped, so a misconfiguration is visible in the payload
    instead of silently monitoring nothing.
    """
    if not UNITS_B64:
        return [], []
    try:
        raw = base64.b64decode(UNITS_B64, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as err:
        return [], [{"reason": "invalid_base64", "detail": str(err)}]

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as err:
        return [], [{"reason": "invalid_json", "detail": str(err)}]
    if not isinstance(parsed, list):
        return [], [{"reason": "not_a_list"}]

    units: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in parsed:
        if not isinstance(entry, dict):
            rejected.append({"reason": "not_an_object"})
            continue

        # Values must be strings, not merely truthy: YAML `unit: yes` would
        # otherwise arrive as a boolean and be coerced into the key "True".
        unit = entry.get("unit")
        if not isinstance(unit, str) or not unit:
            rejected.append({"reason": "missing_unit"})
            continue

        # No implicit fallback to the unit name: unit names contain dots.
        ident = entry.get("id")
        if not isinstance(ident, str) or not ident:
            rejected.append({"unit": unit, "reason": "missing_id"})
            continue
        if "." in ident:
            rejected.append({"unit": unit, "id": ident, "reason": "id_contains_dot"})
            continue
        if ident in seen:
            rejected.append({"unit": unit, "id": ident, "reason": "duplicate_id"})
            continue

        seen.add(ident)
        units.append({"id": ident, "unit": unit})
    return units, rejected


UNITS, UNITS_REJECTED = _load_units()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _unit_unknown(unit: str, error: str) -> dict[str, Any]:
    """Full-shape entry for a probe that did not produce an answer.

    Every key stays present so monitoring paths never disappear, and `exists` is
    None rather than False: when the query itself failed, existence is unknown, not
    disproved.
    """
    return {
        "unit": unit,
        "exists": None,
        "load_state": None,
        "active_state": None,
        "sub_state": None,
        "result": None,
        "error": error,
    }


def _unit_status(unit: str) -> dict[str, Any]:
    args = ["systemctl", "show"]
    for prop in SYSTEMCTL_PROPERTIES:
        args.extend(["-p", prop])
    # Terminator before the unit name: valid units may start with "-" (e.g.
    # "-.mount", the root mount) and would otherwise parse as options.
    args.extend(["--", unit])

    try:
        completed = subprocess.run(  # noqa: S603
            args,
            capture_output=True,
            text=True,
            timeout=SYSTEMCTL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as err:
        return _unit_unknown(unit, str(err))

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        return _unit_unknown(
            unit, detail or f"systemctl show failed ({completed.returncode})"
        )

    data: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value

    # `systemctl show` exits 0 even for a unit that does not exist, so LoadState is
    # what actually distinguishes "missing" from "present but inactive".
    load_state = data.get("LoadState", "")
    return {
        "unit": unit,
        "exists": load_state not in ("", "not-found"),
        "load_state": load_state,
        "active_state": data.get("ActiveState"),
        "sub_state": data.get("SubState"),
        "result": data.get("Result"),
        "error": None,
    }


def _fetch_json(url: str) -> dict[str, Any]:
    with urlopen(url, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _query_count(window_seconds: int) -> float:
    expr = f"sum(count_over_time({SELECTOR}[{window_seconds}s]))"
    query = urlencode({"query": expr})
    body = _fetch_json(f"{LOKI_URL}/loki/api/v1/query?{query}")
    result = body.get("data", {}).get("result", [])
    if not result:
        return 0.0
    try:
        return float(result[0]["value"][1])
    except (KeyError, IndexError, TypeError, ValueError):
        return 0.0


def _build_payload() -> tuple[int, dict[str, Any]]:
    payload: dict[str, Any] = {
        "generated_at": _utc_now(),
        "status": "ok",
        "selector": SELECTOR,
    }

    try:
        with urlopen(f"{LOKI_URL}/ready", timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
            ready_status = response.status
            ready_body = response.read().decode("utf-8").strip()
        ready = ready_status == 200 and ready_body.lower() == "ready"
    except (HTTPError, URLError, TimeoutError) as err:
        ready = False
        ready_status = None
        ready_body = str(err)

    warning_entries = 0.0
    critical_entries = 0.0
    ingest_error = ""
    try:
        warning_entries = _query_count(WARNING_WINDOW_SECONDS)
        critical_entries = _query_count(CRITICAL_WINDOW_SECONDS)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as err:
        ingest_error = str(err)

    payload["loki"] = {
        "ready": ready,
        "ready_status": ready_status,
        "ready_body": ready_body,
    }
    payload["ingest"] = {
        "warning_window_seconds": WARNING_WINDOW_SECONDS,
        "critical_window_seconds": CRITICAL_WINDOW_SECONDS,
        "warning_window_entries": warning_entries,
        "critical_window_entries": critical_entries,
        "warning_fresh": warning_entries > 0,
        "critical_fresh": critical_entries > 0,
    }
    if ingest_error:
        payload["ingest"]["error"] = ingest_error

    # Always present (possibly empty) so monitoring paths have a stable shape.
    # Deliberately does not feed into "status" below: this reports producer-side
    # unit state, which is a separate signal from Logyard's own ingest health and
    # is asserted by its own monitoring check.
    payload["units"] = {entry["id"]: _unit_status(entry["unit"]) for entry in UNITS}
    if UNITS_REJECTED:
        payload["units_rejected"] = UNITS_REJECTED

    if not ready or ingest_error or critical_entries <= 0:
        payload["status"] = "critical"
    elif warning_entries <= 0:
        payload["status"] = "warning"

    return 200, payload


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != PATH:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"not_found"}')
            return

        _, payload = _build_payload()
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    server = ReusableThreadingHTTPServer((BIND, PORT), Handler)
    server.serve_forever()
