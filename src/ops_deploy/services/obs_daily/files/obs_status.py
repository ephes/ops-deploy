#!/usr/bin/env python3
"""Status endpoint of the observability routine for Nyxmon (ops-deploy ``services.obs_daily``), stdlib only.

``obs_status.py --config FILE`` serves ``GET /.well-known/obs-daily`` on
``status_listen`` (loopback; Nyxmon runs on the same host):

- ``pack``: date and age of the last evidence pack (``status.json``);
- ``triage``: date and status of the last result that reached the host
  (``triage.json``, written by ``obs_ctl.py deliver``); ``age_seconds`` is
  the age of the last triage that ran (status ok) and reached the owner, so
  days that were skipped or failed let it grow; ``delivery_age_seconds``
  counts any delivered result;
- ``unit_loops``: systemd units on any log-shipping host that restarted or
  failed at least ``loop_events`` times in the last ``loop_window_seconds``,
  or that systemd gave up on ("Start request repeated too quickly"), from
  systemd's own lines in Loki (one query per host). Transient units
  (``run-*``, ``session-*``, ``user@*``) are ignored. A background thread
  refreshes it every ``cache_seconds``; a request never waits for Loki. It
  is ``ok: false`` when the last query failed, the result is stale, no host
  logged in the window, a host that logged in the last day did not
  or a configured ``log_hosts`` host did not (``missing_hosts``;
  ``sleeping_hosts`` excepted), a host that logged in the window has none of
  PID 1's lines in the last day (``no_pid1_hosts``; ``non_systemd_hosts``
  such as the Studio run no systemd and are neither queried nor expected
  to, they are listed in ``non_systemd_hosts``), or a host hit the line
  limit. Host activity comes from a bounded ``count_over_time`` query;
- ``launchd``: age and crash loops of the last launchd report from the
  Studio (``launchd.json``, written by ``obs_ctl.py launchd``);
- ``timemachine``: the last Time Machine probe report from the Studio
  (``timemachine.json``, written by ``obs_ctl.py timemachine``): its age,
  ``tmutil_ok`` (``tmutil status`` answered in time), ``stalled_seconds``
  (a running backup without any progress: no change of phase, bytes, files
  or percent and no new band write on the backup server; 0 when no backup
  runs), ``cross_check_ok`` (the band read on the server worked, or no
  backup runs) and, for the reader only, ``state`` (``disabled`` when
  automatic backups are off and none runs: OK, information only).

A missing file reads as age ``999999999``, so a threshold check fails instead
of passing on a missing value.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import stat
import sys
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler
from types import ModuleType
from typing import Any

# --- bounded-httpd begin: keep identical to ops_deploy/services/_metrics_httpd/files/bounded_httpd.py ---
# One idle or slow client must not stall the endpoint (ops-control
# SECURITY_AUDIT_OPSLIB_ENDPOINTS_2026_11_12, E1). Every connection gets its own
# daemon thread, at most BOUNDED_HTTPD_MAX_CONNECTIONS at once (one more is closed
# when it is accepted); each read waits at most the handler's timeout, and the
# request line and headers must arrive within BOUNDED_HTTPD_HEADER_DEADLINE seconds
# in total, so a client that drips one byte just inside the read timeout is cut off
# too. The deadline is armed again for every request of a keep-alive connection.
import io as _bounded_io
import socket as _bounded_socket
import socketserver as _bounded_socketserver
import threading as _bounded_threading
import time as _bounded_time

BOUNDED_HTTPD_READ_TIMEOUT = 10
BOUNDED_HTTPD_HEADER_DEADLINE = 15
BOUNDED_HTTPD_MAX_CONNECTIONS = 32


class BoundedThreadingTCPServer(_bounded_socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self.connection_slots = _bounded_threading.BoundedSemaphore(BOUNDED_HTTPD_MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()


class _BoundedDeadlineReader(_bounded_io.RawIOBase):
    def __init__(self, handler):
        super().__init__()
        self._handler = handler

    def readable(self):
        return True

    def readinto(self, buffer):
        handler = self._handler
        timeout = handler.timeout
        deadline = handler.bounded_httpd_deadline
        if deadline is not None:
            remaining = deadline - _bounded_time.monotonic()
            if remaining <= 0:
                raise _bounded_socket.timeout("request header deadline passed")
            timeout = remaining if timeout is None else min(timeout, remaining)
        handler.connection.settimeout(timeout)
        return handler.connection.recv_into(buffer)


class BoundedRequestMixin:
    timeout = BOUNDED_HTTPD_READ_TIMEOUT
    bounded_httpd_deadline = None

    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = _bounded_io.BufferedReader(_BoundedDeadlineReader(self))

    def handle_one_request(self):
        self.bounded_httpd_deadline = _bounded_time.monotonic() + BOUNDED_HTTPD_HEADER_DEADLINE
        try:
            super().handle_one_request()
        finally:
            self.bounded_httpd_deadline = None

    def parse_request(self):
        try:
            return super().parse_request()
        finally:
            # The headers are in: the response and any body get the plain read timeout
            # again, not what was left of the deadline.
            self.bounded_httpd_deadline = None
            self.connection.settimeout(self.timeout)


# --- bounded-httpd end ---


NEVER = 999_999_999
PATH = "/.well-known/obs-daily"
LOKI_TIMEOUT = 30
MAX_STATE = 1024 * 1024
LOOP_HOLD = 1800  # as obs_ctl.py


def _pack_module() -> ModuleType:
    """``obs_pack.py`` from this directory (``-I`` keeps it off ``sys.path``)."""

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "obs_pack.py")
    spec = importlib.util.spec_from_file_location("obs_pack", path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["obs_pack"] = module
    spec.loader.exec_module(module)
    return module


pack = _pack_module()


def _read(path: str) -> dict[str, Any]:
    """A small JSON object from a regular file; a link, FIFO or oversized file reads as missing."""

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return {}
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return {}
        raw = os.read(fd, MAX_STATE + 1)
    except OSError:
        return {}
    finally:
        os.close(fd)
    try:
        data = json.loads(raw) if len(raw) <= MAX_STATE else None
    except (ValueError, RecursionError):  # RecursionError: nesting deeper than the parser allows
        return {}
    return data if isinstance(data, dict) else {}


def active_hosts(loki: Any, exclude: str, seconds: int, now: float, selector: str = '{host=~".+"}') -> list[str]:
    """Hosts with at least one line in the last ``seconds`` (a bounded count, not label metadata)."""

    query = f"sum by (host) (count_over_time({selector}{exclude} [{seconds}s]))"
    data = loki("query", {"query": query, "time": str(int(now * pack.NS))})
    return sorted(
        str(item["metric"].get("host"))
        for item in data.get("result", [])
        if item.get("metric", {}).get("host") and float(item["value"][1]) > 0
    )


def unit_loops(config: dict[str, Any], now: float, loki: Any) -> dict[str, Any]:
    """Units in a restart or failure loop, from systemd's own lines, one query per host.

    Per host, so a burst on one host cannot crowd out another; PID 1's lines
    only and transient units dropped in Loki, before the line limit applies.
    A host whose window still holds more lines than one query returns is
    listed in ``truncated_hosts``, and the result is then not ``ok``
    (incomplete coverage).
    """

    window = int(config["loop_window_seconds"])
    exclude = "".join(f" != {pack.lit(text)}" for text in config["loki_exclude_lines"])
    start, end = str(int((now - window) * pack.NS)), str(int(now * pack.NS))
    hosts = active_hosts(loki, exclude, window, now)
    # Expected: the configured log hosts (a host stays expected until it is retired in the config,
    # however long it is silent) and any other host that logged in the last day.
    expected = set(config.get("log_hosts", [])) | set(active_hosts(loki, exclude, 86400, now))
    # Sleeping hosts (``sleeping_hosts``) pause by design.
    missing = sorted(expected - set(hosts) - set(config.get("sleeping_hosts", [])))
    # PID 1 logs every few minutes (timers); a host without any of its lines in a day ships logs
    # without the ``service="init"`` label this check selects on, so its loops would go unseen.
    pid1 = '{service="init"}'
    parsed = ' | json pid="pid", unit="unit" | __error__ = "" | pid="1" | unit="init.scope"'
    with_pid1 = set(active_hosts(loki, exclude + parsed, 86400, now, selector=pid1))
    # Hosts without systemd (``non_systemd_hosts``, the macOS Studio) have no PID 1 lines to miss
    # and no units to loop; launchd has its own check. Only a configured name is skipped, so a
    # Linux host that stops shipping PID 1's lines stays a gap.
    non_systemd = set(config.get("non_systemd_hosts", []))
    systemd_hosts = sorted(str(h) for h in hosts if h not in non_systemd)
    no_pid1 = sorted(set(systemd_hosts) - with_pid1)
    counts: Counter[tuple[str, str, str]] = Counter()
    truncated, failed = [], []
    for host in systemd_hosts:
        params = {
            "query": pack.restart_selector(host, exclude),
            "start": start,
            "end": end,
            "limit": str(pack.MAX_LINES),
        }
        lines = 0
        try:
            streams = loki("query_range", params).get("result", [])
        except Exception:  # noqa: BLE001 - one host's failure must not hide the others' loops
            failed.append(host)
            continue
        for stream in streams:
            for _ts, raw in stream.get("values", []):
                lines += 1
                event = pack.systemd_event(raw)
                if event is not None:
                    counts[(host, event[0], event[1])] += 1
        if lines >= pack.MAX_LINES:
            truncated.append(host)
    per_unit: dict[tuple[str, str], dict[str, Any]] = {}
    for (host, unit, kind), count in counts.items():
        entry = per_unit.setdefault(
            (host, unit),
            {"host": host, "unit": unit, "restart": 0, "failed": 0, "gave_up": 0},
        )
        entry[kind] = count
    limit = int(config["loop_events"])
    loops = [
        entry
        for entry in per_unit.values()
        if entry["gave_up"] or entry["restart"] >= limit or entry["failed"] >= limit
    ]
    loops.sort(key=lambda e: (e["host"], e["unit"]))
    return {
        "window_seconds": window,
        "hosts": len(hosts),
        "missing_hosts": missing,
        "no_pid1_hosts": no_pid1,
        "non_systemd_hosts": sorted(set(hosts) & non_systemd),
        "count": len(loops),
        "loops": loops[:20],
        "truncated_hosts": truncated,
        "failed_hosts": sorted(failed),
    }


TM_INFO = (
    "host", "tmutil", "tmutil_detail", "running", "stopping", "phase", "percent", "bytes", "files",
    "total_bytes", "total_files", "auto_backup", "band_check", "band_detail",
)  # fmt: skip


def timemachine_section(report: dict[str, Any], now: float) -> dict[str, Any]:
    """The Time Machine probe report for Nyxmon; a missing report fails every rule (age, booleans absent)."""

    def whole(value: Any) -> int | None:
        # Integers only (obs_ctl.py writes no others), in a sane range: never a float that overflows.
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10**10 else None

    epoch = whole(report.get("epoch"))
    if epoch is None:
        return {"age_seconds": NEVER, "state": "no report"}

    def plain(value: Any) -> Any:
        # What strict JSON carries: no nesting, no Infinity or NaN (obs_ctl.py wrote checked values).
        if value is None or isinstance(value, str | bool):
            return value[:200] if isinstance(value, str) else value
        if isinstance(value, int) and -(10**16) < value < 10**16:
            return value
        if isinstance(value, float) and math.isfinite(value):
            return value
        return None

    section: dict[str, Any] = {key: plain(report.get(key)) for key in TM_INFO}
    stalled = whole(report.get("stalled_seconds"))
    section["stalled_seconds"] = NEVER if stalled is None else stalled
    section["tmutil_ok"] = report.get("tmutil") == "ok"
    section["cross_check_ok"] = report.get("cross_check_ok") is True
    band = whole(report.get("band_newest_epoch"))
    section["band_age_seconds"] = None if band is None else int(now - band)
    section["age_seconds"] = int(now - epoch)
    if not section["tmutil_ok"]:
        tmutil = report.get("tmutil")
        section["state"] = f"tmutil {tmutil}" if tmutil in ("timeout", "hung", "error") else "tmutil unknown"
    elif report.get("running"):
        section["state"] = f"running {section['phase'] or '?'}"
    elif report.get("auto_backup") is False:
        section["state"] = "disabled"
    else:
        section["state"] = "idle"
    return section


class Status:
    """Local freshness at request time; the Loki part from a background refresher, never waited for."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.loki = pack.loki_client(config["loki_url"], timeout=LOKI_TIMEOUT)
        self.lock = threading.Lock()
        self.cached: tuple[float, dict[str, Any]] | None = None

    def refresh(self, now: float) -> None:
        try:
            result = {"error": None, **unit_loops(self.config, now, self.loki)}
        except Exception as error:  # noqa: BLE001 - reported to Nyxmon as a failed probe
            result = {"error": f"{type(error).__name__}: {pack.mask(str(error), 160)}", "count": 0, "loops": []}
        with self.lock:
            self.cached = (now, result)

    def refresh_forever(self) -> None:
        while True:
            self.refresh(time.time())
            time.sleep(float(self.config["cache_seconds"]))

    def loops(self, now: float) -> dict[str, Any]:
        with self.lock:
            cached = self.cached
        if cached is None:
            return {"ok": False, "error": "not checked yet", "count": 0, "loops": [], "age_seconds": NEVER}
        at, result = cached
        age = int(now - at)
        # Three missed refreshes (or a failed query) and the answer is no longer trusted.
        fresh = age <= 3 * max(float(self.config["cache_seconds"]), LOKI_TIMEOUT) + LOKI_TIMEOUT
        gaps = ("missing_hosts", "no_pid1_hosts", "truncated_hosts", "failed_hosts")
        covered = bool(result.get("hosts")) and not any(result.get(gap) for gap in gaps)
        ok = result["error"] is None and fresh and covered
        return {**result, "ok": ok, "age_seconds": age}

    def document(self, now: float) -> dict[str, Any]:
        state = self.config["state_dir"]
        status = _read(os.path.join(state, "status.json"))
        triage = _read(os.path.join(state, "triage.json"))
        pack_epoch = status.get("pack_epoch")
        triage_epoch = triage.get("ok_epoch")
        delivery_epoch = triage.get("epoch")
        launchd = _read(os.path.join(state, "launchd.json"))
        launchd_epoch = launchd.get("epoch")
        # Each loop counts only within its hold after its last sighting, also when reports pause.
        held = [
            loop
            for loop in launchd.get("loops") or []
            if isinstance(loop, dict) and isinstance(loop.get("last_seen"), int) and now - loop["last_seen"] < LOOP_HOLD
        ]
        return {
            "generated_at": pack.iso(now),
            "pack": {
                "date": status.get("pack_date"),
                "errors": status.get("pack_errors"),
                "age_seconds": int(now - pack_epoch) if isinstance(pack_epoch, int | float) else NEVER,
            },
            "triage": {
                "date": triage.get("date"),
                "status": triage.get("status"),
                "delivered": triage.get("delivered"),
                # Age of the last triage that ran (status ok) and reached the owner.
                "age_seconds": int(now - triage_epoch) if isinstance(triage_epoch, int | float) else NEVER,
                "delivery_age_seconds": int(now - delivery_epoch) if isinstance(delivery_epoch, int | float) else NEVER,
            },
            "unit_loops": self.loops(now),
            "launchd": {
                "host": launchd.get("host"),
                "checked": launchd.get("checked"),
                "errors": launchd.get("errors"),
                "count": len(held),
                "loops": held[:20],
                "age_seconds": int(now - launchd_epoch) if isinstance(launchd_epoch, int | float) else NEVER,
            },
            "timemachine": timemachine_section(_read(os.path.join(state, "timemachine.json")), now),
        }


class Handler(BoundedRequestMixin, BaseHTTPRequestHandler):
    status: Status

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path.split("?")[0] != PATH:
            self.send_error(404)
            return
        body = json.dumps(self.status.document(time.time()), sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - http.server API
        return


def handler(status: Status) -> type[Handler]:
    return type("StatusHandler", (Handler,), {"status": status})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Status endpoint of the observability routine")
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    with open(args.config, encoding="utf-8") as handle:
        config = json.load(handle)
    host, _, port = str(config["status_listen"]).rpartition(":")
    status = Status(config)
    threading.Thread(target=status.refresh_forever, name="unit-loops", daemon=True).start()
    server = BoundedThreadingTCPServer((host, int(port)), handler(status))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
