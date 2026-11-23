#!/usr/bin/env python3
"""Daily observability evidence pack (ops-deploy ``services.obs_daily``), Python stdlib only.

``obs_pack.py --config FILE [--now EPOCH]`` gathers a deterministic
evidence pack from Loki and InfluxDB for an LLM triage that reviews the last
24 hours open-endedly, looking for problems nobody knows about yet. The pack
is a map, not a filter: it holds no list of known problems, carries raw log
lines (owner decision 2026-11-19), and the triage drills down in Loki and
InfluxDB itself (``obs_ctl.py query``). Every section compares the last 24
hours with the host's or series' own past:

- ``logs.volume``: lines per host and service against the median of the
  seven days before; services that appeared or went silent; hosts without
  lines in the last hour.
- ``logs.samples``: what every service of every host said, at any level:
  a bounded sample of raw lines per service, grouped by template, with
  counts and one raw example per group.
- ``logs.signatures``: problem-like lines (error, failure, denied, timeout
  and the like) grouped by template (numbers, times, addresses, ids and
  quoted text masked, so variants of one message group together) with raw
  examples, compared with a stored baseline of earlier days: templates never
  seen before, and known templates that surged far above their daily average.
- ``logs.unit_restarts``: systemd restart and failure messages per unit.
- ``metrics``: gauge series whose last-24-hour mean or maximum deviates
  strongly from their own daily values of the two weeks before (robust
  z-score); series that went silent or appeared; filesystems that are nearly
  full or fill up within 30 days at the 14-day trend.
- ``tls``: certificates of the configured hosts that expire soon or fail.
- ``nyxmon``: Nyxmon checks currently not ok (what already alerts).

Loki's own container logs are dropped from every log scan (``loki_exclude_lines``):
they reach journald as stderr and come back into Loki as errors. Every section
runs on its own: a failing query is recorded in ``errors`` and the pack is still
written. Files in ``state_dir`` (written atomically): ``packs/<date>.json`` and
``packs/latest.json`` (kept ``pack_retention_days``), ``signatures.json`` (the
template baseline, ``signature_retention_days``) and ``status.json``. On the
first run, or after a gap, the baseline is first filled from up to
``backfill_days`` earlier days, so day one does not report every template as new.

Exit status: 0 pack written, 2 unusable configuration.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import http.client
import io
import json
import os
import re
import socket
import sqlite3
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SCHEMA = 1
HTTP_TIMEOUT = 60
MAX_LINES = 5000
# Lines per problem-line query (logs.signatures). Loki's query frontend splits a query into
# 1-hour pieces and each piece's answer travels inside Loki over gRPC, limited to 4 MiB:
# 2000 lines of about 1.2 KB (RustFS on fractal, 2026-11-19) stay well below it, 5000 did not.
PROBLEM_LINES = 2000
# Problem-line windows Loki may leave unanswered in one pack before the signature pass gives
# up: an isolated oversized piece costs a handful, an outage that drops every query would
# otherwise split every window of every day down to the last level.
MAX_DROPPED = 40
MASK_INPUT = 1000
MAX_BODY = 64 * 1024 * 1024
MAX_SPLIT = 5  # a 6-hour window halves down to about 11 minutes
# Streams a window still at the line limit after MAX_SPLIT may be read without, loudest first
# (RustFS replication errors on fractal and macmini, 2026-11-19/20, up to 28,000 lines in 5 minutes).
MAX_CROWDING = 3
EXAMPLES = 2  # raw example lines per template
EXAMPLE_CHARS = 400  # of each raw line shown
DAY = 86400
HOUR = 3600
NS = 1_000_000_000

PROBLEM_PATTERN = (
    r"(?i)\b(error|errors|fail|failed|failure|fatal|panic|exception|traceback|denied|refused|"
    r"timeout|timed out|segfault|oom|killed|corrupt|unable to|cannot|can't|invalid|critical|"
    r"abort|aborted|crash|crashed|warn|warning|unreachable|unhealthy|degraded)\b"
)
RESTART_PATTERN = "Scheduled restart job|Start request repeated too quickly|Failed with result"
# Lines of transient units, dropped in Loki before the line limit applies.
# Anchored at the start of the JSON ``message`` value: the unit that PID 1 names first.
TRANSIENT_LINES = r'"message":"(run-[a-z0-9]+|session-[0-9]+|user@[0-9]+|user-runtime-dir@[0-9]+)[.][a-z]+: '

TRANSIENT_UNITS = re.compile(r"^(run-[a-z0-9]+|session-[0-9]+|user@[0-9]+|user-runtime-dir@[0-9]+)\.")
SESSION_SERVICES = re.compile(r"^(session|run-u)-?[0-9]")
DARWIN_JUNK_MOUNTS = re.compile(
    r"^/(dev$|Volumes/com\.apple\.TimeMachine|private/(tmp|var)/|Library/Developer/|"
    r"Volumes/Recovery$|System/Volumes/(Update|xarts|iSCPreboot|Hardware|Preboot|VM)(/|$))"
)
# Tags that tell series of one host and metric apart, in this order; everything else is collector detail.
IDENTITY_TAGS = ("subject_id", "service", "mountpoint", "pool", "sensor_label", "interface", "port_name",
                 "entity_id", "traffic_direction", "mode", "cpu", "device")  # fmt: skip
# Short-lived network interfaces (containers, bridges, tunnels) come and go by design.
EPHEMERAL_DEVICES = re.compile(r"^(veth|br-|docker|utun|tun|tap|bridge|awdl|llw|anpi|ipsec|gif|stf|cali|flannel|virbr)")
SKIPPED_METRICS = re.compile(r"^host\.filesystem_inodes_(free|total|used)$")
# Keys of JSON or logfmt lines whose values vary per event; they become <v> in a template.
VARIABLE_KEYS = (
    r"[A-Za-z_]*(?:id|ID|Id|object|key|path|url|uri|URI|file|time|ts|timestamp|latency|duration|elapsed|size|bytes|"
    r"addr|address|ip|remote|peer|client|user|agent|userAgent|referer|referrer|trace|span|etag|version|pid|port|count|"
    r"attempt|took|ms|seconds)"
)
SECRET_WORDS = r"token|password|passwd|secret|key|auth|authorization|cookie|session|credential|bearer"
_SECRET_KEY = re.compile(rf"(?i)({SECRET_WORDS})")
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+")
_JSON_VARIABLE = re.compile(rf"^{VARIABLE_KEYS}$")
_KV_VARIABLE = re.compile(rf"\b({VARIABLE_KEYS})=(\"(?:[^\"\\]|\\.)*\"|\S+)")

_RFC3339 = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z")
_UNIT = re.compile(r"^([A-Za-z0-9@_.:\\-]+\.(?:service|socket|mount|timer|scope|target|path|swap|automount))[:]")
# Applied before anything else, so no later rule can split a secret value first.
_SECRETS = [
    (re.compile(r"(?is)\b((?:set-)?cookie)\s*[:=].*"), r"\1: <redacted>"),
    (re.compile(rf"(?i)(?<![\w.-])([\w.-]*?(?:{SECRET_WORDS})[\w.-]*)([\"']?\s*[=:]\s*)(\"(?:[^\"\\]|\\.)*\"?|'(?:[^'\\]|\\.)*'?)"),
     r"\1\2<redacted>"),
    (re.compile(r"(?i)\b(bearer|basic|digest|negotiate)\s+[^\s,;]+"), r"\1 <redacted>"),
    (re.compile(rf"(?i)(?<![\w.-])([\w.-]*?(?:{SECRET_WORDS})[\w.-]*)([\"']?\s*[=:]\s*)(?!<redacted>)[^\s,;]+"), r"\1\2<redacted>"),
]
_MASKS = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<time>"),
    (re.compile(r"\b\d{1,2}/[A-Z][a-z]{2}/\d{4}[: ]\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?"), "<time>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<time>"),
    (re.compile(r"(?<![\w.<])/[\w.%~+-]+(?:/[\w.%~+-]*)*"), "<path>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])"), "<ip>"),
    (re.compile(r"(?i)\b(user|for|from|by|login|account|uid|username)([ =:]+)(?!<)[^\s,;]+"), r"\1\2<id>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{12,}\b|\b[A-Za-z0-9+/_-]{32,}={0,2}"), "<hex>"),
    (re.compile(r"\b(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{20,}\b"), "<hex>"),
    (re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'"), "<q>"),
    (re.compile(r"\?[^\s\"]*"), "?<query>"),
    (re.compile(r"\d+"), "#"),
    (re.compile(r"\s+"), " "),
]  # fmt: skip


class ConfigError(Exception):
    pass


@dataclass
class Context:
    config: dict[str, Any]
    now: float
    loki: Callable[[str, dict[str, str]], Any]
    flux: Callable[[str], list[dict[str, str]]]
    state_dir: str
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped_windows: int = 0
    dropped_windows: int = 0
    # (host, raw service label) -> windows whose lines of that stream were only sampled (see problem_lines)
    crowded: Counter[tuple[str, str]] = field(default_factory=Counter)
    # host -> day -> whether the host shipped any log line that day (from logs.volume)
    activity: dict[str, dict[str, bool]] = field(default_factory=dict)

    def cap(self, name: str) -> int:
        return int(self.config["caps"][name])


# -- the two APIs ---------------------------------------------------------------------------


class TooLarge(RuntimeError):
    """An answer above ``MAX_BODY`` bytes: the caller narrows its window."""


class Dropped(TooLarge):
    """Loki closed the connection without an answer, as it does when a query piece's
    answer exceeds its internal gRPC message limit: the caller narrows its window."""


def _http(request: urllib.request.Request, timeout: float = HTTP_TIMEOUT, max_body: int = MAX_BODY) -> bytes:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body: bytes = response.read(max_body + 1)
            if len(body) > max_body:
                raise TooLarge(f"answer larger than {max_body} bytes")
            return body
    except urllib.error.HTTPError as error:
        detail = error.read(300).decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError(f"HTTP {error.code}: {detail[0][:160] if detail else ''}") from None
    except (urllib.error.URLError, OSError) as error:
        reason = getattr(error, "reason", error)
        if isinstance(reason, http.client.RemoteDisconnected):
            raise Dropped(f"unreachable: {str(reason)[:160]}") from None
        raise RuntimeError(f"unreachable: {str(reason)[:160]}") from None


def loki_client(
    base: str, timeout: float = HTTP_TIMEOUT, max_body: int = MAX_BODY
) -> Callable[[str, dict[str, str]], Any]:
    def call(path: str, params: dict[str, str]) -> Any:
        url = f"{base.rstrip('/')}/loki/api/v1/{path}?{urllib.parse.urlencode(params)}"
        answer = json.loads(_http(urllib.request.Request(url), timeout, max_body))
        if answer.get("status") != "success":
            raise RuntimeError(f"Loki answered {str(answer.get('status'))[:40]}")
        return answer["data"]

    return call


def parse_flux_csv(text: str) -> list[dict[str, str]]:
    """Rows of an InfluxDB CSV answer: annotation rows skipped, a blank line ends a table, and the next
    row is its header. Quoting is handled first, so a quoted value may hold blank lines."""

    rows: list[dict[str, str]] = []
    header: list[str] | None = None
    for record in csv.reader(io.StringIO(text)):
        if not record or all(not cell.strip() for cell in record):
            header = None
        elif record[0].startswith("#"):
            continue
        elif header is None:
            header = record
            if "error" in header and "reference" in header:
                raise RuntimeError("InfluxDB reported a query error")
        else:
            rows.append(dict(zip(header, record, strict=False)))
    return rows


def flux_client(
    base: str, org: str, token_file: str, timeout: float = HTTP_TIMEOUT, max_body: int = MAX_BODY
) -> Callable[[str], list[dict[str, str]]]:
    def call(query: str) -> list[dict[str, str]]:
        try:
            with open(token_file, encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as error:
            raise RuntimeError(f"InfluxDB token unreadable: {error.strerror}") from None
        token = (token.split() + [""])[0]  # the second line holds the authorization ID
        url = f"{base.rstrip('/')}/api/v2/query?{urllib.parse.urlencode({'org': org})}"
        headers = {
            "Authorization": f"Token {token}",
            "Content-Type": "application/vnd.flux",
            "Accept": "application/csv",
        }
        request = urllib.request.Request(url, data=query.encode(), headers=headers, method="POST")
        body = _http(request, timeout, max_body)
        return parse_flux_csv(body.decode("utf-8", "replace"))

    return call


def clean(text: str) -> str:
    """``text`` with lone surrogates (from escaped JSON) as visible ``\\udXXX`` escapes: always encodable."""

    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def lit(value: str) -> str:
    """A LogQL/Flux string literal (JSON escaping is valid in both)."""

    return json.dumps(value)


def excluded(ctx: Context) -> str:
    """Line filters that drop Loki's own logs (they come back through journald as errors)."""

    return "".join(f" != {lit(text)}" for text in ctx.config["loki_exclude_lines"])


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        parts = []
        for k, v in value.items():
            if _SECRET_KEY.search(str(k)):
                parts.append(f"{k}=<redacted>")
            elif _JSON_VARIABLE.match(str(k)):
                parts.append(f"{k}=<v>")
            else:
                parts.append(f"{k}={_flatten(v)}")
        return "{" + " ".join(parts) + "}"
    if isinstance(value, list):
        return "[...]"
    return str(value)


def restart_selector(host: str, exclude: str) -> str:
    """PID 1's restart and failure lines of ``host``: filtered in Loki (parsed ``pid`` 1, unit ``init.scope``)
    before the line limit applies, so other lines cannot crowd them out."""

    return (
        f'{{host={lit(host)}, service="init"}}{exclude} |~ {lit(RESTART_PATTERN)} !~ {lit(TRANSIENT_LINES)}'
        ' | json pid="pid", unit="unit" | __error__ = "" | pid="1" | unit="init.scope"'
    )


def mask(message: str, limit: int = 180) -> str:
    """A log message as a template: variable parts masked, so no raw value leaves the host.

    A JSON object is flattened to ``key=value`` first; values of keys that vary
    per event (ids, paths, times, sizes, addresses, users) become ``<v>``, as do
    the same keys in logfmt lines. Then times, ids, addresses, e-mail addresses,
    secrets after ``token=``/``password=`` and the like, long hex or base64 runs,
    quoted text and numbers are masked.
    """

    # Bounded work per line: masks scan at most MASK_INPUT characters (the template keeps 180).
    # Lone surrogates (from escaped JSON) become "?" so hashing and export cannot fail on them.
    text = message.encode("utf-8", "replace").decode("utf-8").strip()
    if text.startswith("{") and len(text) <= 20 * MASK_INPUT:
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            text = _flatten(parsed)[1:-1].encode("utf-8", "replace").decode("utf-8")
    text = text[:MASK_INPUT]
    for pattern, replacement in _SECRETS:
        text = pattern.sub(replacement, text)
    text = _URL.sub("<url>", text)
    text = _KV_VARIABLE.sub(r"\1=<v>", text)
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text.strip()[:limit]


def _load_json(path: str, default: Any) -> Any:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as error:
        raise RuntimeError(f"{os.path.basename(path)} unreadable: {type(error).__name__}") from None


def _write_json(path: str, data: Any, *, indent: int | None = 1) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=indent, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    os.replace(tmp, path)


def day_of(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).astimezone().strftime("%Y-%m-%d")


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(text: str) -> float:
    found = _RFC3339.fullmatch(text.strip())
    if found is None:
        raise RuntimeError(f"unexpected time {text[:40]!r}")
    whole = datetime.strptime(found.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    return whole + float(f"0.{found.group(2) or 0}")


# -- logs -------------------------------------------------------------------------------------


def log_hosts(ctx: Context) -> list[str]:
    """Hosts Loki knows for the last eight days, plus the configured ``log_hosts`` (a silent one stays visible).

    No host at all is a broken log source: the log sections are skipped and recorded as an error,
    and no day enters the signature baseline.
    """

    start = ctx.now - 8 * DAY
    data = ctx.loki("label/host/values", {"start": str(int(start * NS)), "end": str(int(ctx.now * NS))})
    found = {str(host) for host in data or []}
    if not found:
        raise NoLogFeed(sorted(ctx.config.get("log_hosts") or []))
    return sorted(found | set(ctx.config.get("log_hosts") or []))


class NoLogFeed(Exception):
    """Loki knows no host at all: the configured hosts are reported silent, nothing enters the baseline."""

    def __init__(self, configured: list[str]) -> None:
        super().__init__("Loki returned no log host for the last eight days")
        self.configured = configured


def _service(name: str) -> str:
    return "session-*" if SESSION_SERVICES.match(name) else name


# Vector writes ``"unit":"<name>"`` from journald's trusted ``_SYSTEMD_UNIT``; without it the
# ``service`` label comes from the caller-supplied ``SYSLOG_IDENTIFIER``. Only lines whose parsed
# JSON carries a non-empty ``unit`` count as trusted (Loki's json parser, not a text match).
UNTRUSTED = "ident:"


def volume_by_service(ctx: Context, host: str, end: float) -> dict[str, float]:
    """Lines per service; services named by the caller (no systemd unit) are keyed ``ident:<name>``."""

    # Login sessions and transient units are left out: thousands of streams would break the series limit.
    selector = f'{{host={lit(host)}, service!~"(session|run-u)-?[0-9].*"}}'
    counts: dict[str, float] = defaultdict(float)
    # Trusted lines are grouped by their full parsed unit (Vector strips suffixes such as
    # ``.mount`` from the service label, and the suffix decides how a name may leave).
    trusted = ' | json unit="unit" | __error__ = "" | unit != ""'
    # Plain-text lines fail the json parser: they count as caller-named, and the error labels go.
    caller_named = ' | json unit="unit" | __error__ != "" or unit = "" | drop __error__, __error_details__'
    for line_filter, prefix, label in ((trusted, "", "unit"), (caller_named, UNTRUSTED, "service")):
        query = f"sum by ({label}) (count_over_time({selector}{excluded(ctx)}{line_filter} [24h]))"
        data = ctx.loki("query", {"query": query, "time": str(int(end * NS))})
        for item in data.get("result", []):
            counts[prefix + _service(item["metric"].get(label, "?"))] += float(item["value"][1])
    return dict(counts)


def host_lines(ctx: Context, host: str, end: float) -> float:
    data = ctx.loki(
        "query", {"query": f"sum(count_over_time({{host={lit(host)}}}{excluded(ctx)} [24h]))", "time": str(int(end * NS))}
    )
    return sum(float(item["value"][1]) for item in data.get("result", []))


def section_volume(ctx: Context, hosts: list[str]) -> dict[str, Any]:
    """Lines per host and service in 24 h against the median of the seven days before."""

    changes: list[dict[str, Any]] = []
    appeared: list[dict[str, Any]] = []
    vanished: list[dict[str, Any]] = []
    totals: list[dict[str, Any]] = []
    for host in hosts:
        today = volume_by_service(ctx, host, ctx.now)
        history = [volume_by_service(ctx, host, ctx.now - day * DAY) for day in range(1, 8)]
        # Activity from every line of the host (sessions and transient units included).
        ctx.activity[host] = {day_of(ctx.now - back * DAY): host_lines(ctx, host, ctx.now - back * DAY) > 0 for back in range(8)}
        total_median = statistics.median(sum(day.values()) for day in history)
        totals.append({"host": host, "lines_24h": int(sum(today.values())), "median_7d": int(total_median)})
        for service in sorted(set(today) | {s for day in history for s in day}):
            count = today.get(service, 0.0)
            past = [day.get(service, 0.0) for day in history]
            median = statistics.median(past)
            days_with = sum(value > 0 for value in past)
            label = service
            if days_with == 0 and count >= 20:
                appeared.append({"host": host, "service": label, "lines_24h": int(count)})
            elif count == 0 and days_with >= 5 and median >= 50:
                vanished.append({"host": host, "service": label, "median_7d": int(median)})
            elif max(count, median) >= 500 and median > 0 and (count / median >= 3 or count / median <= 1 / 5):
                changes.append(
                    {"host": host, "service": label, "lines_24h": int(count), "median_7d": int(median),
                     "factor": round(count / median, 1)}  # fmt: skip
                )
    changes.sort(key=lambda c: (-abs(c["lines_24h"] - c["median_7d"]), c["host"], c["service"]))
    silent = []
    for host in hosts:
        data = ctx.loki(
            "query",
            {"query": f"sum(count_over_time({{host={lit(host)}}}{excluded(ctx)} [1h]))", "time": str(int(ctx.now * NS))},
        )
        if not data.get("result") and host not in ctx.config["sleeping_hosts"]:
            silent.append(host)
    return {
        "hosts": totals,
        "changed": changes[: ctx.cap("volume")],
        "appeared": appeared[: ctx.cap("volume")],
        "vanished": vanished[: ctx.cap("volume")],
        "silent_last_hour": silent,
    }


def _problem_answer(
    ctx: Context, host: str, start: float, end: float, without: list[str]
) -> list[tuple[str, str, str]]:
    """(``service`` label, source, message) of one problem-line query; streams whose ``service``
    label is in ``without`` are left out in Loki. Raises ``TooLarge`` like the client."""

    # Raw UTF-8: Loki reads a \u surrogate pair in a selector as two replacement characters.
    # ``service!=""`` leaves out the streams without a service label.
    matchers = "".join(f", service!={json.dumps(service, ensure_ascii=False)}" for service in without)
    query = f"{{host={lit(host)}{matchers}}}{excluded(ctx)} |~ {lit(PROBLEM_PATTERN)}"
    params = {
        "query": query,
        "start": str(int(start * NS)),
        "end": str(int(end * NS)),
        "limit": str(PROBLEM_LINES),
        "direction": "backward",
    }
    try:
        data = ctx.loki("query_range", params)
    except Dropped as error:
        ctx.dropped_windows += 1
        if ctx.dropped_windows > MAX_DROPPED:
            raise RuntimeError(f"{error} ({MAX_DROPPED} windows not answered; giving up)") from None
        raise
    found: list[tuple[str, str, str]] = []
    for stream in data.get("result", []):
        labels = dict(stream.get("stream", {}))
        for _ts, raw in stream.get("values", []):
            # The source is the stream's ``service`` label: Vector derives it from journald's
            # trusted ``_SYSTEMD_UNIT``, unlike the caller-supplied ``SYSLOG_IDENTIFIER``.
            source = _service(labels.get("service") or "?")
            message = raw
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                message = str(parsed.get("message", raw))
                unit = parsed.get("unit")
                source = _service(unit) if isinstance(unit, str) and unit else UNTRUSTED + source
            else:
                source = UNTRUSTED + source
            # Only the start of a message is ever masked or shown; keep no more of it in memory.
            # Lone surrogates (from escaped JSON) become visible escapes, so the pack always encodes.
            found.append((str(labels.get("service") or ""), clean(source), clean(message[: 4 * MASK_INPUT])))
    return found


def problem_lines(ctx: Context, host: str, start: float, end: float, depth: int = 0) -> list[tuple[str, str]]:
    """(source, message) of problem-like lines; a window that hits the line limit is split.

    A window still at the limit when it cannot be split further is read again without its
    loudest ``service`` stream (up to ``MAX_CROWDING`` streams): that stream's lines from the
    answer stay as a sample (its counts are lower bounds), and the rest of the window is read
    again. Only a window still at the limit after that leaves the day incomplete.
    """

    def split() -> list[tuple[str, str]]:
        middle = start + (end - start) / 2
        return problem_lines(ctx, host, start, middle, depth + 1) + problem_lines(ctx, host, middle, end, depth + 1)

    def skip(error: TooLarge) -> list[tuple[str, str]]:
        what = "connection closed without an answer" if isinstance(error, Dropped) else "answer too large"
        ctx.notes.append(f"{host}: {what} in {iso(start)}..{iso(end)}; skipped")
        ctx.skipped_windows += 1
        return []

    can_split = depth < MAX_SPLIT and end - start > 5 * 60
    try:
        answer = _problem_answer(ctx, host, start, end, [])
    except TooLarge as error:
        return split() if can_split else skip(error)
    if len(answer) < PROBLEM_LINES:
        return [(source, message) for _service_label, source, message in answer]
    if can_split:
        return split()
    sampled: list[tuple[str, str]] = []
    without: list[str] = []
    while True:
        # A label already left out can come back (as structured metadata on another stream):
        # its lines are never counted twice, the sample of that label stays a lower bound.
        kept = [line for line in answer if line[0] not in without]
        if len(answer) < PROBLEM_LINES:
            break
        if len(without) >= MAX_CROWDING or not kept:
            # A sampled window cannot count as a complete day: it stays out of the baseline.
            ctx.notes.append(f"{host}: {PROBLEM_LINES}-line limit reached in {iso(start)}..{iso(end)}; sampled")
            ctx.skipped_windows += 1
            break
        loudest, _lines = Counter(label for label, _s, _m in kept).most_common(1)[0]
        sampled += [(source, message) for label, source, message in kept if label == loudest]
        without.append(loudest)
        try:
            answer = _problem_answer(ctx, host, start, end, without)
        except TooLarge as error:
            return skip(error)
    for service in without:  # only for windows that return their samples
        ctx.crowded[(host, service)] += 1
    return sampled + [(source, message) for _service_label, source, message in kept]


def signature_key(host: str, source: str, template: str) -> str:
    return hashlib.sha1(f"{host}\x00{source}\x00{template}".encode("utf-8", "replace")).hexdigest()[:16]


def day_signatures(ctx: Context, hosts: list[str], end: float) -> tuple[dict[str, dict[str, Any]], bool]:
    """Templates of the 24 hours before ``end``, per host: key -> host, source, template, count; and
    whether every window was read (a window skipped as too large or unanswered leaves the day incomplete).

    Each host is compared with its own past: a failure that is routine on one
    host is still new when it first appears on another.
    """

    found: dict[str, dict[str, Any]] = {}
    skipped_before = ctx.skipped_windows
    ctx.crowded.clear()
    for host in hosts:
        for chunk in range(4):
            start = end - DAY + chunk * 6 * HOUR
            for source, message in problem_lines(ctx, host, start, start + 6 * HOUR):
                template = mask(message)
                key = signature_key(host, source, template)
                entry = found.setdefault(
                    key, {"host": host, "source": source, "template": template, "count": 0, "examples": []}
                )
                entry["count"] += 1
                if len(entry["examples"]) < EXAMPLES:
                    entry["examples"].append(message[:EXAMPLE_CHARS])
    for (host, service), windows in sorted(ctx.crowded.items()):
        stream = f"service={json.dumps(service, ensure_ascii=False)}" if service else "streams without a service label"
        ctx.notes.append(
            f"{host}: {stream} filled {windows} windows to the {PROBLEM_LINES}-line limit in the day before "
            f"{iso(end)}; its lines there are sampled (lower-bound counts) and the window read again without it"
        )
    return found, ctx.skipped_windows == skipped_before


def grouped(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-host findings of the same template as one entry with the hosts and the total count."""

    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in entries:
        # Hosts are merged only when their reported history agrees too.
        history = (entry.get("daily_average_before"), entry.get("days_seen_before"), entry.get("first_seen"))
        kind = (entry["source"], entry["template"], json.dumps(history))
        group = groups.setdefault(
            kind, {k: v for k, v in entry.items() if k not in ("host", "count", "key", "examples")}
        )
        group.setdefault("hosts", [])
        examples = group.setdefault("examples", [])
        for example in entry.get("examples", []):
            if len(examples) < EXAMPLES and example not in examples:
                examples.append(example)
        if entry["host"] not in group["hosts"]:
            group["hosts"].append(entry["host"])
        group["count"] = group.get("count", 0) + entry["count"]
    return sorted(groups.values(), key=lambda g: (-g["count"], g["source"], g["template"], g["hosts"]))


SIGNATURE_SCHEMA = 2


def _record(store: dict[str, Any], day: str, found: dict[str, dict[str, Any]]) -> None:
    """Keep ``day``'s count per template; recording a day again replaces it."""

    signatures = store.setdefault("signatures", {})
    for entry in signatures.values():
        entry["days"].pop(day, None)
    for key, entry in found.items():
        signatures.setdefault(key, {"days": {}})["days"][day] = entry["count"]
    store["covered_days"] = sorted(set(store.get("covered_days", [])) | {day})


def _save_signatures(path: str, store: dict[str, Any], oldest: str) -> None:
    """Write the baseline without the days before ``oldest`` (the retention window)."""

    for entry in store.get("signatures", {}).values():
        entry["days"] = {day: count for day, count in entry["days"].items() if day >= oldest}
    store["signatures"] = {k: v for k, v in store.get("signatures", {}).items() if v["days"]}
    store["covered_days"] = [d for d in store.get("covered_days", []) if d >= oldest]
    store.pop("host_inactive", None)
    store["host_active"] = {h: [d for d in days if d >= oldest] for h, days in store.get("host_active", {}).items()}
    _write_json(path, store, indent=None)


def section_signatures(ctx: Context, hosts: list[str]) -> dict[str, Any]:
    """Today's templates against the stored days strictly before today.

    ``signatures.json`` keeps one count per template and day for
    ``signature_retention_days``; a rerun on the same day replaces that day's
    counts, so it reports the same as the first run.
    """

    path = os.path.join(ctx.state_dir, "signatures.json")
    store = _load_json(path, None)
    if not store or store.get("schema") != SIGNATURE_SCHEMA:
        store = {"schema": SIGNATURE_SCHEMA, "signatures": {}, "covered_days": []}
    today = day_of(ctx.now)
    covered = set(store.get("covered_days", []))
    # Days a host shipped no log line at all (from logs.volume) do not count in its baseline.
    active = store.setdefault("host_active", {})
    for host, days in ctx.activity.items():
        confirmed = set(active.get(host, [])) | {day for day, shipped in days.items() if shipped}
        active[host] = sorted(confirmed - {day for day, shipped in days.items() if not shipped})
    oldest = day_of(ctx.now - int(ctx.config["signature_retention_days"]) * DAY)
    backfilled = []
    try:
        for back in range(int(ctx.config["backfill_days"]), 0, -1):
            day = day_of(ctx.now - back * DAY)
            if day not in covered:
                earlier, complete = day_signatures(ctx, hosts, ctx.now - back * DAY)
                if complete:
                    _record(store, day, earlier)
                    backfilled.append(day)
                else:
                    # An incomplete day never enters the baseline; the next run tries it again.
                    ctx.errors.append(f"logs.signatures: {day} incomplete (a window was too large, not answered or still at the line limit; see the notes); not in the baseline")
        if backfilled:
            ctx.notes.append(f"signature baseline filled from {len(backfilled)} earlier days ({backfilled[0]}..)")
        found, complete_today = day_signatures(ctx, hosts, ctx.now)
    except RuntimeError:
        # A pass that gives up (Loki stopped answering) keeps the days it read completely and
        # the host activity it learned, so the next run continues the backfill instead of
        # starting it again.
        _save_signatures(path, store, oldest)
        raise
    if not complete_today:
        ctx.errors.append("logs.signatures: today incomplete (a window was too large, not answered or still at the line limit; see the notes); not added to the baseline")
    known = store.get("signatures", {})
    baseline_days = len([d for d in store.get("covered_days", []) if oldest <= d < today])
    new, surging = [], []
    for key, entry in found.items():
        before = {day: count for day, count in known.get(key, {}).get("days", {}).items() if oldest <= day < today}
        if not before:
            if entry["count"] >= int(ctx.config["new_signature_min"]):
                new.append({**entry, "key": key})
            continue
        # Covered days without the template count as zero, but only days the host shipped logs:
        # days before a host shipped anything (known from logs.volume) must not lower its average.
        # Only covered days on which the host is known to have shipped logs: a host added to an
        # established baseline is not measured against days before it existed.
        shipped = set(store.get("host_active", {}).get(entry["host"], []))
        host_days = {d for d in store.get("covered_days", []) if oldest <= d < today and d in shipped}
        average = sum(before.values()) / len(host_days | set(before))
        if entry["count"] >= 50 and entry["count"] >= 10 * average:
            surging.append({**entry, "key": key, "daily_average_before": round(average, 1),
                            "days_seen_before": len(before), "first_seen": min(before)})  # fmt: skip
    if complete_today:
        _record(store, today, found)
    _save_signatures(path, store, oldest)
    new, surging = grouped(new), grouped(surging)
    return {
        "baseline_days": baseline_days,
        "templates_24h": len(found),
        "problem_lines_24h": sum(e["count"] for e in found.values()),
        "new": new[: ctx.cap("signatures")],
        "new_total": len(new),
        "surging_total": len(surging),
        "surging": surging[: ctx.cap("signatures")],
    }


def systemd_event(raw: str) -> tuple[str, str] | None:
    """(unit, kind) of a restart or failure line that systemd itself logged, else None.

    Only lines from PID 1 count: journald's trusted ``_PID`` (``pid``) is 1 and
    its ``_SYSTEMD_UNIT`` (``unit``) is ``init.scope``, so an application that
    quotes systemd's wording, or sets its own ``SYSLOG_IDENTIFIER``, cannot
    fake a loop. User managers (``systemd --user``) are not covered.
    """

    try:
        fields = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(fields, dict) or str(fields.get("pid")) != "1" or fields.get("unit") != "init.scope":
        return None
    message = str(fields.get("message", ""))
    unit = _UNIT.match(message)
    if unit is None or TRANSIENT_UNITS.match(unit.group(1)):
        return None
    name = unit.group(1)
    if "Scheduled restart job" in message:
        return name, "restart"
    if "Start request repeated too quickly" in message:
        return name, "gave_up"
    if "Failed with result" in message:
        return name, "failed"
    return None


def section_unit_restarts(ctx: Context, hosts: list[str]) -> list[dict[str, Any]]:
    """PID 1's restarts and failures per host and unit over 24 hours, in 6-hour windows."""

    counts: Counter[tuple[str, str, str]] = Counter()
    for host in hosts:
        for chunk in range(4):
            start = ctx.now - DAY + chunk * 6 * HOUR
            params = {
                "query": restart_selector(host, excluded(ctx)),
                "start": str(int(start * NS)),
                "end": str(int((start + 6 * HOUR) * NS)),
                "limit": str(MAX_LINES),
            }
            lines = 0
            for stream in ctx.loki("query_range", params).get("result", []):
                for _ts, raw in stream.get("values", []):
                    lines += 1
                    event = systemd_event(raw)
                    if event is not None:
                        counts[(host, event[0], event[1])] += 1
            if lines >= MAX_LINES:
                ctx.notes.append(
                    f"{host}: unit restarts limited to {MAX_LINES} lines in {iso(start)}..+6h"
                )
    units: dict[tuple[str, str], dict[str, Any]] = {}
    for (host, unit, kind), count in counts.items():
        units.setdefault((host, unit), {"host": host, "unit": unit})[kind] = count
    ranked = sorted(
        units.values(), key=lambda u: (-sum(v for k, v in u.items() if k not in ("host", "unit")), u["host"], u["unit"])
    )
    return ranked[: ctx.cap("units")]


def service_counts(ctx: Context, host: str) -> dict[str, float]:
    """Lines per ``service`` stream label of ``host`` in the last 24 hours (login sessions and
    transient units left out)."""

    selector = f'{{host={lit(host)}, service!~"(session|run-u)-?[0-9].*"}}'
    query = f"sum by (service) (count_over_time({selector}{excluded(ctx)} [24h]))"
    data = ctx.loki("query", {"query": query, "time": str(int(ctx.now * NS))})
    return {str(item["metric"].get("service", "?")): float(item["value"][1]) for item in data.get("result", [])}


def sample_lines(ctx: Context, host: str, service: str, start: float, end: float) -> list[tuple[float, str, str]]:
    """(time, level, message) of the newest ``sample_lines_per_window`` lines of one service in a window."""

    params = {
        "query": f"{{host={lit(host)}, service={lit(service)}}}{excluded(ctx)}",
        "start": str(int(start * NS)),
        "end": str(int(end * NS)),
        "limit": str(int(ctx.config["sample_lines_per_window"])),
        "direction": "backward",
    }
    lines: list[tuple[float, str, str]] = []
    for stream in ctx.loki("query_range", params).get("result", []):
        labels = dict(stream.get("stream", {}))
        for ts, raw in stream.get("values", []):
            level, message = str(labels.get("level") or labels.get("detected_level") or ""), raw
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                message = str(parsed.get("message", raw))
                level = str(parsed.get("level") or level)
            lines.append((int(ts) / NS, clean(level), clean(message[: 4 * MASK_INPUT])))
    return lines


# Detail steps the samples go through until they fit ``sample_budget_bytes``:
# (most frequent templates, rare templates, characters per example).
SAMPLE_DETAIL = ((6, 3, 400), (4, 2, 300), (3, 2, 240), (2, 1, 200), (1, 1, 160), (1, 0, 120))


def section_samples(ctx: Context, hosts: list[str]) -> dict[str, Any]:
    """What every service of every host said in the last 24 hours, raw: the starting point for reading.

    Not filtered by level or wording: per service up to ``sample_lines_per_window``
    lines from each 6-hour window (all lines of a quiet service), grouped by
    template, and per group its count in the sample and one raw example (time,
    level, message). The most frequent groups and some that occurred only once
    are kept; the detail shrinks until the section fits ``sample_budget_bytes``.
    """

    jobs = []
    totals: dict[tuple[str, str], float] = {}
    for host in hosts:
        for service, count in service_counts(ctx, host).items():
            totals[(host, service)] = count
            jobs.extend((host, service, ctx.now - DAY + chunk * 6 * HOUR) for chunk in range(4))

    def fetch(job: tuple[str, str, float]) -> tuple[str, str, list[tuple[float, str, str]] | str]:
        host, service, start = job
        try:
            return host, service, sample_lines(ctx, host, service, start, start + 6 * HOUR)
        except Exception as error:  # noqa: BLE001 - one service must not cost the others their samples
            return host, service, f"{type(error).__name__}: {str(error)[:120]}"

    groups: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    sampled: Counter[tuple[str, str]] = Counter()
    failed: set[tuple[str, str]] = set()
    with ThreadPoolExecutor(max_workers=4) as pool:
        for host, service, lines in pool.map(fetch, jobs):
            if isinstance(lines, str):
                if (host, service) not in failed:
                    ctx.errors.append(f"logs.samples: {host} {service}: {lines}")
                failed.add((host, service))
                continue
            sampled[(host, service)] += len(lines)
            for ts, level, message in lines:
                group = groups[(host, service)].setdefault(
                    mask(message), {"n": 0, "first": ts, "example": (ts, level, message)}
                )
                group["n"] += 1
                group["first"] = min(group["first"], ts)

    def render(top: int, rare: int, chars: int) -> list[dict[str, Any]]:
        out = []
        for (host, service), count in sorted(totals.items(), key=lambda kv: (kv[0][0], -kv[1], kv[0][1])):
            ranked = sorted(groups[(host, service)].values(), key=lambda g: (-g["n"], g["first"]))
            chosen = ranked[:top] + [g for g in ranked[top:] if g["n"] == 1][:rare]
            entry: dict[str, Any] = {
                "host": host,
                "service": service,
                "lines_24h": int(count),
                "sampled": sampled[(host, service)],
                "groups": len(ranked),
                "lines": [
                    f"{iso(g['example'][0])[11:19]} n={g['n']} {g['example'][1] or '-'} {g['example'][2][:chars]}"
                    for g in chosen
                ],
            }
            if (host, service) in failed:
                entry["error"] = "not (completely) read"
            out.append(entry)
        return out

    def section(services: list[dict[str, Any]], top: int, rare: int, chars: int) -> dict[str, Any]:
        return {
            "per_window_limit": int(ctx.config["sample_lines_per_window"]),
            "detail": {"top": top, "rare": rare, "chars": chars},
            "services": services,
        }

    def size(value: dict[str, Any]) -> int:
        # The section as the pack publishes it (_write_json: indent 1, sorted keys, nested in logs).
        return len(json.dumps({"logs": {"samples": value}}, indent=1, sort_keys=True, ensure_ascii=False).encode())

    budget = int(ctx.config["sample_budget_bytes"])
    for top, rare, chars in SAMPLE_DETAIL:
        result = section(render(top, rare, chars), top, rare, chars)
        if size(result) <= budget:
            break
    else:
        # Still too large: the lines of the last services (the quietest of the last hosts) go first,
        # then, if even the inventory does not fit, the entries themselves.
        services = result["services"]
        emptied = 0
        for entry in reversed(services):
            if size(result) <= budget:
                break
            if entry["lines"]:
                entry["lines"] = []
                emptied += 1
        dropped = 0
        while services and size(result) > budget:
            services.pop()
            dropped += 1
        ctx.notes.append(
            f"logs.samples: over {budget} bytes at the least detail; lines left out for {emptied} services, "
            f"{dropped} services left out"
        )
    return result



# -- metrics ----------------------------------------------------------------------------------


def _bucket(ctx: Context) -> str:
    return lit(ctx.config["influx"]["bucket"])


_ROW_META = {"_start", "_stop", "_time", "_value", "_field", "_measurement", "result", "table", ""}


def series_key(row: dict[str, str]) -> str:
    """The full identity of a series (every tag): calculations use this, displays ``series_name``."""

    return json.dumps(sorted((k, v) for k, v in row.items() if k not in _ROW_META))


def series_name(row: dict[str, str]) -> str:
    """``host metric {identity tags}``: the host (or the subject of a service metric) and what tells series apart."""

    host = row.get("host") or row.get("subject_id") or "?"
    tags = [
        f"{k}={row[k]}"
        for k in IDENTITY_TAGS
        if row.get(k) and row[k] != host and not (k == "service" and row[k].endswith("_host_metrics"))
    ]
    return f"{host} {row.get('metric', '?')}" + (f" {{{','.join(tags)}}}" if tags else "")


def _skip(row: dict[str, str]) -> bool:
    if SKIPPED_METRICS.match(row.get("metric", "")):
        return True
    if row.get("metric", "").startswith("host.network_") and EPHEMERAL_DEVICES.match(row.get("device", "")):
        return True
    return bool(row.get("mountpoint") and DARWIN_JUNK_MOUNTS.match(row["mountpoint"]))


def robust_deviation(value: float, past: list[float]) -> tuple[float, float]:
    """(robust z-score, relative change) of ``value`` against ``past``.

    The scale is at least 5 % of the median and 1 % of the largest magnitude
    seen, so flat series and tiny absolute moves do not produce huge scores.
    """

    median = statistics.median(past)
    mad = statistics.median(abs(x - median) for x in past)
    magnitude = max(abs(value), *(abs(x) for x in past))
    scale = max(1.4826 * mad, 0.05 * abs(median), 0.01 * magnitude, 1e-9)
    relative = (value - median) / abs(median) if median else (1.0 if abs(value) > 1e-9 else 0.0)
    return (value - median) / scale, relative


def slope_per_day(points: list[tuple[float, float]]) -> float:
    """Least-squares slope of (epoch, value) points, per day."""

    xs = [ts / DAY for ts, _value in points]
    ys = [value for _ts, value in points]
    mean_x, mean_y = statistics.fmean(xs), statistics.fmean(ys)
    denominator = sum((x - mean_x) ** 2 for x in xs)
    if denominator == 0:
        return 0.0
    return sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True)) / denominator


def _group_silent(stale: list[tuple[str, str, float]]) -> list[dict[str, Any]]:
    """Silent series grouped by what they describe (host and identity), with the metrics that fell silent."""

    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for name, metric, age in stale:
        host, _, rest = name.partition(" ")
        identity = rest.partition(" ")[2] or "{}"
        group = groups.setdefault((host, identity), {"host": host, "subject": identity, "metrics": [], "silent_hours": 0})
        group["metrics"].append(metric)
        group["silent_hours"] = max(group["silent_hours"], round(age / HOUR))
    for group in groups.values():
        metrics = sorted(group["metrics"])
        group["metrics"] = metrics[:6] + ([f"... {len(metrics) - 6} more"] if len(metrics) > 6 else [])
    return sorted(groups.values(), key=lambda g: (g["silent_hours"], g["host"], g["subject"]))


def section_metrics(ctx: Context) -> dict[str, Any]:
    def series(start_days: float, stop_days: float = 0.0, gauges_only: bool = False) -> str:
        """Every window is fixed to the pack's own clock (``ctx.now``), not InfluxDB's ``now()``."""

        gauge = " and r.metric !~ /_total$/" if gauges_only else ""
        start, stop = iso(ctx.now - start_days * DAY), iso(ctx.now - stop_days * DAY)
        return (
            f"from(bucket: {_bucket(ctx)}) |> range(start: {start}, stop: {stop})"
            f' |> filter(fn: (r) => r._measurement == "graphyard_metrics" and r._field == "value"{gauge})'
        )

    base = series(15)
    # Freshness per series: newest and oldest point of the 15 days.
    # Keyed by the full series identity; series_name() is for display only.
    newest = {series_key(r): (r, _epoch(r["_time"])) for r in ctx.flux(base + " |> last()") if not _skip(r)}
    oldest = {series_key(r): _epoch(r["_time"]) for r in ctx.flux(base + " |> first()") if not _skip(r)}
    names = {key: series_name(row) for key, (row, _last) in newest.items()}
    sleeping = set(ctx.config["sleeping_hosts"])
    stale: list[tuple[str, str, float]] = []
    appeared = []
    for key, (row, last) in newest.items():
        age = ctx.now - last
        relaxed = row.get("host") in sleeping or row.get("metric", "").startswith("ha.")
        if (2 * DAY if relaxed else 2 * HOUR) < age < 14 * DAY:
            stale.append((names[key], row.get("metric", "?"), age))
        if ctx.now - oldest.get(key, 0) < DAY:
            appeared.append(names[key])
    silent = _group_silent(stale)
    fresh = sum(1 for _row, last in newest.values() if ctx.now - last < 2 * HOUR)
    if not newest or not fresh:
        # An empty or stopped feed is a broken source, not a quiet day.
        ctx.errors.append(f"metrics: {len(newest)} series in 15 days, {fresh} updated within 2 h")
    daily: dict[str, dict[str, list[tuple[float, float]]]] = defaultdict(lambda: {"mean": [], "max": []})
    # Day windows end at the pack's time of day, like the last-24-hour window they are compared with.
    offset = int(ctx.now % DAY)
    for fn in ("mean", "max"):
        query = (
            f"{series(15, 1, True)} |> aggregateWindow(every: 1d, offset: {offset}s, fn: {fn}, createEmpty: false)"
        )
        for row in ctx.flux(query):
            if not _skip(row):
                daily[series_key(row)][fn].append((_epoch(row["_time"]), float(row["_value"])))
    recent: dict[str, dict[str, float]] = defaultdict(dict)
    for fn in ("mean", "max"):
        for row in ctx.flux(f"{series(1, gauges_only=True)} |> {fn}()"):
            if not _skip(row):
                recent[series_key(row)][fn] = float(row["_value"])
                names.setdefault(series_key(row), series_name(row))
    strongest: dict[str, dict[str, Any]] = {}
    for key, values in recent.items():
        for fn, value in values.items():
            past = [value for _ts, value in daily.get(key, {}).get(fn, [])]
            if len(past) < 7:
                continue
            z, relative = robust_deviation(value, past)
            if abs(z) < float(ctx.config["deviation_z"]) or abs(relative) < float(ctx.config["deviation_relative"]):
                continue
            if key in strongest and abs(strongest[key]["z"]) >= abs(z):
                continue
            strongest[key] = {
                "series": names[key], "stat": fn, "last_24h": round(value, 4), "median_14d": round(statistics.median(past), 4),
                "min_14d": round(min(past), 4), "max_14d": round(max(past), 4), "z": round(z, 1),
            }  # fmt: skip
    deviations = sorted(strongest.values(), key=lambda d: (-abs(d["z"]), d["series"], d["stat"]))
    disks = []
    for key, (row, last) in newest.items():
        if row.get("metric") != "host.filesystem_used_ratio" or ctx.now - last > DAY:
            continue
        used = float(row["_value"])
        means = daily.get(key, {}).get("mean", [])
        slope = slope_per_day([*means, (last, used)]) if len(means) >= 7 else 0.0
        days_left = (1.0 - used) / slope if slope > 0.0005 else None
        # The sealed macOS system volume (an APFS snapshot) mirrors its container's Data volume.
        sealed = row.get("mountpoint") == "/" and bool(re.fullmatch(r"/dev/disk[0-9]+s[0-9]+s[0-9]+", row.get("device", "")))
        if (used >= 0.85 or (days_left is not None and days_left < 30)) and not sealed:
            disks.append({"series": names[key], "used": round(used, 3),
                          "days_to_full": round(days_left) if days_left is not None else None})  # fmt: skip
    return {
        "series_15d": len(newest),
        "deviations": deviations[: ctx.cap("deviations")],
        "deviations_total": len(deviations),
        "silent": silent[: ctx.cap("series")],
        "silent_series_total": len(stale),
        "appeared": sorted(appeared)[: ctx.cap("series")],
        "appeared_total": len(appeared),
        "filesystems": sorted(
            disks, key=lambda d: (d["days_to_full"] if d["days_to_full"] is not None else 10**9, -d["used"])
        )[: ctx.cap("series")],
        "filesystems_total": len(disks),
    }


# -- TLS and Nyxmon -------------------------------------------------------------------------


def certificate_days(host: str, port: int, now: float) -> float:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
    not_after = ssl.cert_time_to_seconds(str(cert["notAfter"]))  # type: ignore[index]
    return (not_after - now) / DAY


def nyxmon_https_hosts(path: str) -> list[str]:
    """``host:port`` of every enabled Nyxmon check that probes an ``https://`` URL."""

    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        rows = db.execute("select url, data from health_check where disabled = 0").fetchall()
    finally:
        db.close()
    urls = []
    for url, data in rows:
        urls.append(url)
        # json-metrics checks fetch data.url, which may differ from the displayed url.
        try:
            inner = json.loads(data or "{}")
        except ValueError:
            continue
        if isinstance(inner, dict) and isinstance(inner.get("url"), str):
            urls.append(inner["url"])
    hosts = []
    for url in urls:
        try:
            parsed = urllib.parse.urlsplit(str(url))
            if parsed.scheme == "https" and parsed.hostname:
                hosts.append(f"{parsed.hostname}:{parsed.port or 443}")
        except ValueError:
            continue  # one malformed check URL must not hide the other certificates
    return hosts


def section_tls(ctx: Context) -> dict[str, Any]:
    """Certificates of ``tls_hosts`` and of every HTTPS host Nyxmon probes: expiring within 21 days or failing."""

    targets = [t if ":" in t else f"{t}:443" for t in ctx.config["tls_hosts"]]
    if ctx.config.get("nyxmon_db"):
        targets += nyxmon_https_hosts(ctx.config["nyxmon_db"])
    targets = sorted(set(targets))

    def check(target: str) -> dict[str, Any] | None:
        host, _, port = target.rpartition(":")
        try:
            days = certificate_days(host, int(port), ctx.now)
        except (OSError, ssl.SSLError, ValueError, KeyError) as error:
            return {"host": target, "error": f"{type(error).__name__}: {str(error)[:120]}"}
        return {"host": target, "days_left": round(days, 1)} if days < 21 else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        found = [result for result in pool.map(check, targets) if result is not None]
    return {"checked": len(targets), "findings": found}


def section_nyxmon(ctx: Context) -> list[dict[str, str]]:
    path = ctx.config.get("nyxmon_db")
    if not path:
        return []
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        rows = db.execute(
            "select s.name, h.name, r.status from health_check h join service s on s.id = h.service_id"
            " join check_result r on r.id = (select max(id) from check_result where health_check_id = h.id)"
            " where h.disabled = 0 and r.status != 'ok' order by s.name, h.name"
        ).fetchall()
    finally:
        db.close()
    return [{"service": service, "check": name, "status": status} for service, name, status in rows]


# -- the pack -------------------------------------------------------------------------------


def build_pack(ctx: Context) -> dict[str, Any]:
    pack: dict[str, Any] = {"schema": SCHEMA, "date": day_of(ctx.now), "generated_at": iso(ctx.now), "logs": {}}

    def run(name: str, step: Callable[[], Any], default: Any) -> Any:
        try:
            return step()
        except Exception as error:  # noqa: BLE001 - one broken section must not hide the others
            ctx.errors.append(f"{name}: {type(error).__name__}: {str(error)[:200]}")
            return default

    feed = True
    try:
        hosts: list[str] | None = log_hosts(ctx)
    except NoLogFeed as empty:
        feed, hosts = False, empty.configured
        ctx.errors.append(f"log hosts: {empty}")
        pack["logs"]["volume"] = {"silent_last_hour": hosts, "hosts": [], "changed": [], "appeared": [], "vanished": []}
    except Exception as error:  # noqa: BLE001 - one broken section must not hide the others
        ctx.errors.append(f"log hosts: {type(error).__name__}: {str(error)[:200]}")
        hosts = None
    pack["log_hosts"] = hosts
    if hosts is not None and feed:
        pack["logs"]["volume"] = run("logs.volume", lambda: section_volume(ctx, hosts), None)
        pack["logs"]["signatures"] = run("logs.signatures", lambda: section_signatures(ctx, hosts), None)
        pack["logs"]["unit_restarts"] = run("logs.unit_restarts", lambda: section_unit_restarts(ctx, hosts), None)
        pack["logs"]["samples"] = run("logs.samples", lambda: section_samples(ctx, hosts), None)
    pack["metrics"] = run("metrics", lambda: section_metrics(ctx), None)
    pack["tls"] = run("tls", lambda: section_tls(ctx), None)
    pack["nyxmon_not_ok"] = run("nyxmon", lambda: section_nyxmon(ctx), None)
    pack["notes"] = ctx.notes
    pack["errors"] = ctx.errors
    pack.update(clean_all(pack))
    return pack


MAX_PACK = 4 * 1024 * 1024  # what obs_ctl.py hands over; keep in step


def clean_all(value: Any) -> Any:
    """Every string (keys too) of ``value`` through ``clean``: a pack always encodes."""

    if isinstance(value, str):
        return clean(value)
    if isinstance(value, dict):
        return {clean(str(k)): clean_all(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean_all(item) for item in value]
    return value


def fit_pack(pack: dict[str, Any], limit: int = MAX_PACK // 2) -> None:
    """Halve the longest lists until the pack fits ``limit`` bytes; a trimmed pack is a pack error, and
    one that still does not fit is replaced by a small error pack."""

    def lists(value: Any) -> list[list[Any]]:
        if isinstance(value, dict):
            return [found for item in value.values() for found in lists(item)]
        if isinstance(value, list):
            return [value, *[found for item in value for found in lists(item)]]
        return []

    def size() -> int:
        # The serialization _write_json publishes.
        return len((json.dumps(pack, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode())

    trimmed = False
    while size() > limit:
        candidates = [items for items in lists(pack) if len(items) > 1 and items is not pack.get("errors")]
        if not candidates:
            break
        longest = max(candidates, key=lambda items: len(json.dumps(items, ensure_ascii=False)))
        del longest[len(longest) // 2 :]
        trimmed = True
    if trimmed:
        pack["errors"].append(f"pack: lists trimmed to fit {limit} bytes")
    if size() > limit:
        # Still too large (single huge entries): publish a bounded error pack instead.
        errors = [str(e)[:300] for e in pack.get("errors", [])][:50]
        errors.append(f"pack: larger than {limit} bytes even after trimming; replaced by this error pack")
        keep = {key: pack.get(key) for key in ("schema", "date", "generated_at")}
        pack.clear()
        pack.update(keep, logs={}, errors=errors, notes=[])


def prune(directory: str, keep_days: int, now: float) -> None:
    oldest = day_of(now - keep_days * DAY)
    for name in os.listdir(directory):
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.json", name) and name[:10] < oldest:
            os.remove(os.path.join(directory, name))


def load_config(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, ValueError) as error:
        raise ConfigError(f"config unreadable: {type(error).__name__}") from None
    required = (
        "state_dir", "loki_url", "influx", "loki_exclude_lines", "sleeping_hosts", "tls_hosts", "caps",
        "backfill_days", "new_signature_min", "deviation_z", "deviation_relative", "pack_retention_days",
        "signature_retention_days", "sample_lines_per_window", "sample_budget_bytes", "pack_max_bytes",
    )  # fmt: skip
    missing = [key for key in required if key not in config]
    if missing:
        raise ConfigError(f"config lacks {', '.join(missing)}")
    return dict(config)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the daily observability evidence pack")
    parser.add_argument("--config", required=True)
    parser.add_argument("--now", type=float, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except ConfigError as error:
        print(f"obs-pack: {error}", file=sys.stderr)
        return 2
    now = args.now if args.now is not None else time.time()
    state_dir = config["state_dir"]
    packs = os.path.join(state_dir, "packs")
    os.makedirs(packs, exist_ok=True)
    influx = config["influx"]
    ctx = Context(
        config=config,
        now=now,
        loki=loki_client(config["loki_url"]),
        flux=flux_client(influx["url"], influx["org"], influx["token_file"]),
        state_dir=state_dir,
    )
    started = time.time()
    pack = build_pack(ctx)
    pack["duration_seconds"] = round(time.time() - started)
    fit_pack(pack, int(config["pack_max_bytes"]))
    _write_json(os.path.join(packs, f"{pack['date']}.json"), pack)
    _write_json(os.path.join(packs, "latest.json"), pack)
    prune(packs, int(config["pack_retention_days"]), now)
    # Counted from the published pack: fit_pack may have replaced it by an error pack.
    status = {"schema": SCHEMA, "pack_date": pack["date"], "pack_epoch": int(now), "pack_errors": len(pack["errors"])}
    _write_json(os.path.join(state_dir, "status.json"), status)
    sig = pack["logs"].get("signatures") or {}
    metrics = pack.get("metrics") or {}
    print(
        f"obs-pack: {pack['date']}: {sig.get('new_total', '?')} new templates, "
        f"{metrics.get('deviations_total', '?')} metric deviations, {len(ctx.errors)} section errors"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
