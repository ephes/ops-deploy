"""Compare the production (Python) and the shadow (Rust) observation of a host.

PLAN.md 6.3 and 8.1. With ``software_live_rust_shadow: true`` a host runs the
Rust collector next to the Python one, with its own output and caches under
``<data_dir>/shadow/``. This script fetches both sides read-only (``--ssh
root@<host>``: one ``ssh`` that runs a small read-only Python program printing
the files as JSON) or reads a saved bundle (``--bundle``), and reports:

* hard checks: both states have schema 2, the same ``host`` and the same
  ``policy_sha256``; each side's ``summary`` is the one 3.3 derives from its
  observations; each side's projection (``software-health.json``) is exactly
  what the Python oracle's ``inventory_projection`` makes of that side's state
  (so a projection difference between the sides always follows from a state
  difference, and only the states are compared with each other);
* every difference between the two states' observations (``os``,
  ``postgresql``, ``traefik``, ``apt``; ``summary`` and the projections follow
  from them), each either **ignored** (time fields, P2; the cache-only fields
  ``cached``, ``checked_at_epoch`` and ``last_success*`` of the separate
  caches), **explained** by a change between the two observation times, with
  its evidence, or **unexplained**.

An explanation never makes a sample pass: it says why the sample cannot judge
those fields (both programs observed different worlds), not that the shadow
got them right. A sample with explained differences is **inconclusive** and is
repeated; the shadow period counts only conclusive samples.

Explanations (PLAN.md 6.3: an APT list refresh, a Traefik or PostgreSQL
restart, an upstream release):

* ``upstream``: the two sides' cached upstream data (``upstream*.json``,
  without ``checked_at_epoch``) differ, so they were fetched before and after
  an upstream change; or only the production lookup failed. Explains the
  observation's ``upstream``, ``lifecycle``, ``issues`` and ``status``. A
  failed shadow lookup is never explained.
* ``restart`` (Traefik): ``main_pid`` differs. Explains ``main_pid``,
  ``running``, ``running_path``, ``issues``, ``status``.
* ``package``: ``/var/lib/dpkg/status`` or the Traefik binary changed between
  the two observations. Explains installed and running versions, PostgreSQL
  versions and clusters, OS release fields, ``issues``, ``status`` and every
  ``apt`` field.
* ``apt-lists``: the oldest security index's mtime (observation time minus its
  age) differs by more than 120 s. Explains every ``apt`` field.
* ``index-age``: the index age crossed the limit between the two observations.
  Explains ``apt.indexes_fresh`` only.

Anything else, and every failed hard check, is unexplained.

Exit status: 0 match (no difference beyond the ignored fields), 1 mismatch
(unexplained differences or failed hard checks), 2 the inputs could not be
read, 3 inconclusive (only explained differences: repeat the sample after the
next runs of both collectors).

The projection check imports ``roles/software_live/files/software_live.py``
(Python 3.11 or later). Otherwise stdlib only; ``test_shadow_compare.py``.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ORACLE = (
    Path(__file__).resolve().parents[3]
    / "roles"
    / "software_live"
    / "files"
    / "software_live.py"
)
OBSERVATIONS = ("os", "postgresql", "traefik")
TIME_KEYS = frozenset({"oldest_security_index_age_seconds"})
CACHE_KEYS = frozenset(
    {"cached", "checked_at_epoch", "last_success", "last_success_checked_at_epoch"}
)
INDEX_SLACK_SECONDS = 120.0
# Fields of an observation that a change of installed software explains.
PACKAGE_FIELDS = frozenset(
    {
        "installed",
        "running",
        "running_path",
        "main_pid",
        "server_version",
        "major",
        "cluster",
        "clusters",
        "pretty_name",
        "codename",
        "cycle",
        "id",
    }
)

# The read-only program the --ssh mode runs on the host (python3 -I -c).
# argv: data_dir, projection path. It prints one JSON object (a bundle).
REMOTE = r"""
import glob, json, os, sys, time
data, projection = sys.argv[1], sys.argv[2]
def read(path):
    try:
        with open(path, "rb") as handle:
            return {"json": json.loads(handle.read(1 << 20))}
    except FileNotFoundError:
        return {"missing": True}
    except Exception as exc:
        return {"error": type(exc).__name__}
def mtime(path):
    try:
        return os.stat(path).st_mtime
    except Exception:
        return None
def side(directory, projection_path):
    return {
        "state": read(os.path.join(directory, "state.json")),
        "projection": read(projection_path),
        "caches": {
            os.path.basename(p): read(p)
            for p in sorted(glob.glob(os.path.join(directory, "upstream*.json")))
        },
    }
production = side(data, projection)
shadow = side(os.path.join(data, "shadow"), os.path.join(data, "shadow", "software-health.json"))
binary = None
state = production["state"].get("json")
if isinstance(state, dict) and isinstance(state.get("traefik"), dict):
    path = state["traefik"].get("binary_path")
    if isinstance(path, str) and path.startswith("/"):
        binary = mtime(path)
print(json.dumps({
    "fetched_at_epoch": time.time(),
    "production": production,
    "shadow": shadow,
    "evidence": {
        "dpkg_status_mtime": mtime("/var/lib/dpkg/status"),
        "traefik_binary_mtime": binary,
    },
}))
"""


class InputError(Exception):
    """The bundle could not be fetched or read."""


def is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def iso(epoch: Any) -> str:
    if not is_number(epoch):
        return repr(epoch)
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_oracle() -> Any:
    if sys.version_info < (3, 11):
        raise RuntimeError("the Python oracle needs Python 3.11 or later")
    spec = importlib.util.spec_from_file_location("software_live_oracle", ORACLE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ORACLE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def walk(left: Any, right: Any, path: str) -> list[tuple[str, Any, Any]]:
    """Every leaf difference (type and value, P1) as (path, production, shadow)."""
    if isinstance(left, dict) and isinstance(right, dict):
        found = []
        for key in sorted(set(left) | set(right)):
            sub = f"{path}.{key}"
            if key not in left or key not in right:
                found.append((sub, left.get(key, "<absent>"), right.get(key, "<absent>")))
            else:
                found.extend(walk(left[key], right[key], sub))
        return found
    if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        found = []
        for index, (a, b) in enumerate(zip(left, right)):
            found.extend(walk(a, b, f"{path}[{index}]"))
        return found
    if type(left) is not type(right) or left != right:
        return [(path, left, right)]
    return []


def expected_summary(state: dict[str, Any]) -> dict[str, Any]:
    """PLAN.md 3.3: the summary the observations imply."""
    apt = state["apt"]
    return {
        "observation_ok": all(state[name]["observed"] for name in OBSERVATIONS)
        and apt["status"] != "unknown",
        "os_ok": state["os"]["status"] == "ok",
        "postgresql_ok": state["postgresql"]["status"] == "ok",
        "traefik_ok": state["traefik"]["status"] == "ok",
        "security_updates_ok": apt["pending_security_count"] == 0,
        "apt_indexes_fresh": apt["indexes_fresh"],
    }


def cache_data(side: dict[str, Any], name: str) -> Any:
    entry = side.get("caches", {}).get(name)
    if not isinstance(entry, dict) or not isinstance(entry.get("json"), dict):
        return None
    return {k: v for k, v in entry["json"].items() if k != "checked_at_epoch"}


def cache_name(observation: str, state: dict[str, Any]) -> str:
    if observation == "traefik":
        return "upstream.json"
    if observation == "postgresql":
        return "upstream-postgresql.json"
    product = state["os"].get("upstream", {}).get("product") or state["os"].get(
        "expected_id"
    )
    return f"upstream-{product}.json"


def upstream_reason(
    observation: str, bundle: dict[str, Any], prod: dict[str, Any], shadow: dict[str, Any]
) -> str | None:
    p_up = prod[observation].get("upstream", {})
    s_up = shadow[observation].get("upstream", {})
    p_status = p_up.get("status") if isinstance(p_up, dict) else None
    s_status = s_up.get("status") if isinstance(s_up, dict) else None
    if s_status not in ("ok", "not_applicable"):
        return None
    if p_status not in ("ok", "not_applicable"):
        return f"only the production (Python) lookup failed: {p_up.get('error')!r}"
    name = cache_name(observation, prod)
    p_cache = cache_data(bundle["production"], name)
    s_cache = cache_data(bundle["shadow"], name)
    if p_cache is None or s_cache is None or p_cache == s_cache:
        return None
    return (
        f"cached upstream data {name} differ (production fetched "
        f"{iso(p_up.get('checked_at_epoch'))}, shadow {iso(s_up.get('checked_at_epoch'))})"
    )


def changed_between(mtime: Any, start: float, end: float) -> bool:
    return is_number(mtime) and start - 5 <= mtime <= end + 5


def apt_reason(prod: dict[str, Any], shadow: dict[str, Any]) -> str | None:
    p, s = prod["apt"], shadow["apt"]
    p_age = p.get("oldest_security_index_age_seconds")
    s_age = s.get("oldest_security_index_age_seconds")
    if not (is_number(p_age) and is_number(s_age)):
        return None
    p_mtime = prod["generated_at_epoch"] - p_age
    s_mtime = shadow["generated_at_epoch"] - s_age
    if abs(p_mtime - s_mtime) > INDEX_SLACK_SECONDS:
        return (
            f"APT security index refreshed between the observations (oldest index "
            f"~{iso(p_mtime)} vs ~{iso(s_mtime)})"
        )
    return None


def index_age_reason(prod: dict[str, Any], shadow: dict[str, Any]) -> str | None:
    p, s = prod["apt"], shadow["apt"]
    p_age = p.get("oldest_security_index_age_seconds")
    s_age = s.get("oldest_security_index_age_seconds")
    limit = p.get("index_age_limit_seconds")
    if not (is_number(p_age) and is_number(s_age) and is_number(limit)):
        return None
    if (0 <= p_age <= limit) != (0 <= s_age <= limit):
        return f"index age crossed the {limit} s limit ({p_age:.0f} s vs {s_age:.0f} s)"
    return None


def classify(
    path: str,
    reasons: dict[str, dict[str, str]],
) -> str | None:
    """The reason that explains a difference at ``path``, if any."""
    parts = path.removeprefix("$.").replace("[", ".[").split(".")
    observation, field = parts[0], parts[1] if len(parts) > 1 else ""
    have = reasons.get(observation, {})
    if observation == "apt":
        if field == "indexes_fresh" and "index-age" in have:
            return have["index-age"]
        return have.get("apt-lists") or have.get("package")
    allowed: tuple[str, ...]
    if field in ("upstream", "lifecycle"):
        allowed = ("upstream",)
    elif field in ("issues", "status"):
        allowed = ("upstream", "restart", "package")
    elif field in ("main_pid", "running", "running_path"):
        allowed = ("restart", "package")
    elif field in PACKAGE_FIELDS:
        allowed = ("package",)
    else:
        allowed = ()
    for name in allowed:
        if name in have:
            return have[name]
    return None


def ignored(path: str, left: Any, right: Any) -> bool:
    key = path.rsplit(".", 1)[-1]
    if key in TIME_KEYS:
        return (left is None and right is None) or (is_number(left) and is_number(right))
    if ".upstream." in path and key in CACHE_KEYS:
        return True
    return ".upstream.last_success" in path


def compare(bundle: dict[str, Any], oracle: Any = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "checks": [],
        "explained": [],
        "unexplained": [],
        "ignored": 0,
    }

    def check(name: str, ok: bool, detail: str = "") -> None:
        report["checks"].append({"check": name, "ok": ok, "detail": detail})

    states = {}
    for side in ("production", "shadow"):
        entry = bundle[side]["state"]
        state = entry.get("json")
        valid = (
            isinstance(state, dict)
            and state.get("schema_version") == 2
            and all(isinstance(state.get(k), dict) for k in (*OBSERVATIONS, "apt", "summary"))
            and is_number(state.get("generated_at_epoch"))
        )
        detail = "" if valid else f"{side} state.json: {entry}"[:300]
        check(f"{side} state readable (schema 2)", valid, detail)
        if valid:
            states[side] = state
    if len(states) < 2:
        return finish(report)
    prod, shadow = states["production"], states["shadow"]
    report["host"] = prod.get("host")
    report["production_at"] = iso(prod["generated_at_epoch"])
    report["shadow_at"] = iso(shadow["generated_at_epoch"])
    report["gap_seconds"] = round(shadow["generated_at_epoch"] - prod["generated_at_epoch"], 1)

    check("same host", prod.get("host") == shadow.get("host"), f"{prod.get('host')!r} vs {shadow.get('host')!r}")
    check(
        "same policy_sha256",
        isinstance(prod.get("policy_sha256"), str) and prod.get("policy_sha256") == shadow.get("policy_sha256"),
        f"{prod.get('policy_sha256')} vs {shadow.get('policy_sha256')}",
    )
    for side, state in states.items():
        try:
            want = expected_summary(state)
        except (KeyError, TypeError) as exc:
            check(f"{side} summary follows from its observations", False, repr(exc))
            continue
        diff = walk(want, state["summary"], "$.summary")
        check(f"{side} summary follows from its observations", not diff, str(diff))

    if oracle is None:
        try:
            oracle = load_oracle()
        except Exception as exc:  # noqa: BLE001 - reported as a failed check
            check("projections (Python oracle)", False, f"oracle unavailable: {exc}")
    if oracle is not None:
        for side, state in states.items():
            projection = bundle[side]["projection"].get("json")
            name = f"{side} software-health.json is the oracle's projection of its state"
            if projection is None:
                check(name, False, f"no projection: {bundle[side]['projection']}")
                continue
            try:
                want = oracle.inventory_projection(state)
            except Exception as exc:  # noqa: BLE001
                check(name, False, f"oracle refused the state: {type(exc).__name__}: {exc}")
                continue
            diff = walk(want, projection, "$")
            stale = projection.get("observed_at_epoch") != state["generated_at_epoch"]
            detail = str(diff)[:600]
            if stale:
                detail = "projection is of another run (fetched during a collection; repeat): " + detail
            check(name, not diff, detail)

    start = min(prod["generated_at_epoch"], shadow["generated_at_epoch"])
    end = max(prod["generated_at_epoch"], shadow["generated_at_epoch"])
    evidence = bundle.get("evidence", {})
    reasons: dict[str, dict[str, str]] = {name: {} for name in (*OBSERVATIONS, "apt")}
    for name in OBSERVATIONS:
        reason = upstream_reason(name, bundle, prod, shadow)
        if reason:
            reasons[name]["upstream"] = reason
    if prod["traefik"].get("main_pid") != shadow["traefik"].get("main_pid"):
        reasons["traefik"]["restart"] = (
            f"Traefik restarted between the observations (MainPID "
            f"{prod['traefik'].get('main_pid')} -> {shadow['traefik'].get('main_pid')})"
        )
    if changed_between(evidence.get("dpkg_status_mtime"), start, end):
        package = f"/var/lib/dpkg/status changed at {iso(evidence['dpkg_status_mtime'])}, between the observations"
        for name in (*OBSERVATIONS, "apt"):
            reasons[name]["package"] = package
    if changed_between(evidence.get("traefik_binary_mtime"), start, end):
        reasons["traefik"].setdefault(
            "package",
            f"the Traefik binary changed at {iso(evidence['traefik_binary_mtime'])}, between the observations",
        )
    reason = apt_reason(prod, shadow)
    if reason:
        reasons["apt"]["apt-lists"] = reason
    reason = index_age_reason(prod, shadow)
    if reason:
        reasons["apt"]["index-age"] = reason

    for name in (*OBSERVATIONS, "apt"):
        for path, left, right in walk(prod[name], shadow[name], f"$.{name}"):
            if ignored(path, left, right):
                report["ignored"] += 1
                continue
            entry = {"path": path, "production": left, "shadow": right}
            why = classify(path, reasons)
            if why:
                report["explained"].append({**entry, "reason": why})
            else:
                report["unexplained"].append(entry)
    return finish(report)


def finish(report: dict[str, Any]) -> dict[str, Any]:
    failed = [c for c in report["checks"] if not c["ok"]]
    if failed or report["unexplained"]:
        report["verdict"] = "mismatch"
    elif report["explained"]:
        report["verdict"] = "inconclusive"
    else:
        report["verdict"] = "match"
    return report


def fetch(target: str, data_dir: str, projection: str, timeout: int) -> dict[str, Any]:
    argv = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        target,
        "python3",
        "-I",
        "-c",
        _quote(REMOTE),
        _quote(data_dir),
        _quote(projection),
    ]
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InputError(f"ssh {target}: {type(exc).__name__}: {exc}") from exc
    if result.returncode != 0:
        raise InputError(f"ssh {target} exited {result.returncode}: {result.stderr.strip()[:400]}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise InputError(f"ssh {target}: no JSON bundle: {exc}") from exc


def _quote(text: str) -> str:
    # ssh joins its arguments into one shell command line on the host.
    return "'" + text.replace("'", "'\\''") + "'"


def render(report: dict[str, Any]) -> str:
    lines = [
        f"host {report.get('host')}: production state {report.get('production_at')}, "
        f"shadow state {report.get('shadow_at')} (shadow - production: {report.get('gap_seconds')} s)"
    ]
    for item in report["checks"]:
        status = "ok  " if item["ok"] else "FAIL"
        detail = f" ({item['detail']})" if item["detail"] and not item["ok"] else ""
        lines.append(f"  {status} {item['check']}{detail}")
    lines.append(
        f"  state differences: {len(report['unexplained'])} unexplained, "
        f"{len(report['explained'])} explained, {report['ignored']} ignored (time and cache fields)"
    )
    for item in report["explained"]:
        lines.append(
            f"    explained {item['path']}: {item['production']!r} vs {item['shadow']!r} - {item['reason']}"
        )
    for item in report["unexplained"]:
        lines.append(f"    UNEXPLAINED {item['path']}: production {item['production']!r}, shadow {item['shadow']!r}")
    verdict = report["verdict"]
    if verdict == "inconclusive":
        verdict += " (only explained differences: repeat after the next runs of both collectors)"
    lines.append(f"  verdict: {verdict}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--ssh", metavar="TARGET", help="fetch read-only over ssh, e.g. root@host")
    source.add_argument("--bundle", type=Path, help="a bundle saved with --save-bundle")
    parser.add_argument("--data-dir", default="/var/lib/software-live")
    parser.add_argument(
        "--projection", default="/var/lib/software-estate-observations/software-health.json"
    )
    parser.add_argument("--save-bundle", type=Path, help="write the fetched bundle here")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    try:
        if args.ssh:
            bundle = fetch(args.ssh, args.data_dir, args.projection, args.timeout)
        else:
            try:
                bundle = json.loads(args.bundle.read_text())
            except (OSError, ValueError) as exc:
                raise InputError(f"{args.bundle}: {exc}") from exc
        if not isinstance(bundle, dict) or not all(
            isinstance(bundle.get(side), dict)
            and isinstance(bundle[side].get("state"), dict)
            and isinstance(bundle[side].get("projection"), dict)
            for side in ("production", "shadow")
        ):
            raise InputError("not a shadow_compare bundle")
        if args.save_bundle:
            args.save_bundle.write_text(json.dumps(bundle, sort_keys=True) + "\n")
    except InputError as exc:
        print(f"shadow_compare: {exc}", file=sys.stderr)
        return 2
    report = compare(bundle)
    print(json.dumps(report, sort_keys=True, indent=1) if args.json else render(report))
    return {"match": 0, "mismatch": 1, "inconclusive": 3}[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
