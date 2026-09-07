#!/usr/bin/env python3
"""Read-only Linux software observations; no package updates or service mutations."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import ipaddress
import json
import math
import os
import re
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
UPSTREAM_URL = "https://api.github.com/repos/traefik/traefik/releases/latest"
UPSTREAM_TTL = 86400
MAX_REPORT_AGE = 1800


def version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValueError("unsupported version")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def command(argv: list[str], timeout: int = 15, pass_fds: tuple[int, ...] = ()) -> str:
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
        pass_fds=pass_fds,
    )
    return result.stdout.strip()


def binary_info(
    path: str, expected_target: str | None = None, probe_version: bool = True
) -> dict[str, Any]:
    with open(path, "rb") as stream:
        # Pin the inode before validating a process image; never execute a later
        # re-exec through the mutable /proc/PID/exe link.
        if expected_target is not None:
            target = os.readlink(f"/proc/self/fd/{stream.fileno()}")
            if target != os.path.realpath(expected_target):
                raise ValueError("refusing unexpected or deleted process image")
        before = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        output = ""
        if probe_version:
            output = (
                command(
                    [f"/proc/self/fd/{stream.fileno()}", "version"],
                    pass_fds=(stream.fileno(),),
                )
                if expected_target is not None
                else command([path, "version"])
            )
        after = os.fstat(stream.fileno())
    match = re.search(r"(?m)^Version:\s*(v?\d+\.\d+\.\d+)\s*$", output)
    if probe_version and not match:
        raise ValueError("unparseable binary version")
    final = os.stat(path)

    def identity(stat: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            stat.st_dev,
            stat.st_ino,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
            stat.st_size,
        )

    if identity(before) != identity(after) or identity(before) != identity(final):
        raise ValueError("binary changed during observation")
    return {
        "version": match.group(1).removeprefix("v") if match else None,
        "sha256": digest,
    }


def main_pid(unit: str) -> int:
    return int(command(["systemctl", "show", unit, "--property=MainPID", "--value"]))


def atomic_json(path: Path, data: dict[str, Any], group: int | None = None) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".software-live-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o640)
            if group is not None:
                os.fchown(stream.fileno(), -1, group)
            json.dump(data, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def upstream(cache_path: Path | None, now: float) -> dict[str, Any]:
    cached: dict[str, Any] = {}
    if cache_path:
        try:
            cached = json.loads(cache_path.read_text())
            version(cached["version"])
            if 0 <= now - cached["checked_at_epoch"] < UPSTREAM_TTL:
                return {**cached, "status": "ok", "cached": True}
        except (OSError, ValueError, KeyError, TypeError):
            cached = {}
    try:
        request = urllib.request.Request(
            UPSTREAM_URL,
            headers={
                "User-Agent": "ops-library-software-live/1",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read(1024 * 1024))
        tag = data["tag_name"]
        version(tag)
        if data.get("draft") or data.get("prerelease"):
            raise ValueError("upstream release is not stable")
        result = {"version": tag.removeprefix("v"), "checked_at_epoch": now}
        if cache_path:
            atomic_json(cache_path, result)
        return {**result, "status": "ok", "cached": False}
    except Exception as exc:  # noqa: BLE001 - observation boundaries fail closed
        # Never promote a failed refresh or old cache into fresh success.
        return {
            "status": "unknown",
            "error": type(exc).__name__,
            "last_success": cached or None,
        }


def observe_traefik(policy: dict[str, Any], latest: dict[str, Any]) -> dict[str, Any]:
    expected = policy["expected"]
    path = policy["binary_path"]
    unit = policy["unit"]
    result: dict[str, Any] = {
        "expected": expected,
        "observed": False,
        "binary_path": path,
        "desired_version": policy.get("desired_version"),
        "issues": [],
    }
    try:
        for attempt in range(2):
            result["issues"] = []
            pid = main_pid(unit)
            exists = Path(path).exists()
            if not expected:
                exists = any(
                    Path(candidate).exists()
                    for candidate in ("/usr/bin/traefik", "/usr/local/bin/traefik")
                )
                result.update(
                    status="warning" if pid or exists else "ok",
                    present=bool(pid or exists),
                    observed=True,
                )
                if pid or exists:
                    result["issues"].append("unexpected_installation")
                return result
            if not pid or not exists:
                raise ValueError("service stopped or managed binary missing")
            running_path = f"/proc/{pid}/exe"
            target = os.readlink(running_path)
            if target.endswith(" (deleted)"):
                result["issues"].append("deleted_running_executable")
            if target.removesuffix(" (deleted)") != os.path.realpath(path):
                result["issues"].append("running_path_mismatch")
            refuse_execution = target != os.path.realpath(path)
            installed = binary_info(path)
            running = (
                binary_info(running_path, probe_version=False)
                if refuse_execution
                else binary_info(running_path, expected_target=path)
            )
            if main_pid(unit) == pid and os.readlink(running_path) == target:
                break
            if attempt:
                raise ValueError("MainPID changed during observation")
        result.update(
            observed=True,
            installed=installed,
            running=running,
            main_pid=pid,
            running_path=target,
            upstream=latest,
        )
        if installed["sha256"] != running["sha256"] or (
            running["version"] is not None
            and installed["version"] != running["version"]
        ):
            result["issues"].append("installed_running_drift")
        desired = policy.get("desired_version")
        if desired is None:
            result["issues"].append("desired_version_unassigned")
        elif version(desired) != version(installed["version"]):
            result["issues"].append("desired_installed_drift")
        if latest["status"] != "ok":
            result["issues"].append("upstream_unknown")
            result["status"] = "unknown"
        else:
            if running["version"] is not None and version(running["version"]) < version(
                latest["version"]
            ):
                result["issues"].append("outdated_running_version")
            result["status"] = "warning" if result["issues"] else "ok"
    except Exception as exc:  # noqa: BLE001 - observation boundaries fail closed
        result.update(status="unknown", error=f"{type(exc).__name__}: {exc}"[:240])
    return result


def security_origin(origin: Any) -> bool:
    return bool(
        origin.trusted
        and (
            (
                origin.origin in {"Ubuntu", "Debian"}
                and "security" in origin.archive.lower()
            )
            or origin.origin.startswith("UbuntuESM")
            or origin.label == "Debian-Security"
        )
    )


def security_packages(cache: Any, compare: Any, held: set[str]) -> list[dict[str, Any]]:
    updates = []
    for package in cache:
        if not package.installed:
            continue
        candidates = [
            v
            for v in package.versions
            if compare(v.version, package.installed.version) > 0
            and any(security_origin(o) for o in v.origins)
        ]
        if not candidates:
            continue
        newest = candidates[0]
        for candidate in candidates[1:]:
            if compare(candidate.version, newest.version) > 0:
                newest = candidate
        updates.append(
            {
                "package": package.fullname,
                "installed": package.installed.version,
                "security_version": newest.version,
                "candidate": package.candidate.version if package.candidate else None,
                "held": package.name in held or package.fullname in held,
            }
        )
    return sorted(updates, key=lambda item: item["package"])


def observe_apt(max_age: int, now: float) -> dict[str, Any]:
    try:
        import apt  # type: ignore[import-not-found]
        import apt_pkg  # type: ignore[import-not-found]

        indexes = [
            p
            for p in Path("/var/lib/apt/lists").glob("*InRelease")
            if "security" in p.name.lower()
        ]
        ages = [now - p.stat().st_mtime for p in indexes]
        updates = security_packages(
            apt.Cache(memonly=True),
            apt_pkg.version_compare,
            set(command(["apt-mark", "showhold"]).splitlines()),
        )
        return {
            "status": "ok",
            "pending_security_count": len(updates),
            "pending_security_updates": updates,
            "indexes_fresh": bool(ages) and all(0 <= age <= max_age for age in ages),
            "oldest_security_index_age_seconds": max(ages) if ages else None,
            "index_age_limit_seconds": max_age,
            "index_source": "cached security InRelease publication mtimes; no refresh performed",
        }
    except Exception as exc:  # noqa: BLE001 - observation boundaries fail closed
        return {
            "status": "unknown",
            "error": f"APT observation failed ({type(exc).__name__})",
            "indexes_fresh": False,
            "pending_security_count": None,
        }


def validate_policy(policy: dict[str, Any]) -> None:
    if not isinstance(policy.get("host"), str) or not policy["host"]:
        raise ValueError("host is required")
    config = policy["traefik"]
    if not isinstance(config["expected"], bool) or config["unit"] != "traefik.service":
        raise ValueError("invalid Traefik policy")
    if config["binary_path"] not in {"/usr/bin/traefik", "/usr/local/bin/traefik"}:
        raise ValueError("unsupported binary path")
    if config.get("desired_version") is not None:
        version(config["desired_version"])
    age = policy.get("apt_max_age_seconds", 172800)
    if isinstance(age, bool) or not isinstance(age, int) or not 3600 <= age <= 1209600:
        raise ValueError("invalid APT age budget")


def collect(policy: dict[str, Any], cache: Path | None = None) -> dict[str, Any]:
    validate_policy(policy)
    now = time.time()
    latest = (
        upstream(cache, now)
        if policy["traefik"]["expected"]
        else {"status": "not_applicable"}
    )
    proxy = observe_traefik(policy["traefik"], latest)
    packages = observe_apt(policy.get("apt_max_age_seconds", 172800), now)
    return {
        "schema_version": SCHEMA_VERSION,
        "host": policy["host"],
        "generated_at_epoch": time.time(),
        "policy_sha256": hashlib.sha256(
            json.dumps(policy, sort_keys=True).encode()
        ).hexdigest(),
        "traefik": proxy,
        "apt": packages,
        "summary": {
            "observation_ok": proxy["observed"] and packages["status"] != "unknown",
            "traefik_ok": proxy["status"] == "ok",
            "security_updates_ok": packages["pending_security_count"] == 0,
            "apt_indexes_fresh": packages["indexes_fresh"],
        },
    }


def with_freshness(data: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != SCHEMA_VERSION
        or not isinstance(data.get("summary"), dict)
    ):
        raise ValueError("invalid report schema")
    for key in (
        "observation_ok",
        "traefik_ok",
        "security_updates_ok",
        "apt_indexes_fresh",
    ):
        if not isinstance(data["summary"].get(key), bool):
            raise ValueError("invalid summary")
    timestamp = data["generated_at_epoch"]
    if type(timestamp) not in (int, float) or not math.isfinite(timestamp):
        raise ValueError("invalid timestamp")
    age = (time.time() if now is None else now) - timestamp
    data["meta"] = {"age_seconds": age, "max_age_seconds": MAX_REPORT_AGE}
    data["summary"]["fresh"] = 0 <= age <= MAX_REPORT_AGE
    return data


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def do_GET(self) -> None:
        config = self.server.config  # type: ignore[attr-defined]
        if self.path != config["path"]:
            self.reply(404, {"error": "not_found"})
            return
        try:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Basic ") or len(header) > 4096:
                raise ValueError("missing auth")
            user, password = (
                base64.b64decode(header[6:], validate=True).decode().split(":", 1)
            )
            if user != config["auth_user"] or "\n" in password:
                raise ValueError("invalid auth")
            subprocess.run(
                ["htpasswd", "-vi", config["htpasswd"], user],
                input=password,
                text=True,
                capture_output=True,
                check=True,
                timeout=5,
            )
        except Exception:  # noqa: BLE001 - malformed/auth/provider failures fail closed
            self.reply(401, {"error": "unauthorized"})
            return
        try:
            data = with_freshness(json.loads(Path(config["state"]).read_text()))
            self.reply(200, data)
        except Exception:  # noqa: BLE001 - malformed/auth/provider failures fail closed
            self.reply(503, {"error": "missing_or_invalid_observation"})

    def reply(self, code: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if code == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="software-live"')
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Do not log request headers, credentials or arbitrary paths.


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["collect", "serve", "validate"])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--config-json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--group")
    args = parser.parse_args()
    config = json.loads(
        args.config_json if args.config_json else args.config.read_text()
    )
    if args.mode == "validate":
        validate_policy(config)
        return
    if args.mode == "serve":
        address = ipaddress.ip_address(config["bind"])
        if address.version != 4 or not (
            address.is_loopback or address in ipaddress.ip_network("100.64.0.0/10")
        ):
            raise ValueError("endpoint must bind IPv4 loopback or Tailscale")
        server = http.server.HTTPServer((config["bind"], int(config["port"])), Handler)
        server.config = config  # type: ignore[attr-defined]
        server.serve_forever()
    else:
        data = collect(config, args.cache)
        if args.output:
            import grp

            group = grp.getgrnam(args.group).gr_gid if args.group else None
            atomic_json(args.output, data, group)
        else:
            print(json.dumps(with_freshness(data), sort_keys=True))


if __name__ == "__main__":
    main()
