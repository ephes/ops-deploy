#!/usr/bin/env python3
"""Read-only, stdlib-only software discovery. Input is a JSON policy argument."""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import math
import os
import platform
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from os import fstat as artifact_stat
from os import read as artifact_read
from pathlib import Path
from xml.parsers.expat import ExpatError

SCHEMA = 2
MAX_BYTES = 32 * 1024 * 1024


def command(argv, timeout=30, env=None):
    """Spool stdout to disk; enforce timeout and cap before reading into memory."""
    limit = MAX_BYTES
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(
            argv,
            stdout=output,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if output.tell() > limit:
                    raise ValueError("output_limit")
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(argv[0], timeout)
                time.sleep(0.02)
            if process.returncode:
                raise RuntimeError("command_failed")
            if output.tell() > limit:
                raise ValueError("output_limit")
            output.seek(0)
            data = output.read(limit + 1)
            if len(data) > limit:
                raise ValueError("output_limit")
            return data.decode(errors="replace")
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()


class UnsupportedProbe(RuntimeError):
    """An unavailable tool cannot prove absence of installed software."""


def category(fn):
    try:
        return {"status": "ok", "items": fn()}
    except UnsupportedProbe:
        return {"status": "unsupported", "items": []}
    except (
        ExpatError,
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as exc:
        return {"status": "error", "error": type(exc).__name__, "items": []}


def packages():
    data = command(
        [
            "dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n",
        ]
    )
    return [
        {"name": a, "version": b, "architecture": c, "kind": "deb"}
        for line in data.splitlines()
        if len(parts := line.split("\t")) == 4
        for a, b, c, state in [parts]
        if state == "installed"
    ]


def units():
    # Both installed units and instantiated units; never return command lines.
    names = {
        line.split()[0]
        for line in command(
            [
                "systemctl",
                "list-unit-files",
                "--type=service",
                "--no-legend",
                "--no-pager",
            ]
        ).splitlines()
        if line.strip()
    }
    states = {}
    for row in json.loads(
        command(
            [
                "systemctl",
                "list-units",
                "--all",
                "--type=service",
                "--output=json",
                "--no-pager",
            ]
        )
    ):
        states[row["unit"]] = row["active"]
    return [
        {"name": name, "state": states.get(name, "not-loaded")}
        for name in sorted(names | states.keys())
    ]


def containers():
    if not shutil.which("docker"):
        raise UnsupportedProbe("docker unavailable")
    ids = command(["docker", "ps", "-aq"]).split()
    rows = []
    deadline = time.monotonic() + 60
    for identifier in ids:
        if time.monotonic() >= deadline:
            raise RuntimeError("container_discovery_deadline")
        if not re.fullmatch(r"[a-f0-9]{12,64}", identifier):
            raise ValueError("invalid container id")
        # Project only harmless fields in the daemon, before data leaves the host.
        fmt = (
            '{"id":{{json .Id}},"name":{{json .Name}},'
            '"image":{{json .Config.Image}},"image_id":{{json .Image}},'
            '"state":{{json .State.Status}}}'
        )
        row = json.loads(command(["docker", "inspect", "--format", fmt, identifier]))
        image_fmt = (
            '{"digests":{{json .RepoDigests}},"os":{{json .Os}},'
            '"architecture":{{json .Architecture}}}'
        )
        row.update(
            json.loads(
                command(
                    [
                        "docker",
                        "image",
                        "inspect",
                        "--format",
                        image_fmt,
                        row["image_id"],
                    ]
                )
            )
        )
        row["name"] = row["name"].lstrip("/")
        rows.append(row)
    return rows


def python_packages(root):
    if not Path(root).is_dir():
        raise FileNotFoundError("venv missing")
    entries = []
    for metadata in sorted(
        Path(root).glob("lib/python*/site-packages/*.dist-info/METADATA")
    ):
        if metadata.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("metadata_limit")
        msg = email.parser.Parser().parsestr(metadata.read_text(errors="replace"))
        entries.append(
            {
                "name": msg["Name"],
                "version": msg["Version"],
                "kind": "pypi",
                "requires": [
                    r for r in msg.get_all("Requires-Dist", []) if "@" not in r
                ],
                "omitted_direct_references": sum(
                    "@" in r for r in msg.get_all("Requires-Dist", [])
                ),
                "license": msg.get("License-Expression"),
                "source": str(metadata),
            }
        )
    return entries


def git_checkout(root):
    prefix = [
        "git",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"safe.directory={root}",
        "-C",
        root,
    ]
    commit = command(prefix + ["rev-parse", "HEAD"]).strip()
    # No filenames (may be sensitive); merely note whether working tree is dirty.
    dirty = bool(
        command(prefix + ["status", "--porcelain", "--untracked-files=normal"])
    )
    return {"commit": commit, "dirty": dirty}


ARTIFACT_ROOT = "/opt"


def artifact_metadata(relative):
    """Read bounded public release metadata through pinned, trusted directories."""
    parts = Path(relative).parts
    if (
        not parts
        or Path(relative).is_absolute()
        or any(p in (".", "..") for p in parts)
    ):
        raise ValueError("invalid artifact path")
    directory = os.open(ARTIFACT_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            st = artifact_stat(directory)
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise ValueError("untrusted artifact directory")
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
        st = artifact_stat(directory)
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("untrusted artifact directory")
        fd = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            st = artifact_stat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise ValueError("untrusted artifact file")
            if st.st_size > 16384:
                raise ValueError("oversized artifact metadata")
            content = bytearray()
            while len(content) <= 16384:
                block = artifact_read(fd, 16385 - len(content))
                if not block:
                    return content.decode("utf-8")
                content.extend(block)
            raise ValueError("oversized artifact metadata")
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def web_artifact_version(kind):
    if platform.system() != "Linux":
        raise ValueError("unsupported probe")
    if kind == "snappymail":
        source = "snappymail/index.php"
        metadata = artifact_metadata(source)
        definitions = re.findall(
            r"\bdefine\s*\(\s*(['\"])APP_VERSION\1", metadata, re.IGNORECASE
        )
        matches = re.findall(
            r"^[ \t]*define\('APP_VERSION', '([0-9]+\.[0-9]+\.[0-9]+)'\);[ \t]*$",
            metadata,
            re.MULTILINE,
        )
        if (
            len(matches) != 1
            or len(definitions) != 1
            or re.search(r"\bconst\s+APP_VERSION\b", metadata, re.IGNORECASE)
        ):
            raise ValueError("ambiguous or missing artifact version")
        version = matches[0]
        # Read only the version-selected public entry point, never execute PHP.
        entry = f"snappymail/snappymail/v/{version}/include.php"
    elif kind == "postfixadmin":
        source = "postfixadmin/.installed_version"
        version = artifact_metadata(source).strip()
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ValueError("invalid artifact version")
        entry = "postfixadmin/public/index.php"
    else:
        raise ValueError("unsupported probe")
    if not artifact_metadata(entry).strip():
        raise ValueError("empty artifact entry point")
    return {
        "presence": "installed",
        "installed_version": version,
        "running_version": None,
        "version_source": {
            "kind": "artifact-metadata",
            "path": str(Path(ARTIFACT_ROOT) / source),
            "entry_point": str(Path(ARTIFACT_ROOT) / entry),
        },
    }


def media_version(kind):
    # Dedicated known probes only; no arbitrary executable paths from policy.
    if kind in ("snappymail", "postfixadmin"):
        return web_artifact_version(kind)
    if kind != "navidrome" or platform.system() != "Linux":
        raise ValueError("unsupported probe")
    path = "/opt/navidrome/navidrome"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("untrusted binary")
        # Keep the verified inode pinned across the child execution.
        result = subprocess.run(
            [f"/proc/self/fd/{fd}", "--version"],
            pass_fds=(fd,),
            check=False,
            capture_output=True,
            timeout=10,
        )
        if result.returncode:
            raise RuntimeError("version probe failed")
        match = re.match(r"(\d+\.\d+\.\d+)\b", result.stdout.decode())
        if not match:
            raise ValueError("unexpected version output")
        evidence = {"installed_version": match[1], "running_version": None}
        pid_text = command(
            ["systemctl", "show", "navidrome.service", "--property=MainPID", "--value"]
        ).strip()
        if pid_text.isdigit() and int(pid_text) > 0:
            try:
                running = os.stat(f"/proc/{pid_text}/exe")
                unchanged = (
                    command(
                        [
                            "systemctl",
                            "show",
                            "navidrome.service",
                            "--property=MainPID",
                            "--value",
                        ]
                    ).strip()
                    == pid_text
                )
                if unchanged and (st.st_dev, st.st_ino) == (
                    running.st_dev,
                    running.st_ino,
                ):
                    evidence["running_version"] = match[1]
            except OSError:
                pass
        return evidence
    finally:
        os.close(fd)


HEALTH_EXPORT = Path("/var/lib/software-estate-observations/software-health.json")


def software_health(expected_host):
    """Read an allowlisted local projection; no network, privilege or command."""
    parent = HEALTH_EXPORT.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError("unsafe_health_directory")
    fd = os.open(HEALTH_EXPORT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != 0
            or st.st_nlink != 1
            or st.st_mode & 0o022
        ):
            raise ValueError("unsafe_health_file")
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("health_size_limit")
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {
        "schema_version",
        "source",
        "host",
        "observed_at_epoch",
        "max_age_seconds",
        "checks",
        "apt",
    }:
        raise ValueError("invalid_health_schema")
    if (
        (
            not isinstance(data["schema_version"], int)
            or isinstance(data["schema_version"], bool)
        )
        or data["schema_version"] != 1
        or data["source"] != "software-live/2"
        or not expected_host
        or data["host"] != expected_host
    ):
        raise ValueError("health_identity_mismatch")
    observed = data["observed_at_epoch"]
    if (
        type(observed) not in (int, float)
        or not math.isfinite(observed)
        or not 0 <= time.time() - observed <= 1800
    ):
        raise ValueError("health_source_stale_or_future")
    if (
        not isinstance(data["max_age_seconds"], int)
        or isinstance(data["max_age_seconds"], bool)
    ) or data["max_age_seconds"] != 1800:
        raise ValueError("invalid_health_freshness")
    checks = data["checks"]
    if not isinstance(checks, dict) or set(checks) != {"os", "postgresql", "traefik"}:
        raise ValueError("invalid_health_checks")
    for item in checks.values():
        if not isinstance(item, dict) or set(item) != {
            "status",
            "observed",
            "expected",
            "installed_version",
            "running_version",
            "upstream_version",
            "issues",
            "issues_truncated",
        }:
            raise ValueError("invalid_health_check")
        if item["status"] not in ("ok", "warning", "unknown") or any(
            not isinstance(item[k], bool)
            for k in ("observed", "expected", "issues_truncated")
        ):
            raise ValueError("invalid_health_verdict")
        for key in ("installed_version", "running_version", "upstream_version"):
            if item[key] is not None and (
                not isinstance(item[key], str) or len(item[key]) > 160
            ):
                raise ValueError("invalid_health_version")
        if (
            not isinstance(item["issues"], list)
            or len(item["issues"]) > 20
            or any(not isinstance(i, str) or len(i) > 160 for i in item["issues"])
        ):
            raise ValueError("invalid_health_issues")
    apt = data["apt"]
    if (
        not isinstance(apt, dict)
        or set(apt) != {"status", "indexes_fresh", "pending_security_count"}
        or apt["status"] not in ("ok", "unknown")
        or not isinstance(apt["indexes_fresh"], bool)
    ):
        raise ValueError("invalid_health_apt")
    count = apt["pending_security_count"]
    if (
        count is not None
        and ((not isinstance(count, int) or isinstance(count, bool)) or count < 0)
    ) or (apt["status"] == "ok" and count is None):
        raise ValueError("invalid_health_security_count")
    return data


def related_unit_names(spec):
    names = spec.get("related_units", [])
    if (
        not isinstance(names, list)
        or len(names) > 32
        or any(
            not isinstance(name, str)
            or len(name) > 200
            or not re.fullmatch(r"[a-zA-Z0-9_.@-]+\.service", name)
            for name in names
        )
        or len(set(names)) != len(names)
        or spec.get("unit") in names
    ):
        raise ValueError("invalid related units")
    return names


def application(spec, pkg_rows, package_status="ok", host=None, unit_observation=None):
    result = {
        "id": spec["id"],
        "coverage": [],
        "components": [],
        "running_version": None,
    }
    for field in ("path", "venv"):
        if field in spec and (
            not Path(spec[field]).is_absolute() or ".." in Path(spec[field]).parts
        ):
            raise ValueError("invalid application path")
    if spec.get("unit"):
        unit = spec["unit"]
        if not re.fullmatch(r"[a-zA-Z0-9_.@-]+\.service", unit):
            raise ValueError("invalid unit")
        props = command(
            ["systemctl", "show", unit, "--property=LoadState,ActiveState,MainPID"]
        )
        props = dict(line.split("=", 1) for line in props.splitlines() if "=" in line)
        result["presence"] = (
            "absent" if props.get("LoadState") == "not-found" else "installed"
        )
        result["runtime"] = props.get("ActiveState", "unknown")
    names = related_unit_names(spec)
    if names:
        # Bind only the already-collected unit inventory; no additional commands.
        observation = unit_observation or {"status": "unsupported", "items": []}
        status = observation["status"]
        states = (
            {row["name"]: row["state"] for row in observation["items"]}
            if status == "ok"
            else {}
        )
        result["related_units"] = {
            "status": status,
            "items": [
                {
                    "name": name,
                    "state": (
                        states.get(name, "not-observed")
                        if status == "ok"
                        else "unknown"
                    ),
                }
                for name in names
            ],
        }
        if status != "ok":
            result["coverage"].append("related_units:host_probe_unavailable")
        else:
            result["coverage"].extend(
                f"related_units:{name}:not_observed"
                for name in names
                if name not in states
            )
    if spec.get("packages"):
        if package_status != "ok":
            result["coverage"].append("packages:host_probe_unavailable")
        result["components"] = [
            r for r in pkg_rows if r["name"].split(":")[0] in spec["packages"]
        ]
        primary = next(
            (
                p
                for p in result["components"]
                if p["name"].split(":")[0] == spec.get("primary_package")
            ),
            None,
        )
        if primary:
            result["installed_version"] = primary["version"]
        else:
            result["coverage"].append("installed_version:unknown")
        # Cached package candidates are evidence, not an index refresh.
        candidates = []
        for name in spec["packages"]:
            if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name):
                raise ValueError("invalid package")
            policy = command(["apt-cache", "policy", name])
            installed = re.search(r"Installed: (\S+)", policy)
            candidate = re.search(r"Candidate: (\S+)", policy)
            if (
                installed
                and candidate
                and installed[1] != "(none)"
                and candidate[1] != "(none)"
            ):
                newer = (
                    subprocess.run(
                        [
                            "dpkg",
                            "--compare-versions",
                            candidate[1],
                            "gt",
                            installed[1],
                        ],
                        check=False,
                        capture_output=True,
                    ).returncode
                    == 0
                )
                candidates.append(
                    {
                        "name": name,
                        "installed": installed[1],
                        "candidate": candidate[1],
                        "update_available": newer,
                    }
                )
        result["package_candidates"] = candidates
    for field, fn in [("path", git_checkout), ("venv", python_packages)]:
        if field in spec:
            observation = category(lambda fn=fn, field=field: fn(spec[field]))
            result["git" if field == "path" else "python"] = observation
            if observation["status"] != "ok":
                result["coverage"].append(f"{field}:unreadable_or_missing")
    if "software_health" in spec:
        if not isinstance(spec["software_health"], bool):
            raise ValueError("software_health must be boolean")
        if spec["software_health"]:
            observation = category(lambda: software_health(host))
            result["software_health"] = observation
            if observation["status"] != "ok":
                result["coverage"].append("software_health:unavailable")
    if spec.get("version_probe"):
        observation = category(lambda: media_version(spec["version_probe"]))
        if observation["status"] == "ok":
            result.update(observation["items"])
        else:
            result["coverage"].append("installed_version:unknown")
            if spec["version_probe"] in ("snappymail", "postfixadmin"):
                result["version_probe_error"] = observation.get(
                    "error", observation["status"]
                )
    return result


def mac_packages():
    brew = next(
        (
            p
            for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew")
            if Path(p).exists()
        ),
        None,
    )
    if not brew:
        raise UnsupportedProbe("homebrew unavailable")
    env = dict(os.environ, HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1")
    # Root cannot run brew; use read-only cellar receipts instead on that transport.
    if os.geteuid() == 0:
        prefix = str(Path(brew).parents[1])
        return [
            {"name": p.parent.parent.name, "version": p.parent.name, "kind": "brew"}
            for p in Path(prefix, "Cellar").glob("*/*/INSTALL_RECEIPT.json")
        ]
    data = json.loads(command([brew, "info", "--json=v2", "--installed"], env=env))
    return [
        {"name": p["name"], "version": i["version"], "kind": "brew"}
        for p in data["formulae"]
        for i in p["installed"]
    ] + [
        {"name": p["token"], "version": p.get("installed"), "kind": "cask"}
        for p in data.get("casks", [])
    ]


def mac_apps(roots):
    result = []
    for root in roots:
        base = Path(root)
        if not base.exists():
            continue
        for app in sorted(base.glob("*.app/Contents/Info.plist")):
            with app.open("rb") as handle:
                data = plistlib.load(handle)
            result.append(
                {
                    "name": app.parents[1].stem,
                    "version": data.get("CFBundleShortVersionString"),
                    "build": data.get("CFBundleVersion"),
                    "kind": "app",
                    "path": str(app.parents[1]),
                }
            )
    return result


def mac_jobs():
    return [
        {"name": parts[2], "state": "running" if parts[0] != "-" else "not-running"}
        for line in command(["launchctl", "list"]).splitlines()[1:]
        if len(parts := line.split()) == 3
    ]


def validate_policy(policy):
    if not isinstance(policy, dict):
        raise TypeError("policy object required")
    if not isinstance(policy.get("host"), str) or not policy["host"]:
        raise ValueError("host required")
    if not isinstance(policy.get("preserve_partial_applications", False), bool):
        raise ValueError("preserve_partial_applications must be a boolean")
    applications = policy.get("applications", [])
    if not isinstance(applications, list):
        raise ValueError("applications must be a list")
    identifiers = set()
    for app in applications:
        if (
            not isinstance(app, dict)
            or not isinstance(app.get("id"), str)
            or not app["id"].strip()
        ):
            raise ValueError("non-empty application id required")
        if app["id"] in identifiers:
            raise ValueError("duplicate application id")
        identifiers.add(app["id"])
        related_unit_names(app)


def collect(policy):
    validate_policy(policy)
    started = time.time()
    is_linux = platform.system() == "Linux"
    observations = {
        "packages": category(packages if is_linux else mac_packages),
        "services": category(units if is_linux else mac_jobs),
        "containers": (
            category(containers) if is_linux else {"status": "unsupported", "items": []}
        ),
    }
    gaps = [
        "dependency_graph:partial",
        "unregistered_application_paths:not_scanned",
        "running_versions:partial",
    ]
    if not is_linux:
        observations["application_bundles"] = category(
            lambda: mac_apps(
                policy.get(
                    "application_roots", ["/Applications", "/System/Applications"]
                )
            )
        )
        gaps += [
            "launchd:current_bootstrap_only",
            "homebrew_updates:not_compared",
            "macos_updates:not_compared",
        ]
        if os.geteuid() == 0:
            gaps.append("homebrew_casks:use_application_bundle_inventory")
    apps = []
    for spec in policy.get("applications", []):
        item = category(
            lambda spec=spec: application(
                spec,
                observations["packages"]["items"],
                observations["packages"]["status"],
                host=policy["host"],
                unit_observation=observations["services"],
            )
        )
        apps.append({"id": spec["id"], **item})
    release = {}
    if is_linux:
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    if key in ("ID", "VERSION_ID", "PRETTY_NAME"):
                        release[key] = value.strip('"')
        # Preserve Python 3.10 syntax despite the controller's Python 3.14 formatter.
        except (OSError, UnicodeDecodeError):  # fmt: skip
            gaps.append("os_release:unreadable_or_missing")
    return {
        "schema_version": SCHEMA,
        "host": policy["host"],
        "observed_at": started,
        "collector": "software-estate/1",
        "policy_sha256": hashlib.sha256(
            json.dumps(policy, sort_keys=True).encode()
        ).hexdigest(),
        "platform": platform.system(),
        "os_version": (
            platform.mac_ver()[0] if not is_linux else release.get("VERSION_ID")
        ),
        "kernel_release": platform.release(),
        "os_release": release,
        "categories": observations,
        "applications": apps,
        "gaps": gaps,
        "duration_seconds": round(time.time() - started, 3),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-json", required=True)
    args = parser.parse_args()
    try:
        policy = json.loads(args.policy_json)
        print(json.dumps(collect(policy), sort_keys=True))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(json.dumps({"error": type(exc).__name__}))
        raise SystemExit(1) from None
