#!/usr/bin/env python3
"""Read-only, stdlib-only software discovery. Input is a JSON policy argument."""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import signal
import subprocess
import tempfile
import time
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


def media_version(kind):
    # Dedicated known probes only; no arbitrary executable paths from policy.
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


def application(spec, pkg_rows, package_status="ok"):
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
    if spec.get("version_probe"):
        observation = category(lambda: media_version(spec["version_probe"]))
        if observation["status"] == "ok":
            result.update(observation["items"])
        else:
            result["coverage"].append("installed_version:unknown")
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


def collect(policy):
    validate_policy(policy)
    started = time.time()
    is_linux = platform.system() == "Linux"
    observations = {
        "packages": category(packages if is_linux else mac_packages),
        "services": category(units if is_linux else mac_jobs),
        "containers": category(containers)
        if is_linux
        else {"status": "unsupported", "items": []},
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
        "os_version": platform.mac_ver()[0]
        if not is_linux
        else release.get("VERSION_ID"),
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
