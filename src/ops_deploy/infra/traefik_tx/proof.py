"""Isolated native compatibility proof for a Traefik binary update. Requests are trusted operator policy.

The transaction engine's ``binary`` action requires a ``compatibility`` block: the exact
candidate executable and the unchanged static config must have loaded every router in an
isolated start on the host's own architecture, and so must the installed pair (the
baseline). This program makes that proof on the host, as root, with the standard library
only, under ``/usr/bin/python3`` 3.11 or newer, next to ``engine.py``::

    python3 proof.py --request request.json

The request is the engine's: ``policy`` (with ``acme_paths``), ``release.version``,
``release.sha256`` and ``archive_path``. The program holds the transaction lock and reads
the live identity. Into a work directory below ``/var/lib/traefik-update-proofs`` go a
copy of the static config that differs only by ``api.insecure = true``, a copy of the
dynamic tree, copies of the ACME stores and the candidate taken from the checksum-pinned
archive. Each pair, the installed executable first, then the candidate, starts in its
own transient systemd unit with ``PrivateNetwork=yes`` and a read-only file system; the
copies are bound over their live paths, the dynamic tree read-only, the ACME stores and
log directories writable (the unit's own copies), so nothing live is read for routing or
written. Inside the unit this same program starts Traefik, reads ``/api/rawdata`` once
the routers settle and stops it.

A pair passes when the API answered, the routers settled while Traefik kept running,
every router is ``enabled`` and the ``@file`` routers are exactly the ones the dynamic
files define. The proof passes when both pairs pass, they loaded the same routers and
the live identity did not change meanwhile. It is written once, as
``/var/lib/traefik-update-proofs/<version>-<YYYYMMDD>-<host>.json`` (``-2``, ``-3`` ... when
taken), and printed. Exit 0: passed; 1: the proof ran and failed (``passed`` false);
2: refused or an error before a proof existed, with ``error`` and no file.
:func:`compatibility` turns a passed proof into the engine's ``compatibility`` block.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import fcntl
import ipaddress
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib
import urllib.request
import uuid
from pathlib import Path
from types import FrameType
from typing import Any

try:
    from . import engine
except ImportError:  # a standalone script on the host, next to engine.py
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import engine  # type: ignore[import-not-found,no-redef]

Refused = engine.Refused
require = engine.require

PROOF_ROOT = Path("/var/lib/traefik-update-proofs")
ISOLATION = "systemd PrivateNetwork and read-only bind mounts"
OVERRIDE = "api.insecure=true only"
GOARCH = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
# Traefik's file provider reads these from the directory and its subdirectories.
DYNAMIC_SUFFIXES = (".toml", ".yaml", ".yml")
# API section per router kind.
KINDS = {"http": "routers", "tcp": "tcpRouters", "udp": "udpRouters"}
# What ProtectSystem=strict leaves writable (the API file systems); /tmp and /var/tmp are private.
WRITABLE_IN_UNIT = (Path("/dev"), Path("/proc"), Path("/sys"))
SAFE_PATH = re.compile(r"/[A-Za-z0-9._@+/-]*")
API_HEADER = re.compile(r"^[ \t]*\[api\][ \t]*(?:#.*)?$", re.MULTILINE)
YAML_KEY = re.compile(r"""(?P<key>[A-Za-z0-9_][A-Za-z0-9_.@-]*|"[^"\\]*"|'[^']*')[ ]*:(?:[ ]+(?P<value>.*))?""")
UNIT_MAX_SEC = 150  # the transient unit's hard limit
DEADLINE = 90  # seconds Traefik gets to load every router
SETTLE = 5  # router statuses unchanged this long: loaded (the file provider throttles 2 s)
PATIENCE = 20  # unchanged this long although defined routers are missing: give up waiting


Router = tuple[str, str]  # (kind, name with provider): kinds keep their own namespaces


def qualified(router: Router) -> str:
    """How a router is shown: HTTP names plain, others (and HTTP names with ``:``) prefixed by kind."""

    kind, name = router
    return name if kind == "http" and ":" not in name else f"{kind}:{name}"


def isolated_config(text: str) -> tuple[str, str | None]:
    """The static config with ``api.insecure = true`` and the override made (``None``: already set).

    The text is edited, not re-serialized, and the result must parse to the original plus
    that one key; a layout this cannot edit with certainty is refused.
    """

    original = tomllib.loads(text)
    api = original.get("api")
    if isinstance(api, dict) and api.get("insecure") is True:
        return text, None
    require(
        api is None or (isinstance(api, dict) and "insecure" not in api),
        "unsupported api.insecure setting for the isolation override",
    )
    if api is None:
        candidate = text + ("\n" if text and not text.endswith("\n") else "") + "\n[api]\n  insecure = true\n"
    else:
        headers = list(API_HEADER.finditer(text))
        require(len(headers) == 1, "unsupported [api] table for the isolation override")
        end = headers[0].end()
        candidate = text[:end] + "\n  insecure = true" + text[end:]
    expected = copy.deepcopy(original)
    expected.setdefault("api", {})["insecure"] = True
    require(tomllib.loads(candidate) == expected, "the isolation override must change api.insecure only")
    return candidate, OVERRIDE


def split_address(address: Any, name: str) -> tuple[str, int]:
    require(isinstance(address, str) and address, f"entrypoint without an address: {name}")
    host, separator, port = address.split("/")[0].rpartition(":")
    require(separator and port.isdigit() and 0 < int(port) < 65536, f"unsupported address of entrypoint {name}")
    return host.strip("[]"), int(port)


def is_local(host: str) -> bool:
    if host in ("", "0.0.0.0", "::", "localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def api_url(static: dict[str, Any]) -> str:
    """Where the isolated API answers; every entrypoint must be able to listen in an empty network."""

    entrypoints = static.get("entryPoints", {})
    require(isinstance(entrypoints, dict), "unsupported entryPoints")
    for name, entrypoint in entrypoints.items():
        require(isinstance(entrypoint, dict), f"unsupported entrypoint {name}")
        host, _ = split_address(entrypoint.get("address"), name)
        require(is_local(host), f"entrypoint {name} listens on an address an isolated network does not have")
    # api.insecure serves the API on the traefik entrypoint, :8080 unless it is defined.
    traefik = entrypoints.get("traefik")
    host, port = split_address(":8080" if traefik is None else traefik.get("address"), "traefik")
    if host in ("", "0.0.0.0", "::", "localhost"):
        host = "127.0.0.1"
    base = static.get("api", {}).get("basePath", "/")
    require(isinstance(base, str) and SAFE_PATH.fullmatch(base), "unsupported api.basePath")
    shown = f"[{host}]" if ":" in host else host
    return f"http://{shown}:{port}{base.rstrip('/')}/api/rawdata"


def safe_path(value: Any, what: str) -> Path:
    require(
        isinstance(value, str) and SAFE_PATH.fullmatch(value) and ".." not in Path(value).parts, f"unsupported {what}"
    )
    return Path(value)


def log_dirs(static: dict[str, Any], keep: list[Path]) -> list[Path]:
    """Directories of the log files; the unit gets empty writable ones in their place."""

    dirs: set[Path] = set()
    for section in ("log", "accessLog"):
        settings = static.get(section)
        if isinstance(settings, dict) and settings.get("filePath"):
            parent = safe_path(settings["filePath"], f"{section}.filePath").parent
            require(parent.is_dir() and not parent.is_symlink(), f"{section}.filePath directory is absent")
            require(
                parent != Path("/") and not any(path == parent or parent in path.parents for path in keep),
                f"{section}.filePath directory would hide configuration",
            )
            dirs.add(parent)
    return sorted(dirs)


def acme_stores(static: dict[str, Any], policy: dict[str, Any], cwd: Path) -> list[Path]:
    """The existing approved ACME stores; every store a resolver names must be one of them."""

    approved = [safe_path(path, "acme_paths entry") for path in policy.get("acme_paths", [])]
    resolvers = static.get("certificatesResolvers", {})
    require(isinstance(resolvers, dict), "unsupported certificatesResolvers")
    for name, resolver in resolvers.items():
        acme = resolver.get("acme") if isinstance(resolver, dict) else None
        if isinstance(acme, dict):
            store = cwd / acme.get("storage", "acme.json")
            require(store in approved, f"ACME store of resolver {name} is not an approved acme_paths entry")
    for path in approved:
        # A symlink anywhere in the path (a dangling leaf included) could lead into a writable tree.
        require(os.path.realpath(path) == str(path), f"ACME store path is not canonical: {path}")
        require(not path.exists() or path.is_file(), f"ACME store is not a file: {path}")
        # An absent store stays unbound; Traefik must not be able to create it there.
        require(
            path.exists() or not any(tree == path or tree in path.parents for tree in WRITABLE_IN_UNIT),
            f"absent ACME store would be writable in the unit: {path}",
        )
    return [path for path in approved if path.exists()]


def yaml_routers(text: str, name: str) -> set[Router]:
    """Router names in a block-style YAML dynamic file; what this cannot read with certainty is refused.

    Only the keys at ``<kind>:``, ``<kind>.routers:`` and the names below them are read;
    deeper content and other sections are skipped by indentation.
    """

    found: set[Router] = set()
    stack: list[tuple[int, str]] = []
    seen = False  # a document start marker may only precede the first key
    for number, line in enumerate(text.splitlines(), 1):
        content = line.strip()
        if not content or content.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        unsupported = f"unsupported YAML in {name}, line {number}"
        require(line[indent] != "\t", unsupported)
        if content == "---" and not seen:
            seen = True
            continue
        seen = True
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = [key for _, key in stack]
        level = len(path)
        if level > 2 or (level >= 1 and path[0] not in KINDS) or (level == 2 and path[1] != "routers"):
            continue
        require(content not in ("---", "...") and not content.startswith(("- ", "? ")) and content != "-", unsupported)
        match = YAML_KEY.fullmatch(content)
        require(match, unsupported)
        assert match is not None
        key, value = match["key"].strip("\"'"), (match["value"] or "").strip()
        require(key != "<<", unsupported)
        if value.startswith("#"):
            value = ""
        if level == 2:
            found.add((path[0], f"{key}@file"))
        elif (level == 0 and key in KINDS) or (level == 1 and key == "routers"):
            require(value in ("", "{}"), unsupported)
        stack.append((indent, key))
    return found


def defined_routers(root: Path) -> set[Router]:
    """``@file`` routers the dynamic tree defines (TOML parsed, YAML scanned)."""

    names: set[Router] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in DYNAMIC_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        relative = str(path.relative_to(root))
        if path.suffix.lower() == ".toml":
            data = tomllib.loads(text)
            for kind in KINDS:
                routers = data.get(kind, {}).get("routers", {}) if isinstance(data.get(kind), dict) else {}
                require(isinstance(routers, dict), f"unsupported routers in {relative}")
                names.update((kind, f"{router}@file") for router in routers)
        else:
            names.update(yaml_routers(text, relative))
    return names


def native(binary: Path) -> None:
    machine = os.uname().machine
    match = re.search(r"^OS/Arch:\s+(\S+)\s*$", engine.run([str(binary), "version"]), re.MULTILINE)
    require(
        machine in GOARCH and match is not None and match.group(1) == f"linux/{GOARCH[machine]}",
        f"not a native build for {machine}: {binary.name}",
    )


def unit_argv(unit: str, workdir: Path, spec: Path, mounts: dict[str, list[tuple[Path, Path]]], cwd: Path) -> list[str]:
    """``systemd-run`` for one isolated start; ``mounts`` maps ``BindReadOnlyPaths``/``BindPaths`` to pairs."""

    properties = [
        "PrivateNetwork=yes",
        "ProtectSystem=strict",
        "PrivateTmp=yes",
        "NoNewPrivileges=yes",
        f"RuntimeMaxSec={UNIT_MAX_SEC}",
        f"WorkingDirectory={cwd}",
        f"ReadWritePaths={spec.parent}",
    ]
    for kind in ("BindReadOnlyPaths", "BindPaths"):
        properties += [f"{kind}={source}:{target}" for source, target in mounts.get(kind, [])]
    argv = ["systemd-run", "--quiet", "--wait", "--collect", "--service-type=exec", f"--unit={unit}"]
    for item in properties:
        argv += ["-p", item]
    return [*argv, "--", "/usr/bin/python3", "-I", str(workdir / "proof.py"), "--inside", str(spec)]


def statuses(raw: dict[str, Any]) -> dict[Router, str]:
    found: dict[Router, str] = {}
    for kind, section in KINDS.items():
        routers = raw.get(section) or {}
        require(isinstance(routers, dict), "unexpected API answer")
        for name, router in routers.items():
            found[(kind, name)] = router.get("status", "") if isinstance(router, dict) else ""
    return found


def observe(process: subprocess.Popen[bytes], spec: dict[str, Any]) -> dict[str, Any]:
    """Poll the API until the router statuses settle, Traefik exits or the deadline passes."""

    url, expected = spec["api"], {(kind, name) for kind, name in spec["expected"]}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    start = time.monotonic()
    last: dict[Router, str] | None = None
    since = start
    raw: dict[str, Any] | None = None
    while time.monotonic() - start < spec["deadline"]:
        if process.poll() is not None:
            return {"api_reachable": raw is not None, "stable": False, "exited": process.returncode, "rawdata": raw}
        try:
            with opener.open(url, timeout=2) as response:
                answer = json.load(response)
            require(isinstance(answer, dict), "unexpected API answer")
            raw, current = answer, statuses(answer)
        except (OSError, ValueError, Refused):
            time.sleep(0.5)
            continue
        now = time.monotonic()
        if current != last:
            last, since = current, now
        elif now - since >= (spec["settle"] if expected <= set(current) else spec["patience"]):
            return {"api_reachable": True, "stable": True, "exited": None, "rawdata": raw}
        time.sleep(0.5)
    return {"api_reachable": raw is not None, "stable": False, "exited": None, "rawdata": raw}


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def inside(spec_path: Path) -> int:
    """In the isolated unit: start one pair, observe it, stop it, leave ``result.json`` next to the spec."""

    spec = json.loads(spec_path.read_text())
    out = spec_path.parent
    with (out / "traefik.log").open("wb") as log:
        process = subprocess.Popen(
            [spec["binary"], f"--configFile={spec['config']}"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        try:
            result = observe(process, spec)
        finally:
            stop(process)
    (out / "result.json").write_text(json.dumps(result))
    return 0


def pair(result: dict[str, Any], expected: set[Router]) -> dict[str, Any]:
    """What one isolated start loaded, against the routers the dynamic files define."""

    found = statuses(result.get("rawdata") or {})
    loaded = {router for router in found if router[1].endswith("@file")}
    summary: dict[str, Any] = {
        "router_count": len(found),
        "disabled": sorted(qualified(router) for router, status in found.items() if status != "enabled"),
        "missing": sorted(qualified(router) for router in expected - loaded),
        "unexpected": sorted(qualified(router) for router in loaded - expected),
        "api_reachable": result.get("api_reachable") is True,
    }
    summary["passed"] = bool(
        summary["api_reachable"]
        and result.get("stable") is True
        and result.get("exited") is None
        and loaded
        and not (summary["disabled"] or summary["missing"] or summary["unexpected"])
    )
    summary["routers"] = sorted(found)
    return summary


def build_proof(
    policy: dict[str, Any],
    release: dict[str, Any],
    live: dict[str, Any],
    run: dict[str, Any],
) -> dict[str, Any]:
    """The proof record; the first nine keys are the 2026-09 proof format, unchanged."""

    candidate, baseline = run["candidate"], run["baseline"]
    same = candidate["routers"] == baseline["routers"]
    error = run.get("error")
    return {
        "host": policy["host"],
        "version": release["version"],
        "architecture": run["architecture"],
        "candidate_binary_sha256": run["candidate_binary_sha256"],
        "live_config_sha256": live["config_sha256"],
        "router_count": candidate["router_count"],
        "disabled": candidate["disabled"],
        "api_reachable": candidate["api_reachable"],
        "isolation_override": run["isolation_override"],
        "missing": candidate["missing"],
        "unexpected": candidate["unexpected"],
        "same_routers_as_baseline": same,
        "baseline_pair": {
            "version": live["version"],
            "binary_sha256": live["binary_sha256"],
            **{key: baseline[key] for key in ("router_count", "disabled", "missing", "unexpected", "api_reachable")},
        },
        "passed": bool(candidate["passed"] and baseline["passed"] and same and error is None),
        "baseline_pair_passed": bool(baseline["passed"] and error is None),
        "baseline": live,
        "isolation": ISOLATION,
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
        "report_reference": run["report_reference"],
        "error": error,
    }


def compatibility(proof: dict[str, Any], live: dict[str, Any]) -> dict[str, Any]:
    """The engine's ``compatibility`` block from a passed proof of exactly this live identity."""

    require(proof.get("passed") is True and proof.get("baseline_pair_passed") is True, "compatibility proof failed")
    require(
        proof.get("baseline") == live and proof.get("live_config_sha256") == live["config_sha256"],
        "compatibility proof is for another live identity",
    )
    return {
        "baseline": live,
        "architecture": proof["architecture"],
        "candidate_binary_sha256": proof["candidate_binary_sha256"],
        "candidate_config_sha256": proof["live_config_sha256"],
        "passed": True,
        "baseline_pair_passed": True,
        "report_reference": proof["report_reference"],
    }


def report_path(release: dict[str, Any], host: str, now: datetime.datetime) -> list[Path]:
    stem = f"{release['version']}-{now:%Y%m%d}-{host}"
    return [PROOF_ROOT / f"{stem}.json"] + [PROOF_ROOT / f"{stem}-{n}.json" for n in range(2, 100)]


def write_once(path: Path, data: bytes) -> None:
    """``path`` gets ``data``, complete or not at all; an existing file is never overwritten."""

    temporary = PROOF_ROOT / f".tmp-{uuid.uuid4()}"
    engine.atomic(temporary, data)
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink()


def stop_units(run_id: str) -> None:
    for variant in ("baseline", "candidate"):
        subprocess.run(
            ["systemctl", "stop", f"traefik-proof-{run_id}-{variant}.service"],
            capture_output=True,
            timeout=60,
            check=False,
        )


def interrupted(signum: int, frame: FrameType | None) -> None:
    raise Refused(f"interrupted by signal {signum}")


def prepare_root() -> None:
    PROOF_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = PROOF_ROOT.stat()
    require(
        not PROOF_ROOT.is_symlink() and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
        "unsafe proof directory",
    )
    # Left behind by an interrupted proof; the lock is held, so nothing uses them.
    for stale in sorted(PROOF_ROOT.glob(".work-*")):
        stop_units(stale.name.removeprefix(".work-"))
        shutil.rmtree(stale)
    for stale in PROOF_ROOT.glob(".tmp-*"):
        stale.unlink()


def isolated_start(
    variant: str,
    binary: Path,
    workdir: Path,
    run_id: str,
    mounts: dict[str, list[tuple[Path, Path]]],
    cwd: Path,
    spec: dict[str, Any],
) -> dict[str, Any]:
    """One pair in its transient unit; the unit's ``result.json``."""

    out = workdir / f"out-{variant}"
    out.mkdir(mode=0o700)
    spec_path = out / "spec.json"
    engine.save(spec_path, {"binary": str(binary), **spec})
    argv = unit_argv(f"traefik-proof-{run_id}-{variant}", workdir, spec_path, mounts, cwd)
    engine.run(argv, timeout=UNIT_MAX_SEC + 60)
    result: dict[str, Any] = json.loads((out / "result.json").read_text())
    return result


def run_proof(request: dict[str, Any]) -> dict[str, Any]:
    policy, release = request["policy"], request["release"]
    engine.validate_policy(policy)
    require(re.fullmatch(r"3\.\d+\.\d+", str(release["version"])), "unsupported release")
    archive = safe_path(request["archive_path"], "archive_path")
    require(os.geteuid() == 0, "root is required")
    with engine.LOCK.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("transaction lock held") from None
        prepare_root()
        started = datetime.datetime.now(datetime.UTC)
        live = engine.identity(policy)
        static_text = Path(policy["config_path"]).read_text()
        static = tomllib.loads(static_text)
        config_text, override = isolated_config(static_text)
        url = api_url(static)
        cwd = working_directory()
        dynamic = Path(policy["dynamic_path"])
        stores = acme_stores(static, policy, cwd)
        logs = log_dirs(static, [dynamic, *stores])
        run_id = uuid.uuid4().hex[:12]
        workdir = PROOF_ROOT / f".work-{run_id}"
        workdir.mkdir(mode=0o700)
        try:
            shutil.copy2(Path(__file__).resolve(), workdir / "proof.py")
            shutil.copy2(Path(engine.__file__).resolve(), workdir / "engine.py")
            config = workdir / "traefik.toml"
            engine.atomic(config, config_text.encode())
            shutil.copytree(dynamic, workdir / "dynamic", symlinks=True)
            require(engine.inventory_tree(workdir / "dynamic") == live["dynamic_sha256"], "dynamic copy differs")
            expected = defined_routers(workdir / "dynamic")
            mounts: dict[str, list[tuple[Path, Path]]] = {"BindReadOnlyPaths": [(workdir / "dynamic", dynamic)]}
            for index, store in enumerate(stores):
                shutil.copy2(store, workdir / f"acme-{index}")
                mounts.setdefault("BindPaths", []).append((workdir / f"acme-{index}", store))
            for index, directory in enumerate(logs):
                (workdir / f"log-{index}").mkdir(mode=0o700)
                mounts.setdefault("BindPaths", []).append((workdir / f"log-{index}", directory))
            installed = Path(policy["binary_path"])
            candidate = engine.candidate_binary(archive, release["sha256"], workdir, release["version"])
            native(installed)
            native(candidate)
            spec = {
                "config": str(config),
                "api": url,
                "expected": [list(router) for router in sorted(expected)],
                "deadline": DEADLINE,
                "settle": SETTLE,
                "patience": PATIENCE,
            }
            results = {
                variant: pair(isolated_start(variant, binary, workdir, run_id, mounts, cwd, spec), expected)
                for variant, binary in (("baseline", installed), ("candidate", candidate))
            }
            error = None if engine.identity(policy) == live else "live identity changed during the proof"
            # Linked under exactly this name; the lock keeps another proof from taking it.
            target = next((path for path in report_path(release, policy["host"], started) if not path.exists()), None)
            require(target is not None, "no free proof file name for today")
            assert target is not None
            run = {
                **results,
                "architecture": os.uname().machine,
                "candidate_binary_sha256": engine.digest(candidate),
                "isolation_override": override,
                "started_at": started.isoformat(timespec="seconds"),
                "finished_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
                "error": error,
            }
            run["report_reference"] = str(target)
            proof = build_proof(policy, release, live, run)
            write_once(target, (json.dumps(proof, indent=2) + "\n").encode())
            return proof
        finally:
            stop_units(run_id)
            shutil.rmtree(workdir, ignore_errors=True)


def working_directory() -> Path:
    """The live unit's working directory, which relative ACME stores resolve against."""

    value = engine.run(["systemctl", "show", "traefik.service", "-p", "WorkingDirectory", "--value"]).strip()
    return safe_path(value or "/", "WorkingDirectory of traefik.service")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Isolated native compatibility proof for a Traefik binary update.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--request", type=Path)
    group.add_argument("--inside", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.inside is not None:
        return inside(args.inside)
    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        proof = run_proof(json.loads(args.request.read_text()))
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"failed": True, "error": str(exc)}))
        return 2
    print(json.dumps(proof))
    return 0 if proof["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
