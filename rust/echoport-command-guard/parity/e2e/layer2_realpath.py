#!/usr/bin/env python3
"""Layer 2, filesystem part (PLAN.md 7.5): the Rust guard's real GuardEnv
against CPython on real trees, inside the distribution containers.

Runs as root inside ``parity/e2e/Dockerfile`` (Ubuntu 24.04 with Python
3.12, Debian 13 with Python 3.13), with the users of the policies. It builds
real trees under the policies' path roots and private media path, then asks
the Rust probe (``examples/env-probe.rs``, ``RealEnv``) and this Python the
same questions and compares:

- ``realpath``: the Rust ``pyrealpath`` against ``os.path.realpath``
  (non-strict). Every probe is a path ``_is_safe_path`` accepts, since that
  is all the guard ever resolves (PLAN.md 3.3.6). A curated case either
  resolves to the same string or is one of the stricter refusals of PLAN.md
  4.2 with its errno; a random case must resolve to the same string unless
  Rust refuses a loop, which an independent resolver (without Python's
  ``seen`` map) must confirm.
- ``lstat``: kind, permission bits, uid and link count, or absent, or the
  same errno and ``strerror`` text (the text goes into refusal reasons).
- ``uid_of`` against ``pwd.getpwnam`` (NSS), ``euid`` against
  ``os.geteuid``.

A curated EACCES case runs the probe and Python as ``nobody``.

Usage (``parity/e2e/run-layer2.sh`` does this)::

    python3 -I layer2_realpath.py --probe /usr/local/bin/env-probe [--random 300] [--seed 1]
    python3 -I layer2_realpath.py --probe ... --probe-name soft-canonicalize --realpath-only

Exits 1 on any difference that PLAN.md 4.2 does not allow. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import random
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
KIND = {
    stat.S_IFREG: "reg",
    stat.S_IFDIR: "dir",
    stat.S_IFLNK: "lnk",
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "sock",
    stat.S_IFCHR: "chr",
    stat.S_IFBLK: "blk",
}
# The policies' path roots and private media path (fixtures/policies/).
ROOTS = {
    "/var/lib/gotosocial": "gotosocial",
    "/home/marina/site": "marina",
    "/home/villakunterbunt/data": "villakunterbunt",
    "/home/python-podcast/site/private_media": "python-podcast",
}
USERS = ["root", "postgres", "gotosocial", "marina", "villakunterbunt", "python-podcast", "nobody",
         "echoport-no-such-user"]
RANDOM_BASE = "/srv/echoport-l2-random"


def is_safe_path(path: str) -> bool:
    """``_is_safe_path`` (guard.py:203-206)."""
    if not SAFE_PATH_RE.match(path):
        return False
    return all(part not in ("", ".", "..") for part in path.rstrip("/").split("/")[1:])


class Probe:
    """The Rust probe as a JSON-lines server."""

    def __init__(self, argv: list[str]) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def ask(self, request: dict[str, Any]) -> dict[str, Any]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(f"the probe exited (status {self.proc.wait()})")
        answer = json.loads(line)
        if "bad_request" in answer:
            raise RuntimeError(f"the probe refused {request}: {answer}")
        return answer

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        self.proc.wait()


def py_realpath(path: str) -> dict[str, Any]:
    try:
        return {"resolved": os.path.realpath(path)}
    except OSError as exc:  # 3.12 lets a readlink error through
        return {"error": {"errno": _errno_name(exc.errno), "strerror": exc.strerror}}


def py_lstat(path: str) -> dict[str, Any]:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"absent": True}
    except OSError as exc:
        return {"error": {"errno": _errno_name(exc.errno), "strerror": exc.strerror}}
    return {"stat": {"kind": KIND[stat.S_IFMT(st.st_mode)], "mode": stat.S_IMODE(st.st_mode),
                     "uid": st.st_uid, "nlink": st.st_nlink}}


def py_uid_of(name: str) -> dict[str, Any]:
    try:
        return {"uid": pwd.getpwnam(name).pw_uid}
    except KeyError:
        return {"uid": None}


def _errno_name(code: int | None) -> str:
    import errno

    return errno.errorcode.get(code or 0, "?")


MAX_LINKS = 40  # pyrealpath::MAX_LINKS, Linux's MAXSYMLINKS


def naive_realpath(path: str, budget: int = 10_000) -> tuple[str, int] | None:
    """Python's non-strict resolution without its ``seen`` map, following at
    most ``budget`` links: the path and the symlink traversals it took (every
    link followed counts, as in the kernel), or ``None`` when the resolution
    does not end."""
    stack = path.split("/")[::-1]
    resolved = "/"
    links = 0
    while stack:
        name = stack.pop()
        if not name or name == ".":
            continue
        if name == "..":
            resolved = resolved[:resolved.rindex("/")] or "/"
            continue
        newpath = resolved + name if resolved == "/" else resolved + "/" + name
        try:
            is_link = stat.S_ISLNK(os.lstat(newpath).st_mode)
        except OSError:
            is_link = False
        if not is_link:
            resolved = newpath
            continue
        links += 1
        if links > budget:
            return None
        target = os.readlink(newpath)
        if target.startswith("/"):
            resolved = "/"
        stack.extend(target.split("/")[::-1])
    return resolved, links


def is_eloop(path: str) -> bool:
    """Whether an ELOOP refusal is right: a loop, or more than 40 traversals."""
    naive = naive_realpath(path)
    return naive is None or naive[1] > MAX_LINKS


# --- trees ----------------------------------------------------------------------


def reset(path: str) -> None:
    if os.path.lexists(path):
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)


def make_roots() -> None:
    for root, user in ROOTS.items():
        reset(root)
        os.makedirs(root, mode=0o755)
        entry = pwd.getpwnam(user)
        os.chown(root, entry.pw_uid, entry.pw_gid)


def link(target: str | bytes, path: str) -> None:
    os.symlink(target, path)


def build_curated() -> list[dict[str, Any]]:
    """The scenarios of PLAN.md 7.5 for realpath, with what is expected.

    ``expect`` is ``same`` (Rust resolves like Python) or the errno of a
    PLAN.md 4.2 refusal (Rust refuses, Python returns a path).
    """
    make_roots()
    site = "/home/marina/site"
    gts = "/var/lib/gotosocial"
    media = "/home/python-podcast/site/private_media"
    os.makedirs(f"{site}/media/2026", exist_ok=True)
    with open(f"{site}/media/2026/a.jpg", "w") as handle:
        handle.write("x")
    os.makedirs("/srv/elsewhere/deep", exist_ok=True)
    reset("/srv/echoport-l2-long")
    os.makedirs("/srv/echoport-l2-long")

    # Symlinks in and out of a root.
    link("media/2026", f"{site}/in")
    link("/etc", f"{site}/out")
    link("../../../etc/passwd", f"{site}/up")
    link("/home/marina/site/../site/media", f"{site}/abs-dotdot")
    link("/", f"{site}/to-root")
    link("//srv//elsewhere/./deep/", f"{site}/slashes")
    # Dangling links, followed by their text.
    link("/nonexistent/x", f"{site}/dangling")
    link("missing/../../site2", f"{site}/dangling-up")
    link("media/none/../2026", f"{site}/through-missing")
    # Loops.
    link("loop-b", f"{site}/loop-a")
    link("loop-a", f"{site}/loop-b")
    link("self", f"{site}/self")
    link(".", f"{site}/dot")
    link(f"{site}/parent-loop/..", f"{site}/parent-loop")
    # A replaced directory: the media directory is now a link elsewhere.
    os.makedirs(f"{gts}/storage", exist_ok=True)
    os.rename(f"{gts}/storage", f"{gts}/storage.old")
    link("/srv/elsewhere", f"{gts}/storage")
    # A file below which nothing exists (ENOTDIR), a hard link, a fifo.
    with open(f"{gts}/sqlite.db", "w") as handle:
        handle.write("x")
    os.link(f"{gts}/sqlite.db", f"{gts}/sqlite.db.hard")
    os.mkfifo(f"{gts}/fifo")
    link("/dev/null", f"{gts}/devnull")
    # Foreign owner, private and open modes.
    os.makedirs(f"{media}/foreign", exist_ok=True)
    os.chown(f"{media}/foreign", pwd.getpwnam("postgres").pw_uid, 0)
    os.chmod(f"{media}/foreign", 0o700)
    os.makedirs(f"{media}/open", exist_ok=True)
    os.chmod(f"{media}/open", 0o777)
    # 40 and 41 links in a chain.
    for count in (40, 41):
        base = f"/srv/echoport-l2-long/c{count}"
        os.makedirs(base)
        for i in range(count):
            link("/srv/elsewhere" if i + 1 == count else f"{base}/l{i + 1}", f"{base}/l{i}")
    # A link target that is not UTF-8 (Python carries surrogates).
    link(b"\xff/x", f"{site}/not-utf8".encode())
    # A directory only root can search (the EACCES case runs as nobody).
    os.makedirs(f"{site}/closed/inner", exist_ok=True)
    os.chmod(f"{site}/closed", 0o700)

    long_name = "n" * 256
    return [
        {"path": f"{site}/in/a.jpg", "expect": "same"},
        {"path": f"{site}/out/passwd", "expect": "same"},
        {"path": f"{site}/up", "expect": "same"},
        {"path": f"{site}/abs-dotdot/2026/", "expect": "same"},
        {"path": f"{site}/to-root/etc", "expect": "same"},
        {"path": f"{site}/slashes/x", "expect": "same"},
        {"path": f"{site}/dangling", "expect": "same"},
        {"path": f"{site}/dangling/y/z", "expect": "same"},
        {"path": f"{site}/dangling-up/q", "expect": "same"},
        {"path": f"{site}/through-missing", "expect": "same"},
        {"path": f"{site}/media/missing/deeper/", "expect": "same"},
        {"path": "//", "expect": "same"},
        {"path": f"{site}/media/2026//", "expect": "same"},
        {"path": f"{site}/loop-a", "expect": "ELOOP"},
        {"path": f"{site}/loop-b/x", "expect": "ELOOP"},
        {"path": f"{site}/self", "expect": "ELOOP"},
        {"path": f"{site}/parent-loop", "expect": "ELOOP"},
        {"path": f"{gts}/storage/deep/x", "expect": "same"},
        {"path": f"{gts}/storage.old", "expect": "same"},
        {"path": f"{gts}/sqlite.db/x", "expect": "same"},
        {"path": f"{gts}/sqlite.db.hard", "expect": "same"},
        {"path": f"{gts}/fifo", "expect": "same"},
        {"path": f"{gts}/devnull", "expect": "same"},
        {"path": f"{media}/foreign/x", "expect": "same"},
        {"path": f"{media}/open", "expect": "same"},
        {"path": "/srv/echoport-l2-long/c40/l0/deep", "expect": "same"},
        {"path": "/srv/echoport-l2-long/c41/l0/deep", "expect": "ELOOP"},
        # 41 traversals of one cached link: refused, Python resolves.
        {"path": f"{site}/dot" + "/dot" * 40, "expect": "ELOOP"},
        {"path": f"{site}/dot" + "/dot" * 39, "expect": "same"},
        {"path": f"{site}/{long_name}/x", "expect": "ENAMETOOLONG"},
        {"path": f"{site}/not-utf8", "expect": "EILSEQ"},
        {"path": f"{site}/closed/inner/x", "expect": "same"},
        {"path": f"{site}/closed/inner/x", "expect": "EACCES", "as_user": "nobody"},
    ]


def build_random(rng: random.Random, index: int) -> tuple[str, list[str]]:
    """A random tree under RANDOM_BASE (dirs, files, links with random
    relative or absolute targets), and probe paths into it."""
    base = f"{RANDOM_BASE}/t{index}"
    reset(base)
    os.makedirs(base)
    names = ["a", "b", "c"]
    paths = [base]
    level = [base]
    for _ in range(3):
        level = [f"{parent}/{name}" for parent in level for name in names]
        paths.extend(level)
    # Only below directories this function made: never through a link,
    # whose target may lie outside `base`.
    made_dirs = {base}
    for path in paths[1:]:
        if os.path.dirname(path) not in made_dirs:
            continue
        roll = rng.random()
        if roll < 0.3:
            continue
        if roll < 0.55:
            os.mkdir(path)
            made_dirs.add(path)
        elif roll < 0.65:
            with open(path, "w") as handle:
                handle.write("x")
        else:
            parts = [rng.choice(["a", "b", "c", "a", "b", "c", "..", ".", ""]) for _ in range(rng.randrange(0, 5))]
            target = "/".join(parts) or "."  # Linux has no empty link targets
            if rng.random() < 0.4:
                target = f"{base}/{target}"
            os.symlink(target, path)
    probes = []
    for _ in range(5):
        parts = [rng.choice(names) for _ in range(rng.randrange(0, 5))]
        probe = "/".join([base, *parts])
        if rng.random() < 0.2:
            probe += "/"
        probes.append(probe)
    return base, probes


# --- comparison -----------------------------------------------------------------


@dataclass
class Report:
    compared: dict[str, int] = field(default_factory=dict)
    refusals: dict[str, int] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)

    def count(self, what: str) -> None:
        self.compared[what] = self.compared.get(what, 0) + 1

    def refused(self, errno: str) -> None:
        self.refusals[errno] = self.refusals.get(errno, 0) + 1


def run_as(user: str, argv: list[str], requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run a JSON-lines program as `user` (setpriv-less: `runuser`)."""
    lines = "".join(json.dumps(r) + "\n" for r in requests)
    result = subprocess.run(["runuser", "-u", user, "--", *argv], input=lines, capture_output=True, text=True,
                            check=True, timeout=60)
    return [json.loads(line) for line in result.stdout.splitlines()]


PY_AS_USER = r"""
import json, os, sys
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"resolved": os.path.realpath(request["path"])}), flush=True)
"""


def compare_realpath(report: Report, path: str, rust: dict[str, Any], python: dict[str, Any], expect: str,
                     label: str) -> None:
    report.count("realpath")
    if expect == "same" or (expect == "loop?" and "resolved" in rust):
        if rust != python or "resolved" not in rust:
            report.failures.append(f"{label}: realpath({path!r}): Rust {rust}, Python {python}")
        elif is_eloop(path):
            report.failures.append(f"{label}: realpath({path!r}): resolved after more than 40 traversals")
        return
    if expect == "loop?":
        errno = rust.get("error", {}).get("errno")
        if errno == "ELOOP" and "resolved" in python and is_eloop(path):
            report.refused("ELOOP")
            return
        report.failures.append(f"{label}: realpath({path!r}): Rust {rust}, Python {python}")
        return
    errno = rust.get("error", {}).get("errno")
    if errno != expect or "resolved" not in python:
        report.failures.append(f"{label}: realpath({path!r}): expected a Rust {expect} refusal and a Python path, "
                               f"got Rust {rust}, Python {python}")
        return
    if expect == "ELOOP" and not is_eloop(path):
        report.failures.append(f"{label}: realpath({path!r}): Rust refuses a loop that resolves")
        return
    report.refused(expect)


def compare_lstat(report: Report, probe: Probe, path: str, label: str) -> None:
    report.count("lstat")
    rust = probe.ask({"op": "lstat", "path": path})
    python = py_lstat(path)
    if rust != python:
        report.failures.append(f"{label}: lstat({path!r}): Rust {rust}, Python {python}")


def every_prefix(path: str) -> list[str]:
    parts = path.rstrip("/").split("/")[1:]
    return ["/" + "/".join(parts[:i]) for i in range(1, len(parts) + 1)]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--probe", required=True, help="the Rust probe binary (JSON lines)")
    parser.add_argument("--probe-name", default="pyrealpath", help="what the probe resolves with (report only)")
    parser.add_argument("--realpath-only", action="store_true", help="the probe answers only realpath")
    parser.add_argument("--random", type=int, default=300, help="random trees (default 300)")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--json", help="write the report here as JSON")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("layer2_realpath.py runs as root inside the e2e container", file=sys.stderr)
        return 2

    report = Report()
    probe = Probe([args.probe])
    label = f"{args.probe_name} / Python {sys.version.split()[0]}"

    curated = build_curated()
    as_user = [case for case in curated if "as_user" in case]
    for case in curated:
        if "as_user" in case:
            continue
        path = case["path"]
        if not (is_safe_path(path)):
            raise AssertionError(f"curated probe is not a safe path: {path!r}")
        compare_realpath(report, path, probe.ask({"op": "realpath", "path": path}), py_realpath(path),
                         case["expect"], f"{label} curated")
        if not args.realpath_only:
            for prefix in every_prefix(path):
                compare_lstat(report, probe, prefix, f"{label} curated")
    for case in as_user:
        rust = run_as(case["as_user"], [args.probe], [{"op": "realpath", "path": case["path"]}])[0]
        python = run_as(case["as_user"], [sys.executable, "-I", "-c", PY_AS_USER], [{"path": case["path"]}])[0]
        compare_realpath(report, case["path"], rust, python, case["expect"], f"{label} as {case['as_user']}")
        if not args.realpath_only:
            report.count("lstat")
            lstat = run_as(case["as_user"], [args.probe], [{"op": "lstat", "path": case["path"]}])[0]
            if lstat.get("error", {}).get("errno") != "EACCES":
                report.failures.append(f"{label}: lstat({case['path']!r}) as {case['as_user']}: {lstat}")

    rng = random.Random(args.seed)
    for index in range(args.random):
        base, probes = build_random(rng, index)
        for path in probes:
            assert is_safe_path(path), path
            compare_realpath(report, path, probe.ask({"op": "realpath", "path": path}), py_realpath(path),
                             "loop?", f"{label} random {index}")
            if not args.realpath_only:
                compare_lstat(report, probe, path, f"{label} random {index}")
        reset(base)

    if not args.realpath_only:
        for name in USERS:
            report.count("uid_of")
            rust = probe.ask({"op": "uid_of", "name": name})
            if rust != py_uid_of(name):
                report.failures.append(f"{label}: uid_of({name!r}): Rust {rust}, Python {py_uid_of(name)}")
        report.count("euid")
        if probe.ask({"op": "euid"}) != {"euid": os.geteuid()}:
            report.failures.append(f"{label}: euid differs")
    probe.close()

    summary = {"probe": args.probe_name, "python": sys.version.split()[0], "compared": report.compared,
               "refusals": report.refusals, "failures": report.failures}
    if args.json:
        with open(args.json, "w") as handle:
            json.dump(summary, handle, indent=2)
    print(json.dumps({k: v for k, v in summary.items() if k != "failures"}))
    for failure in report.failures[:50]:
        print("FAIL", failure)
    print(f"{label}: {len(report.failures)} failures")
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
