#!/usr/bin/env python3
"""software-live-apt against python-apt in a fake APT world.

software-live PLAN.md 6.1 (TESTMAP: test_security_packages_include_held_and_
pinned_versions) and 13.6: after container/setup-world.sh, run the helper
and `observe_apt` of `roles/software_live/files/software_live.py` (the
oracle, with python-apt and `apt-mark showhold`) on the same lists with the
same `(max_age, now)` and require identical JSON objects. Also checks the
expected result of every fake package, that the helper never writes under
/var/cache/apt (as root, where it could, and as an unprivileged user,
which reads the warm srcpkgcache.bin as the collector unit does), and an
`unknown` result for a broken security index. Runs as root in the
container only; stdlib plus python3-apt.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

CACHE_DIR = Path("/var/cache/apt")
LISTS = Path("/var/lib/apt/lists")
NOBODY = 65534


class CompareError(Exception):
    pass


def load_oracle(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("software_live", path)
    if spec is None or spec.loader is None:
        raise CompareError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot() -> dict[str, tuple[int, int]]:
    """Every file under /var/cache/apt with its size and mtime."""
    files = {}
    for path in sorted(CACHE_DIR.rglob("*")):
        if path.is_file():
            stat = path.stat()
            files[str(path)] = (stat.st_size, stat.st_mtime_ns)
    return files


def run_helper(helper: Path, max_age: int, now: float, user: int | None = None) -> Any:
    argv = [str(helper), "observe", "--max-age", str(max_age), "--now", repr(now)]
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    result = subprocess.run(  # noqa: S603 - the helper under test
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
        check=False,
        user=user,
        group=user,
        extra_groups=[] if user is not None else None,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "TMPDIR": "/tmp"},
    )
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if result.returncode != 0:
        raise CompareError(
            f"helper exited {result.returncode}: {result.stderr.decode(errors='replace')}"
        )
    lines = result.stdout.decode("utf-8").splitlines()
    if len(lines) != 1:
        raise CompareError(f"helper printed {len(lines)} lines, expected one")
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    print(
        f"  helper{' as uid ' + str(user) if user is not None else ''}: "
        f"{time.monotonic() - started:.2f} s wall, {cpu:.2f} s CPU, "
        f"largest child maxrss so far {after.ru_maxrss / 1024:.1f} MiB"
    )
    return json.loads(lines[0])


def by_package(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["package"]: item for item in result["pending_security_updates"]}


def check_expectations(result: dict[str, Any], native: str, foreign: str) -> None:
    """The fake packages of setup-world.sh as PLAN.md 13.1 expects them."""
    if result.get("status") != "ok":
        raise CompareError(f"expected status ok, got {result}")
    updates = by_package(result)
    expected = {
        f"fakenative:{native}": ("1.1", "9.9", False),
        f"fakeforeign:{foreign}": ("1.1", "1.1", True),
        f"fakeheld:{native}": ("1.1", "1.1", True),
        f"fakepin:{native}": ("1.2", "1.1", False),
        f"fakeall:{native}": ("1.3", "1.3", False),
        f"fakedual:{native}": ("2.0", "2.0", False),
        f"fakecase:{native}": ("1.2", "1.2", False),
    }
    for package, (security, candidate, held) in expected.items():
        entry = updates.get(package)
        want = {
            "package": package,
            "installed": "1.0",
            "security_version": security,
            "candidate": candidate,
            "held": held,
        }
        if entry != want:
            raise CompareError(f"{package}: expected {want}, got {entry}")
    for name in ("fakemulti", "fakeesmun", "fakelow"):
        if f"{name}:{native}" in updates:
            raise CompareError(f"{name} must not be a pending security update")
    if result["pending_security_count"] != len(result["pending_security_updates"]):
        raise CompareError("pending_security_count differs from the list")


def compare(
    oracle: Any, helper: Path, cases: list[tuple[int, float]], user=None
) -> None:
    for max_age, now in cases:
        expected = oracle.observe_apt(max_age, now)
        actual = run_helper(helper, max_age, now, user)
        if actual != expected:
            raise CompareError(
                f"max_age={max_age} now={now!r}: helper and python-apt differ\n"
                f"python-apt: {json.dumps(expected, sort_keys=True)}\n"
                f"helper:     {json.dumps(actual, sort_keys=True)}"
            )
        print(
            f"  max_age={max_age} now={now!r}: identical "
            f"({expected.get('pending_security_count')} pending, "
            f"indexes_fresh={expected.get('indexes_fresh')})"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    args = parser.parse_args(argv)
    helper = args.helper.resolve()
    native = subprocess.run(
        ["dpkg", "--print-architecture"], capture_output=True, text=True, check=True
    ).stdout.strip()
    foreign = {"amd64": "i386", "arm64": "armhf"}[native]
    oracle = load_oracle(args.oracle)
    now = time.time()
    cases = [
        (172800, now),  # fresh (lists refreshed by setup-world.sh)
        (3600, now + 30 * 86400),  # stale
        (1209600, now - 365 * 86400),  # indexes from the future: negative ages
        (3600, float(int(now))),  # an integral float
    ]
    try:
        print("helper as root without cache files (/var/cache/apt writable):")
        for path in CACHE_DIR.glob("*.bin"):
            path.unlink()
        before = snapshot()
        first = run_helper(helper, *cases[0])
        check_expectations(first, native, foreign)
        if snapshot() != before:
            raise CompareError(f"the helper wrote under {CACHE_DIR}: {snapshot()}")
        print("python-apt oracle vs helper (root):")
        compare(oracle, helper, cases)
        # python-apt and apt-mark have now written the cache files (the
        # writable column of PLAN.md 13.3); an unprivileged run cannot write
        # there, reads the warm srcpkgcache.bin and must change nothing.
        warm = snapshot()
        if not any(name.endswith("srcpkgcache.bin") for name in warm):
            raise CompareError("python-apt wrote no srcpkgcache.bin to read warm")
        os.chmod("/tmp", 0o1777)
        print(f"python-apt oracle vs helper (uid {NOBODY}, warm read-only cache):")
        compare(oracle, helper, cases[:1], user=NOBODY)
        if snapshot() != warm:
            raise CompareError(f"the unprivileged helper changed {CACHE_DIR}")
        print("a broken security index makes both unknown:")
        broken = LISTS / "zz.example_dists_x-security_InRelease"
        broken.symlink_to(LISTS / "missing-target")
        try:
            compare(oracle, helper, cases[:1])
        finally:
            broken.unlink()
        result = run_helper(helper, *cases[0])
        if result.get("status") != "ok":
            raise CompareError(f"expected ok after removing the broken index: {result}")
    except CompareError as error:
        print(f"compare.py: FAILED: {error}", file=sys.stderr)
        return 1
    print("compare.py: helper and python-apt agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
