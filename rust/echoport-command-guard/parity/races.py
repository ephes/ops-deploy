#!/usr/bin/env python3
"""The race regressions of ``races.json`` against the Python guard (H1).

The Python guard's ``check()`` with the real filesystem, then its
``perform()`` with a test hook, for every scenario of ``races.json`` (its
``about`` explains the format). The Rust guard runs the same table
(``tests/mutations.rs``). Used by ``tests/test_echoport_remote_command_guard.py``
(``GuardMutationRaces``) and, as root on the hosts' distributions, by the
Layer-2 containers (``parity/e2e/run-layer2.sh``)::

    python3 -I races.py --guard <guard.py> [--races races.json]

Prints one line per failed scenario and exits 1 if there is any. Stdlib only.
"""

from __future__ import annotations

import argparse
import contextlib
import grp
import importlib.util
import json
import os
import pwd
import shutil
import stat
import sys
import tempfile
import types
from pathlib import Path
from typing import Any

RACES = Path(__file__).resolve().parent / "races.json"


def load_guard(path: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("echoport_remote_command_guard_races", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up
    spec.loader.exec_module(module)
    return module


def chown_target(guard: Any) -> tuple[str, tuple[int, int] | None]:
    """{owner} and its ids: as root nobody:nogroup, else another group of the
    test user (so a chown shows in the gid); no ids without a second group."""
    if os.geteuid() == 0:
        user = pwd.getpwnam("nobody")
        for name in ("nogroup", "nobody"):
            with contextlib.suppress(KeyError):
                return f"nobody:{name}", (user.pw_uid, grp.getgrnam(name).gr_gid)
    me = pwd.getpwuid(os.geteuid()).pw_name
    with tempfile.NamedTemporaryFile(dir=os.path.realpath(tempfile.gettempdir())) as probe:
        file_gid = os.stat(probe.name).st_gid
    for gid in sorted(set(os.getgroups())):
        with contextlib.suppress(KeyError):
            name = grp.getgrgid(gid).gr_name
            if gid != file_gid and guard._SAFE_OWNER_RE.match(f"{me}:{name}"):
                return f"{me}:{name}", (os.geteuid(), gid)
    return f"{me}:{grp.getgrgid(file_gid).gr_name}", None


def needs_chown(scenario: dict[str, Any]) -> bool:
    return scenario.get("command", "").startswith("chown") or "mutation" in scenario


def act(action: list[str]) -> None:
    kind, path, *rest = action
    if kind == "mkdir":
        os.mkdir(path)
    elif kind == "file":
        Path(path).write_text("new")
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "fifo_hex":
        os.mkfifo(os.fsencode(path) + b"/" + bytes.fromhex(rest[0]))
    elif kind == "link":
        os.symlink(rest[0], path)
    elif kind == "hardlink":
        os.link(rest[0], path)
    elif kind == "remove":
        os.unlink(path)
    elif kind == "rename":
        os.rename(path, rest[0])
    elif kind == "chmod":
        os.chmod(path, int(rest[0], 8))
    elif kind == "replace_with_link":
        os.rename(path, path + ".orig")
        os.symlink(rest[0], path)
    else:
        raise AssertionError(f"unknown action {kind}")


def owners(base: Path) -> dict[str, tuple[int, int]]:
    out = {}
    for directory, dirs, files in os.walk(base):
        for name in [*dirs, *files]:
            path = os.path.join(directory, name)
            st = os.lstat(path)
            out[path] = (st.st_uid, st.st_gid)
    return out


def check_after(after: list[list[str]], sub: Any, before: dict[str, tuple[int, int]],
                new_ids: tuple[int, int] | None) -> list[str]:
    errors = []
    for assertion in after:
        kind, path, *rest = [sub(a) for a in assertion]
        if kind == "absent":
            if os.path.lexists(path):
                errors.append(f"{assertion}: exists")
            continue
        try:
            st = os.lstat(path)
        except OSError as exc:
            errors.append(f"{assertion}: {exc}")
            continue
        if kind == "mode":
            ok = stat.S_IMODE(st.st_mode) == int(rest[0], 8)
        elif kind == "owner":
            ok = (st.st_uid, st.st_gid) == (new_ids if rest[0] == "new" else before[path])
        elif kind == "file":
            ok = stat.S_ISREG(st.st_mode)
        elif kind == "dir":
            ok = stat.S_ISDIR(st.st_mode)
        elif kind == "link":
            ok = stat.S_ISLNK(st.st_mode) and os.readlink(path) == rest[0]
        elif kind == "content":
            ok = stat.S_ISREG(st.st_mode) and Path(path).read_text() == rest[0]
        elif kind == "exists":
            ok = True
        else:
            raise AssertionError(f"unknown assertion {kind}")
        if not ok:
            errors.append(f"{assertion}: mode {st.st_mode:o} uid {st.st_uid} gid {st.st_gid}")
    return errors


def run_scenario(guard: Any, tree: dict[str, Any], scenario: dict[str, Any], owner: str,
                 new_ids: tuple[int, int] | None) -> list[str]:
    """The failures of one scenario (empty: it passed)."""
    base = Path(os.path.realpath(tempfile.mkdtemp()))
    try:
        names = {"{base}": str(base), "{root}": str(base / "root"), "{outside}": str(base / "outside"),
                 "{owner}": owner}

        def sub(text: str) -> str:
            for key, value in names.items():
                text = text.replace(key, value)
            return text

        for rel, mode in tree["dirs"]:
            (base / rel).mkdir()
            (base / rel).chmod(int(mode, 8))
        for rel, mode in tree["files"]:
            (base / rel).write_text(rel)
            (base / rel).chmod(int(mode, 8))
        for action in scenario.get("setup", []):
            act([sub(a) for a in action])
        before = owners(base)
        expect = scenario["expect"]

        if "command" in scenario:
            policy = guard.Policy.from_dict({"path_roots": [{"path": names["{root}"], "owner": owner}]})
            command = sub(scenario["command"])
            try:
                decision = guard.check(command, policy)
            except guard.Refused as exc:
                if str(exc) != sub(expect.get("check_refused", "<allowed>")):
                    return [f"check() refused {command!r}: {exc}"]
                return check_after(scenario.get("after", []), sub, before, new_ids)
            if "check_refused" in expect:
                return [f"check() allowed {command!r}"]
            if decision.argv != [] or decision.mutation is None:
                return [f"not a mutation: {decision}"]
            mutation = decision.mutation
        else:
            raw = json.loads(sub(json.dumps(scenario["mutation"])))
            mutation = guard.Mutation(**raw)
        for action in scenario.get("before_use", []):
            act([sub(a) for a in action])

        hooks = [dict(h, path=sub(h["path"]), seen=0) for h in scenario.get("hooks", [])]

        def hook(event: str, path: str) -> None:
            for spec in hooks:
                if spec["event"] == event and spec["path"] == path:
                    spec["seen"] += 1
                    if spec["seen"] == spec.get("nth", 1):
                        for action in spec["actions"]:
                            act([sub(a) for a in action])

        errors = []
        try:
            guard.perform(mutation, hook=hook)
        except guard.Refused as exc:
            reason = str(exc)
            if "refused_prefix" in expect:
                ok = reason.startswith(sub(expect["refused_prefix"]))
            else:
                ok = reason == sub(expect.get("refused", "<done>"))
            if not ok:
                errors.append(f"perform() refused: {reason}; expected {expect}")
        else:
            if expect != {"done": True}:
                errors.append(f"perform() done; expected {expect}")
        for spec in hooks:
            if spec["seen"] < spec.get("nth", 1):
                errors.append(f"hook never reached: {spec['event']} {spec['path']}")
        return errors + check_after(scenario.get("after", []), sub, before, new_ids)
    finally:
        for rel, _mode in tree["dirs"]:
            with contextlib.suppress(OSError):
                os.chmod(base / rel, 0o700)
        shutil.rmtree(base, ignore_errors=True)


def run_all(guard: Any, races_path: Path = RACES) -> tuple[list[str], list[str]]:
    """(failures, skipped scenario ids) of the whole table."""
    races = json.loads(races_path.read_text())
    owner, new_ids = chown_target(guard)
    failures, skipped = [], []
    for scenario in races["scenarios"]:
        platforms = scenario.get("platforms")
        if ((needs_chown(scenario) and new_ids is None) or (platforms and sys.platform not in platforms)
                or (scenario.get("unprivileged") and os.geteuid() == 0)):
            skipped.append(scenario["id"])
            continue
        for error in run_scenario(guard, races["tree"], scenario, owner, new_ids):
            failures.append(f"{scenario['id']}: {error}")
    return failures, skipped


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--guard", required=True)
    parser.add_argument("--races", default=str(RACES))
    args = parser.parse_args(argv)
    guard = load_guard(args.guard)
    failures, skipped = run_all(guard, Path(args.races))
    total = len(json.loads(Path(args.races).read_text())["scenarios"])
    for line in failures:
        print(f"FAIL {line}")
    print(f"races: {total} scenarios, {len(failures)} failures, {len(skipped)} skipped (euid {os.geteuid()})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
