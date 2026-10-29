"""Original file(state=directory,recurse=true,follow=true) ownership subset.

Only metadata is read; no filenames, file contents or account details are
returned. Existing modes and timestamps are untouched. As in the original,
existing symlinks and their existing targets participate in ownership repair.
"""

import grp
import json
import os
from pathlib import Path
import pwd
import sys


def entries(root, active=None):
    active = set() if active is None else active
    canonical = os.path.realpath(root)
    if canonical in active:
        raise ValueError("recursive environment ownership link cycle")
    active.add(canonical)
    try:
        # Only converge() resolves the top-level root. Recursive targets keep
        # their spelling: the original lchown repairs a second-level link,
        # while os.walk traverses its directory contents.
        root = Path(root)
        if not root.is_dir():
            raise ValueError("environment ownership root is not a directory")
        yield root
        for parent, directories, files in os.walk(root):
            for name in directories + files:
                entry = Path(parent) / name
                yield entry
                if entry.is_symlink():
                    target = entry.parent / os.readlink(entry)
                    if target.exists():
                        if target.is_dir():
                            linked = iter(entries(target, active))
                            target_root = next(linked)
                            yield from linked
                            yield target_root
                        else:
                            yield target
    finally:
        active.remove(canonical)


def converge(root, uid, gid, apply=False):
    root = Path(root)
    if not root.is_absolute() or root == Path("/") or ".." in root.parts:
        raise ValueError("invalid declared environment root")
    # Original ensure_directory follows a root link, including a missing target.
    if root.is_symlink():
        root = Path(os.path.realpath(root))
    if Path(os.path.realpath(root)) == Path("/"):
        raise ValueError("environment ownership root resolves to filesystem root")
    if not root.exists():
        if not apply:
            return "pending"
        missing = []
        current = root
        while not current.exists():
            missing.append(current)
            current = current.parent
        for path in reversed(missing):
            path.mkdir()
            os.lchown(path, uid, gid)
        return "changed"
    planned = list(entries(root))
    wrong = []
    for path in planned:
        metadata = path.lstat()
        if metadata.st_uid != uid or metadata.st_gid != gid:
            wrong.append(path)
    if not wrong:
        return "current"
    if not apply:
        return "pending"
    for path in wrong:
        metadata = path.lstat()
        if metadata.st_uid != uid or metadata.st_gid != gid:
            os.lchown(path, uid, gid)
    return "changed"


def main():
    request = json.load(sys.stdin)
    if (not isinstance(request, dict) or set(request) != {"root", "user", "group", "apply"}
            or type(request["apply"]) is not bool
            or any(not isinstance(request[key], str) for key in ("root", "user", "group"))):
        raise ValueError("invalid ownership request")
    uid = pwd.getpwnam(request["user"]).pw_uid
    gid = grp.getgrnam(request["group"]).gr_gid
    print(converge(request["root"], uid, gid, request["apply"]))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError):
        print("Home Assistant environment ownership inspection or repair failed", file=sys.stderr)
        raise SystemExit(1) from None
