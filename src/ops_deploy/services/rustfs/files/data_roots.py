"""Read-only mount and ownership admission for the RustFS data root.

Refuses unless the required mount is a mount point and the data root (or its
nearest existing ancestor) lies on that file system. An existing data root is
walked for the first foreign-owned descendant or nested mount; object bodies
are never read and nothing is repaired. Prints ``empty`` or ``current``.
"""
import grp
import json
import os
import pwd
import re
import stat
import sys


def mount_points():
    """Mount points from /proc/self/mountinfo (bind mounts keep the device number)."""
    points = []
    with open("/proc/self/mountinfo", encoding="utf-8") as source:
        for line in source:
            fields = line.split()
            points.append(re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4]))
    return points


def admit(root, mount, user, group):
    if not os.path.ismount(mount):
        raise ValueError("required mount is absent; refusing to place data on the underlying file system")
    device = os.stat(mount).st_dev
    probe = root
    while not os.path.lexists(probe):
        probe = os.path.dirname(probe)
    info = os.lstat(probe)
    # A symlinked ancestor would let mountinfo (resolved paths) miss a mount below the root.
    if os.path.realpath(probe) != probe or os.path.realpath(mount) != mount:
        raise ValueError("data root or required mount path contains a symlink")
    if not stat.S_ISDIR(info.st_mode) or info.st_dev != device:
        raise ValueError("data root is not a directory on the required mount")
    if probe != root:
        return False
    if any(point == root or point.startswith(root + "/") for point in mount_points()):
        raise ValueError("a mount at or below the data root is outside deployment ownership")
    try:
        uid, gid = pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError:
        uid = gid = None
    populated = False
    pending = [root]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                populated = True
                info = entry.stat(follow_symlinks=False)
                if uid is None:
                    raise ValueError("existing data requires the configured account identity")
                if info.st_dev != device:
                    raise ValueError("nested mount below data root is outside deployment ownership")
                if info.st_uid != uid or info.st_gid != gid:
                    raise ValueError("foreign-owned descendant below data root; no recursive repair performed")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(entry.path)
    return populated


def main():
    try:
        payload = json.load(sys.stdin)
        populated = admit(payload["root"], payload["mount"], payload["user"], payload["group"])
        print("current" if populated else "empty")
    except ValueError as error:
        print("refused: " + str(error))
        sys.exit(1)
    except Exception:
        print("refused: unable to inspect the data root")
        sys.exit(1)


if __name__ == "__main__":
    main()
