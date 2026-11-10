"""The Linux role's path checks, read-only: prints ``ok`` or exits non-zero with the path.

``python3 -I -c <this> root PATH...``: every existing path is a root-owned
directory or single-link regular file, not a symlink, not group or world
writable. ``python3 -I -c <this> private ACCOUNT PATH...``: every existing
path is owned by ACCOUNT (refused when the account does not exist yet), not a
symlink, mode 0600 or 0700, a directory or a single-link regular file.
"""

import os
import pwd
import stat
import sys


def estate_check(path, owner, private):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    mode = stat.S_IMODE(info.st_mode)
    safe = (
        not stat.S_ISLNK(info.st_mode)
        and info.st_uid == owner
        and (stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1))
        and (mode in (0o600, 0o700) if private else not mode & 0o022)
    )
    if not safe:
        sys.exit("Unsafe publisher path: " + path)


def estate_main(argv):
    if argv[:1] == ["root"]:
        owner, private, paths = 0, False, argv[1:]
    elif argv[:1] == ["private"] and len(argv) > 1:
        try:
            owner = pwd.getpwnam(argv[1]).pw_uid
        except KeyError:
            owner = -1
        private, paths = True, argv[2:]
    else:
        sys.exit("usage: linux_paths.py root PATH... | private ACCOUNT PATH...")
    for path in paths:
        estate_check(path, owner, private)
    print("ok")


estate_main(sys.argv[1:])
