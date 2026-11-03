"""Give a directory tree to a user, as root, without following any symlink.

argv: ``PATH USER GROUP [--top]`` (``--top``: PATH itself, not the entries below it). Opens PATH one component at a time from ``/`` with
``O_NOFOLLOW`` (a symlinked component anywhere fails the run), then changes
the owner of the directory and of every entry below it through directory
descriptors; symlinks themselves get the owner, their targets are never
touched. Runs as ``python3 -I -c``; the source holds no backslash.
"""

import grp
import os
import pwd
import stat
import sys

FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def walk(dir_fd, uid, gid):
    os.chown(dir_fd, uid, gid)
    for name in os.listdir(dir_fd):
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, FLAGS, dir_fd=dir_fd)
            try:
                walk(child, uid, gid)
            finally:
                os.close(child)
        else:
            os.chown(name, uid, gid, dir_fd=dir_fd, follow_symlinks=False)


def main():
    path, user, group = sys.argv[1:4]
    top_only = sys.argv[4:] == ["--top"]
    uid, gid = pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    fd = os.open("/", FLAGS)
    for part in path.strip("/").split("/"):
        if part in ("", ".", ".."):
            raise SystemExit("path must be absolute and plain")
        child = os.open(part, FLAGS, dir_fd=fd)
        os.close(fd)
        fd = child
    try:
        if top_only:
            os.chown(fd, uid, gid)
        else:
            walk(fd, uid, gid)
    finally:
        os.close(fd)


main()
