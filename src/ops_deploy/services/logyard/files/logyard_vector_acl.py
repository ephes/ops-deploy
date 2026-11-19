"""Grant the Vector user read access to its log files with POSIX ACLs (Linux, run as root).

``check`` prints ``current`` or ``needed``; ``apply`` sets what is missing and
prints one line per change. The request (base64 JSON, argv) names the user
and, per directory, whether its files get access too and which file name
patterns are meant::

    {"user": "vector", "dirs": [{"path": "/var/log/rspamd", "files": false, "patterns": []}]}

Paths are opened one component at a time from ``/`` with ``O_NOFOLLOW``, and
every change goes through ``/proc/self/fd/<n>``: a symbolic link anywhere in
the path, or planted in a service-writable log directory, never redirects a
grant. Links, sockets and other non-regular files among the matches are
skipped. Access the user already has (as owner, through a group, through
``other`` or an existing entry) is left alone. A directory's first default
ACL is explicit (``d:u::rwx,d:g::---,d:o::---,d:m::r--`` plus the user's
read), because with a default ACL Linux ignores the creator's umask. A new or extended named entry
keeps the rights an existing one had; the mask is never recalculated
(``setfacl -n``), and when the mask, or for a file without ACL its group
bits, would leave the grant without effect the script stops before changing
anything. A configured directory that does not exist is an error.
"""

import base64
import fnmatch
import grp
import json
import os
import pwd
import stat
import subprocess
import sys

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY
BITS = {"r": 4, "w": 2, "x": 1}


def to_bits(perms):
    return sum(BITS[char] for char in perms if char in BITS)


def to_text(bits):
    return "".join(char if bits & value else "-" for char, value in BITS.items())


def open_dir(path):
    """``path`` opened component by component without following any symbolic link."""

    if not path.startswith("/"):
        raise SystemExit("not absolute: %s" % path)
    fd = os.open("/", DIR_FLAGS)
    for part in [part for part in path.split("/") if part]:
        if part in (".", ".."):
            os.close(fd)
            raise SystemExit("unexpected path component in %s" % path)
        try:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
        except FileNotFoundError:
            os.close(fd)
            raise SystemExit("missing directory %s" % path)
        except OSError as error:
            os.close(fd)
            raise SystemExit("cannot open %s without following links: %s" % (path, error))
        os.close(fd)
        fd = child
    return fd


def acl(fd):
    """The ACL's entries without effective-rights comments: {("user", "vector"): bits, ("mask", ""): bits, ...}."""

    out = subprocess.run(
        ["getfacl", "-cpE", "/proc/self/fd/%d" % fd], pass_fds=[fd], capture_output=True, text=True, check=True
    ).stdout
    entries = {}
    for line in out.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(":")
        if parts[0] == "default":
            tag, qualifier, perms = "default:" + parts[1], parts[2], parts[3]
        else:
            tag, qualifier, perms = parts[0], parts[1], parts[2]
        entries[(tag, qualifier)] = to_bits(perms)
    return entries


def _group_exists(gid):
    try:
        grp.getgrgid(gid)
        return True
    except KeyError:
        return False


class Account:
    def __init__(self, name):
        entry = pwd.getpwnam(name)
        self.name, self.uid = name, entry.pw_uid
        self.gids = {entry.pw_gid} | {g.gr_gid for g in grp.getgrall() if name in g.gr_mem}
        self.groups = {grp.getgrgid(gid).gr_name for gid in self.gids if _group_exists(gid)}


def evaluate(fd, entries, account, want):
    """Which ACL class decides for ``account`` and whether it grants all of ``want`` (POSIX.1e order)."""

    info = os.fstat(fd)
    mode = info.st_mode
    has_mask = ("mask", "") in entries
    mask = entries.get(("mask", ""), 7)
    if info.st_uid == account.uid:
        return "owner", (mode >> 6) & 7 & want == want, (mode >> 6) & 7
    if ("user", account.name) in entries:
        bits = entries[("user", account.name)]
        return "named", bits & mask & want == want, bits & mask
    groups = []
    if info.st_gid in account.gids:
        groups.append(entries.get(("group", ""), 0) if has_mask else (mode >> 3) & 7)
    groups += [bits for (tag, name), bits in entries.items() if tag == "group" and name in account.groups]
    if groups:
        # Linux grants a request when one matching group entry covers all of it.
        union = 0
        for bits in groups:
            union |= bits & mask
        return "group", any(bits & mask & want == want for bits in groups), union
    return "other", mode & 7 & want == want, mode & 7


def plan(fd, label, account, wanted, default):
    """The setfacl spec still needed, or None; refuses what a named entry cannot grant without
    widening a mask or taking away rights the account has now."""

    entries = acl(fd)
    want = to_bits(wanted)
    if default:
        if not any(tag.startswith("default:") for tag, _ in entries):
            # A first default ACL makes Linux ignore the creator's umask for
            # files created here, so it is explicit and tight: owner as the
            # mode says, nobody else but this account, which may read.
            return "d:u::rwx,d:g::---,d:o::---,d:m::r--,d:u:%s:%s" % (account.name, wanted.replace("-", ""))
        current = entries.get(("default:user", account.name), 0)
        # An existing default ACL without a mask has no named entries yet;
        # setfacl -n then derives the mask from its group entry.
        mask = entries.get(("default:mask", ""), entries.get(("default:group", ""), 0))
        if current & mask & want == want:
            return None
        if mask & want != want:
            raise SystemExit("%s: the default mask is narrower than %s" % (label, wanted))
        return "d:u:%s:%s" % (account.name, to_text(current | want).replace("-", ""))
    decided, granted, rights = evaluate(fd, entries, account, want)
    if granted:
        return None
    if decided == "owner":
        raise SystemExit("%s: owned by %s without %s; an ACL entry cannot change that" % (label, account.name, wanted))
    if decided in ("group", "other") and rights:
        # A named entry would replace these rights; extending it to keep them
        # could widen the mask. Left to the operator.
        raise SystemExit("%s: %s has %s through %s; refusing to replace them" % (label, account.name, to_text(rights), decided))
    current = entries.get(("user", account.name), 0)
    # Without an ACL, setfacl -n starts the mask from the owning group's bits.
    mask = entries.get(("mask", ""), (os.fstat(fd).st_mode >> 3) & 7)
    if mask & (current | want) != current | want:
        raise SystemExit("%s: its mask or group bits are narrower than %s; refusing to widen them" % (label, wanted))
    return "u:%s:%s" % (account.name, to_text(current | want).replace("-", ""))


def targets(spec):
    """(label, fd, wanted, default) for every object the request names; the caller closes the fds."""

    directory = spec["path"]
    dfd = open_dir(directory)
    found = [(directory, dfd, "r-x", False)]
    if not spec["files"]:
        return found
    found.append((directory + " (default)", dfd, "r--", True))
    for name in sorted(os.listdir(dfd)):
        if not any(fnmatch.fnmatchcase(name, pattern) for pattern in spec["patterns"]):
            continue
        try:
            fd = os.open(name, FILE_FLAGS, dir_fd=dfd)
        except OSError:
            continue  # a symbolic link (ELOOP), gone, or not openable: skipped
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            continue
        found.append((directory + "/" + name, fd, "r--", False))
    return found


def main():
    action, request = sys.argv[1], json.loads(base64.b64decode(sys.argv[2]))
    account = Account(request["user"])
    needed = []
    fds = set()
    try:
        for spec in request["dirs"]:
            for label, fd, wanted, default in targets(spec):
                fds.add(fd)
                grant = plan(fd, label, account, wanted, default)
                if grant is not None:
                    needed.append((label, fd, grant, wanted, default))
        if action == "check":
            print("needed" if needed else "current")
            return
        for label, fd, grant, wanted, default in needed:
            subprocess.run(["setfacl", "-n", "-m", grant, "/proc/self/fd/%d" % fd], pass_fds=[fd], check=True)
            if plan(fd, label, account, wanted, default) is not None:
                raise SystemExit("%s: the grant %s did not give effective access" % (label, grant))
            print("granted %s on %s" % (grant, label))
    finally:
        for fd in fds:
            os.close(fd)


if __name__ == "__main__":
    main()
