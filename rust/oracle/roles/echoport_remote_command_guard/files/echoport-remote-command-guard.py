#!/usr/bin/python3 -I
"""Forced-command allowlist for the Echoport remote backup runners.

sshd runs this program instead of whatever the client asked for when the
deploy@macmini key logs in as root (``command="..."`` in authorized_keys). The
requested command arrives in ``SSH_ORIGINAL_COMMAND``. It runs only when it has
exactly one of the shapes the ops-library remote runners send
(``echoport_backup/templates/*_backup.py.j2``) and every database, unit and
path in it is allowed by the policy file named on the command line. Anything
else is refused and logged; there is no interactive shell.

Allowed commands are executed directly (no shell), with a fixed PATH, so the
quoting of the original string cannot smuggle extra commands through. The few
redirections the runners use (``< file``, ``> file``) are done by the guard
itself, on files it opens without following symlinks. Uploads (``scp -t``, the
rsync receiver) run as the unprivileged owner of their target, so the sender
cannot create root-owned, setuid or device files.

The changes root makes inside the policy roots (``chmod``, ``chown [-R]``,
``mv``, ``rm -f`` of SQLite side files) are not run as tools on a pathname,
which a local user who can write inside a root could redirect with a symlink
after the check. The guard makes them itself (``perform``): it walks each
path from ``/`` one directory at a time without following symlinks, and
changes, renames or removes the entry relative to the directory it opened.
"""

from __future__ import annotations

import ctypes
import errno
import grp
import json
import os
import pwd
import re
import shlex
import stat
import sys
import syslog
from dataclasses import dataclass, field

PROGRAM = "echoport-remote-command-guard"
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_COMMAND_LENGTH = 4096

# Values that reach argv. No whitespace, quotes or shell metacharacters.
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]*$")
_SAFE_OWNER_RE = re.compile(r"^[a-z_][a-z0-9_-]*:[a-z_][a-z0-9_-]*$")
_STAMP = r"[A-Za-z0-9_-]+"
_PRIVATE_TMP_DIR_RE = re.compile(r"^/tmp/echoport-pp-private-media\.[A-Za-z0-9]+$")
_PRIVATE_ARCHIVE_RE = re.compile(r"^/tmp/echoport-pp-private-media\.[A-Za-z0-9]+/private_media\.tar\.gz$")
_PRIVATE_MKTEMP = ["mktemp", "-d", "/tmp/echoport-pp-private-media.XXXXXXXX"]
_TAR_RE = re.compile(r"^umask 077 && (tar -C \S+ -czf \S+ -- \S+)$")
_CAT_TO_FILE_RE = re.compile(r"^umask 077 && cat > (\S+)$")
_TEMP_TEMPLATE_RE = re.compile(r"^/(?:var/)?tmp/[a-z0-9][a-z0-9._-]*\.X{6,}$")
_READY_URL_RE = re.compile(r"^http://127\.0\.0\.1:[0-9]{1,5}/[a-z]+$")

# The rsync server arguments (everything between "rsync" and ". <dir>/") for
# exactly the client options the runners use. Derived by running the rsync
# client with a recording -e program: rsync 3.2.7 (Ubuntu 24.04, the runner
# host) and 3.5.0 (Debian 13) send the same strings. Anything else (-L, -K,
# devices/specials, --remove-source-files, ...) is refused.
RSYNC_SERVER_ARGS = {
    # rsync -a --safe-links <host>:<dir>/ <local>/      (download)
    ("--server", "--sender", "-logDtpre.iLsfxCIvu", "--safe-links"),
    # rsync -a --no-D <local>/ <host>:<dir>/             (upload, keeps extra files)
    ("--server", "-logtpre.iLsfxCIvu"),
    # rsync -a --no-D --delete <local>/ <host>:<dir>/    (upload, mirror)
    ("--server", "-logtpre.iLsfxCIvu", "--delete"),
}

_PSQL_RUNNER_PREFIX = ["-X", "-v", "ON_ERROR_STOP=1", "-qAt", "-d"]
_SQL_SERVER_VERSION = "SHOW server_version;"
_SQL_DB_EXISTS_RE = re.compile(r"^SELECT 1 FROM pg_database WHERE datname = '([a-z0-9_]+)';$")
_SQL_COUNT_RE = re.compile(r"^SELECT count\(\*\) FROM public\.[a-z_][a-z0-9_]*;$")
_SQLITE_BACKUP_RE = re.compile(r"^\.backup '(/[A-Za-z0-9._/-]+)'$")
# The busy handler a runner sets before `.backup` (waits for a committing writer).
_SQLITE_TIMEOUT_RE = re.compile(r"^\.timeout [1-9][0-9]{0,5}$")
_SQLITE_INTEGRITY = "PRAGMA integrity_check;"
_CHMOD_MODES = ("0600", "0700")
_UPLOAD_SUFFIXES = (".tmp", ".restore-tmp")


class Refused(Exception):
    """The command is not on the allowlist."""


def _temp_dir_re(template: str) -> re.Pattern[str]:
    """What `mktemp -d <template>` can return."""
    prefix = template.rstrip("X")
    return re.compile(rf"^{re.escape(prefix)}[A-Za-z0-9]{{{len(template) - len(prefix)}}}$")


@dataclass
class SqliteSnapshot:
    database: str
    owner: str
    temp_dir: str

    @property
    def user(self) -> str:
        return self.owner.split(":", 1)[0]


@dataclass
class Policy:
    dump_databases: set[str] = field(default_factory=set)
    restore_databases: dict[str, str] = field(default_factory=dict)
    temp_file_prefixes: list[str] = field(default_factory=list)
    scratch_restore_prefixes: list[str] = field(default_factory=list)
    units: set[str] = field(default_factory=set)
    private_media_paths: set[str] = field(default_factory=set)
    path_roots: list[tuple[str, str]] = field(default_factory=list)
    temp_dirs: list[str] = field(default_factory=list)
    sqlite_snapshots: list[SqliteSnapshot] = field(default_factory=list)
    read_files: set[str] = field(default_factory=set)
    ready_urls: set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        postgres = data.get("postgres") or {}
        policy = cls(
            dump_databases=set(postgres.get("dump_databases") or []),
            restore_databases=dict(postgres.get("restore_databases") or {}),
            temp_file_prefixes=list(postgres.get("temp_file_prefixes") or []),
            scratch_restore_prefixes=list(postgres.get("scratch_restore_prefixes") or []),
            units=set(data.get("units") or []),
            private_media_paths={p.rstrip("/") for p in data.get("private_media_paths") or []},
            path_roots=[
                (str(entry["path"]).rstrip("/"), str(entry["owner"]))
                for entry in data.get("path_roots") or []
            ],
            temp_dirs=[str(t) for t in data.get("temp_dirs") or []],
            sqlite_snapshots=[
                SqliteSnapshot(str(entry["database"]), str(entry["owner"]), str(entry["temp_dir"]))
                for entry in data.get("sqlite_snapshots") or []
            ],
            read_files={str(p) for p in data.get("read_files") or []},
            ready_urls={str(u) for u in data.get("ready_urls") or []},
        )
        for name in policy.dump_databases | set(policy.restore_databases) | set(policy.restore_databases.values()):
            _require(_SAFE_NAME_RE.match(name), f"invalid database or role name in policy: {name!r}")
        for prefix in policy.temp_file_prefixes:
            _require(re.fullmatch(r"[a-z0-9_]+", prefix), f"invalid temp file prefix in policy: {prefix!r}")
        for prefix in policy.scratch_restore_prefixes:
            _require(re.fullmatch(r"[a-z][a-z0-9_]*", prefix), f"invalid scratch database prefix: {prefix!r}")
        for unit in policy.units:
            _require(_SAFE_NAME_RE.match(unit), f"invalid unit name in policy: {unit!r}")
        for path in policy.private_media_paths:
            _require(_is_safe_path(path) and path.count("/") >= 2, f"invalid private media path: {path!r}")
        for root, owner in policy.path_roots:
            _require(_is_safe_path(root) and root.count("/") >= 2, f"invalid path root: {root!r}")
            _require(_SAFE_OWNER_RE.match(owner), f"invalid owner for {root}: {owner!r}")
            _require(not owner.startswith("root:"), f"uploads into {root} must not run as root")
        for template in policy.temp_dirs:
            _require(_TEMP_TEMPLATE_RE.match(template), f"invalid temp dir template: {template!r}")
        for snapshot in policy.sqlite_snapshots:
            _require(
                _is_safe_path(snapshot.database) and snapshot.database.count("/") >= 2,
                f"invalid sqlite database: {snapshot.database!r}",
            )
            _require(_SAFE_OWNER_RE.match(snapshot.owner), f"invalid sqlite owner: {snapshot.owner!r}")
            _require(snapshot.user != "root", "sqlite snapshots must run as the service user, not root")
            _require(_TEMP_TEMPLATE_RE.match(snapshot.temp_dir), f"invalid temp dir template: {snapshot.temp_dir!r}")
        for path in policy.read_files:
            _require(_is_safe_path(path) and path.count("/") >= 2, f"invalid read file: {path!r}")
        for url in policy.ready_urls:
            _require(_READY_URL_RE.match(url), f"invalid ready URL: {url!r}")
        return policy

    def scratch_database(self, name: str) -> bool:
        return any(re.fullmatch(rf"{re.escape(p)}_[0-9]+", name) for p in self.scratch_restore_prefixes)

    def private_temp_dir(self, path: str) -> bool:
        """A root-only directory from `mktemp -d <template>` (policy temp_dirs)."""
        return any(_temp_dir_re(t).match(path) for t in self.temp_dirs)

    def snapshot_for_temp_dir(self, path: str) -> SqliteSnapshot | None:
        for snapshot in self.sqlite_snapshots:
            if _temp_dir_re(snapshot.temp_dir).match(path):
                return snapshot
        return None


@dataclass
class Redirect:
    """A file the guard opens itself and hands the command as stdin or stdout.

    `directory` is opened without following symlinks and must belong to the
    guard's own user (or one of `owners`) with no group/other access; `name`
    is opened inside it without following symlinks and must be a plain file.
    """

    directory: str
    name: str
    owners: tuple[str, ...] = ()


@dataclass
class Mutation:
    """A change the guard makes itself instead of running a tool (perform()).

    `op` is the tool it replaces: ``chmod`` (`mode`), ``chown`` (`owner`,
    `recursive`; `private`: the path must still be a directory of the guard's
    own user with no group/other access), ``mv`` (`paths` is source and
    target; `replace`: the target may exist) or ``rm`` (``-f``: missing paths
    are fine). Every path is walked from / without following symlinks.
    `user`: main() drops to this user (the root's owner) before perform(), so
    chmod, mv and rm only ever do what that user could do itself; chown keeps
    root (`user` None).
    """

    op: str
    paths: list[str]
    mode: int | None = None
    owner: str | None = None
    recursive: bool = False
    private: bool = False
    replace: bool = False
    user: str | None = None


@dataclass
class Decision:
    argv: list[str]  # empty for a mutation: nothing is executed
    umask: int | None = None
    stdin: Redirect | None = None
    stdout: Redirect | None = None  # created exclusively, mode 0600
    mutation: Mutation | None = None


def _require(condition: object, message: str) -> None:
    if not condition:
        raise Refused(message)


def _is_safe_path(path: str) -> bool:
    if not _SAFE_PATH_RE.match(path):
        return False
    return all(part not in ("", ".", "..") for part in path.rstrip("/").split("/")[1:])


def _temp_dump_re(policy: Policy, kind: str) -> re.Pattern[str] | None:
    if not policy.temp_file_prefixes:
        return None
    prefixes = "|".join(re.escape(p) for p in policy.temp_file_prefixes)
    return re.compile(rf"^/tmp/echoport_({prefixes})_{kind}_{_STAMP}\.dump$")


def _is_temp_dump(policy: Policy, path: str, kinds: tuple[str, ...]) -> bool:
    for kind in kinds:
        pattern = _temp_dump_re(policy, kind)
        if pattern is not None and pattern.match(path):
            return True
    return False


def _root_for(policy: Policy, path: str, realpath=os.path.realpath) -> tuple[str, str] | None:
    """Return (root, owner) when path resolves inside (or to) a policy root."""
    if not _is_safe_path(path):
        return None
    resolved = realpath(path)
    for root, owner in policy.path_roots:
        if resolved == root or resolved.startswith(root + "/"):
            return root, owner
    return None


def _require_in_roots(policy: Policy, path: str, realpath=os.path.realpath) -> tuple[str, str]:
    found = _root_for(policy, path, realpath)
    _require(found is not None, f"path outside the allowed roots: {path!r}")
    return found  # type: ignore[return-value]


def _require_mutable(policy: Policy, path: str, realpath=os.path.realpath) -> tuple[str, str]:
    """A path inside a root that root changes (perform()): it must resolve inside
    the root and also name it as written, because perform() walks the path
    itself without following symlinks."""
    found = _require_in_roots(policy, path, realpath)
    root = found[0]
    _require(
        path == root or (path.startswith(root + "/") and not path.endswith("/")),
        f"path not inside its root as written: {path!r}",
    )
    return found


def _lstat_or_none(path: str, lstat, what: str):
    try:
        return lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Refused(f"{what} not checkable: {path!r}: {exc.strerror}") from exc


def _require_plain_file_or_absent(path: str, lstat, what: str, owner: str | None = None) -> None:
    """A path scp may read or write: missing, or a regular file with one link.

    Uses lstat, so a symlink, device, FIFO, socket or directory is refused.
    With `owner`, an existing file must belong to that user.
    """
    st = _lstat_or_none(path, lstat, what)
    if st is None:
        return
    _require(stat.S_ISREG(st.st_mode), f"{what} is not a regular file: {path!r}")
    _require(st.st_nlink == 1, f"{what} has other hard links: {path!r}")
    if owner is not None:
        _require(st.st_uid in _user_uids((owner,), include_self=False), f"{what} does not belong to {owner}: {path!r}")


def _require_private_dir(path: str, lstat) -> None:
    """A directory of the guard's own user with no group/other access (fresh mktemp -d).

    Nobody else can put a symlink into it, and in a sticky /tmp nobody else can
    replace it.
    """
    st = _lstat_or_none(path, lstat, "directory")
    _require(
        st is not None and stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077,
        f"not a private directory: {path!r}",
    )


def _split_in_dir(path: str, is_dir) -> tuple[str, str]:
    """Split <dir>/<name> where `is_dir(dir)` and name is a plain file name."""
    _require(_is_safe_path(path), f"unsafe path: {path!r}")
    directory, _, name = path.rpartition("/")
    _require(is_dir(directory) and _SAFE_NAME_RE.match(name), f"path not allowed: {path!r}")
    return directory, name


def private_media_probe_script(path: str) -> str:
    """The probe python_podcast_production_db_backup.py.j2 sends under sh -c."""
    quoted = shlex.quote(path)
    return (
        f"if test -L {quoted}; then echo symlink; "
        f"elif test -d {quoted}; then echo present; "
        f"elif test -e {quoted}; then echo notdir; "
        f"else echo missing; fi"
    )


def _check_postgres(policy: Policy, args: list[str], stdin_path: str | None) -> Redirect | None:
    """Check a PostgreSQL client call run as postgres; return its stdin file, if any."""
    tool, rest = args[0], args[1:]
    if tool == "pg_restore" and stdin_path is not None:
        # Restore into a fresh scratch database, the dump read from a root-only
        # temp directory (django_chat_staging_db_backup.py.j2).
        _require(
            len(rest) == 4 and rest[:3] == ["--no-owner", "--no-privileges", "--exit-on-error"],
            "unexpected pg_restore arguments",
        )
        _require(rest[3].startswith("--dbname="), "unexpected pg_restore arguments")
        database = rest[3][len("--dbname="):]
        _require(policy.scratch_database(database), f"pg_restore into {database!r} not allowed")
        directory, name = _split_in_dir(stdin_path, policy.private_temp_dir)
        _require(name.endswith(".dump"), f"pg_restore source not allowed: {stdin_path!r}")
        return Redirect(directory, name)
    _require(stdin_path is None, "input redirection not allowed here")
    if tool == "pg_dump":
        if len(rest) == 2:
            # Dump to stdout (django_chat_staging_db_backup.py.j2).
            _require(rest[0] == "--format=custom" and rest[1].startswith("--dbname="), "unexpected pg_dump arguments")
            database = rest[1][len("--dbname="):]
            _require(database in policy.dump_databases, f"pg_dump of {database!r} not allowed")
            return None
        _require(len(rest) == 3 and rest[0] == "--format=custom", "unexpected pg_dump arguments")
        _require(rest[1].startswith("--file=") and rest[2].startswith("--dbname="), "unexpected pg_dump arguments")
        dump_file = rest[1][len("--file="):]
        database = rest[2][len("--dbname="):]
        _require(database in policy.dump_databases, f"pg_dump of {database!r} not allowed")
        _require(_is_temp_dump(policy, dump_file, ("dump",)), f"pg_dump target not allowed: {dump_file!r}")
        return None
    if tool == "dropdb":
        _require(len(rest) == 3 and rest[:2] == ["--if-exists", "--force"], "unexpected dropdb arguments")
        _require(rest[2] in policy.restore_databases, f"dropdb of {rest[2]!r} not allowed")
        return None
    if tool == "createdb":
        if len(rest) == 1:
            _require(policy.scratch_database(rest[0]), f"createdb {rest[0]!r} not allowed")
            return None
        _require(len(rest) == 2 and rest[0].startswith("--owner="), "unexpected createdb arguments")
        database, owner = rest[1], rest[0][len("--owner="):]
        _require(policy.restore_databases.get(database) == owner, f"createdb {database!r} owner {owner!r} not allowed")
        return None
    if tool == "pg_restore":
        _require(len(rest) == 5, "unexpected pg_restore arguments")
        _require(rest[0] == "--exit-on-error" and rest[2] == "--no-owner", "unexpected pg_restore arguments")
        _require(rest[1].startswith("--dbname=") and rest[3].startswith("--role="), "unexpected pg_restore arguments")
        database, role, dump_file = rest[1][len("--dbname="):], rest[3][len("--role="):], rest[4]
        _require(policy.restore_databases.get(database) == role, f"pg_restore into {database!r} as {role!r} not allowed")
        _require(_is_temp_dump(policy, dump_file, ("restore",)), f"pg_restore source not allowed: {dump_file!r}")
        return None
    if tool == "psql":
        if len(rest) == 4:
            _require(rest[0] == "-d" and rest[2:] == ["-c", "SELECT 1"], "unexpected psql arguments")
            _require(
                rest[1] in policy.restore_databases or rest[1] in policy.dump_databases,
                f"psql on {rest[1]!r} not allowed",
            )
            return None
        # The read-only queries of django_chat_staging_db_backup.py.j2.
        _require(len(rest) == 8 and rest[:5] == _PSQL_RUNNER_PREFIX and rest[6] == "-c", "unexpected psql arguments")
        database, sql = rest[5], rest[7]
        if sql == _SQL_SERVER_VERSION:
            _require(database in policy.dump_databases, f"psql on {database!r} not allowed")
            return None
        exists = _SQL_DB_EXISTS_RE.match(sql)
        if exists:
            _require(database == "postgres" and policy.scratch_database(exists.group(1)), "psql query not allowed")
            return None
        _require(_SQL_COUNT_RE.match(sql) and policy.scratch_database(database), "psql query not allowed")
        return None
    raise Refused(f"postgres tool not allowed: {tool!r}")


def _check_sqlite(policy: Policy, user: str, args: list[str]) -> None:
    """sqlite3 as the service user: online .backup into its temp dir, integrity check."""
    _require(len(args) in (3, 4) and args[0] == "sqlite3", "unexpected command for a service user")
    if len(args) == 4:
        # sqlite3 <db> ".timeout <ms>" ".backup '<snapshot>'"
        _require(_SQLITE_TIMEOUT_RE.match(args[2]) and args[3].startswith(".backup "), "unexpected sqlite3 arguments")
        args = [args[0], args[1], args[3]]
    for snapshot in policy.sqlite_snapshots:
        if snapshot.user != user:
            continue
        in_temp = _temp_dir_re(snapshot.temp_dir)
        backup = _SQLITE_BACKUP_RE.match(args[2])
        if args[1] == snapshot.database and backup:
            directory, _, name = backup.group(1).rpartition("/")
            if in_temp.match(directory) and _SAFE_NAME_RE.match(name):
                return
        directory, _, name = args[1].rpartition("/")
        if args[2] == _SQLITE_INTEGRITY and in_temp.match(directory) and _SAFE_NAME_RE.match(name):
            return
    raise Refused(f"sqlite3 call not allowed for {user!r}")


def _check_scp(policy: Policy, args: list[str], realpath, lstat) -> str | None:
    """Check scp -f/-t; return the user an upload runs as (None: download, as root)."""
    _require(len(args) == 3 and args[1] in ("-f", "-t"), "unexpected scp arguments")
    mode, path = args[1], args[2]
    _require(_is_safe_path(path), f"unsafe scp path: {path!r}")
    if mode == "-f":
        if _is_temp_dump(policy, path, ("dump",)):
            # Written by pg_dump as postgres.
            _require_plain_file_or_absent(path, lstat, "scp source", owner="postgres")
            return None
        if policy.private_media_paths and _PRIVATE_ARCHIVE_RE.match(path):
            _require_private_dir(path.rpartition("/")[0], lstat)
            _require_plain_file_or_absent(path, lstat, "scp source")
            return None
        if path not in policy.read_files:
            _require_in_roots(policy, path, realpath)
        _require_plain_file_or_absent(realpath(path), lstat, "scp source")
        return None
    # Upload: onto a new path or an existing plain file, never through a symlink,
    # and as the target's owner (the scp sink takes the file mode from the sender).
    if _is_temp_dump(policy, path, ("restore",)):
        # Read by pg_restore as postgres.
        _require_plain_file_or_absent(path, lstat, "scp target", owner="postgres")
        return "postgres"
    _require(path.endswith(_UPLOAD_SUFFIXES), f"scp upload target not allowed: {path!r}")
    _root, owner = _require_in_roots(policy, path, realpath)
    _require_plain_file_or_absent(path, lstat, "scp target")
    return owner.split(":", 1)[0]


def _check_rsync(policy: Policy, args: list[str], realpath) -> str | None:
    """Check an rsync server call; return the user a receiver runs as (None: sender, as root)."""
    _require(len(args) >= 5 and args[-2] == ".", "unexpected rsync arguments")
    _require(tuple(args[1:-2]) in RSYNC_SERVER_ARGS, "unexpected rsync options")
    path = args[-1]
    _require(path.endswith("/"), "rsync path must be a directory with a trailing slash")
    _root, owner = _require_in_roots(policy, path.rstrip("/"), realpath)
    # The receiver runs as the root's owner: -o/-g are ignored, setuid bits
    # and devices cannot be created as root.
    return None if args[2] == "--sender" else owner.split(":", 1)[0]


def _check_chown(policy: Policy, args: list[str], realpath, lstat) -> Mutation:
    if len(args) == 3:
        snapshot = policy.snapshot_for_temp_dir(args[2])
        if snapshot is not None:
            # Hand a fresh snapshot temp dir (root's, from mktemp) to the service user.
            _require(args[1] == snapshot.owner, f"owner {args[1]!r} not allowed for {args[2]!r}")
            _require_private_dir(args[2], lstat)
            return Mutation("chown", [args[2]], owner=args[1], private=True)
    if len(args) == 4 and args[1] == "-R":
        owner, path = args[2], args[3]
    else:
        _require(len(args) == 3, "unexpected chown arguments")
        owner, path = args[1], args[2]
    _root, root_owner = _require_mutable(policy, path, realpath)
    _require(owner == root_owner, f"owner {owner!r} not allowed for {path!r}")
    return Mutation("chown", [path], owner=owner, recursive=len(args) == 4)


def check(command: str, policy: Policy, realpath=os.path.realpath, lstat=os.lstat) -> Decision:
    """Return what to execute for an allowed command, or raise Refused."""
    _require(command and len(command) <= MAX_COMMAND_LENGTH, "empty or oversized command")
    _require("\n" not in command and "\0" not in command and "\r" not in command, "control characters in command")

    tar_match = _TAR_RE.match(command)
    if tar_match:
        args = shlex.split(tar_match.group(1))
        _require(len(args) == 7 and args[1] == "-C" and args[3] == "-czf" and args[5] == "--", "unexpected tar arguments")
        parent, archive, root_name = args[2], args[4], args[6]
        _require(_SAFE_NAME_RE.match(root_name) and _is_safe_path(parent), "unexpected tar arguments")
        _require(f"{parent}/{root_name}" in policy.private_media_paths, "tar source not allowed")
        _require(_PRIVATE_ARCHIVE_RE.match(archive), f"tar archive path not allowed: {archive!r}")
        # Only into root's own fresh mktemp dir: nobody else can have put a
        # symlink there for tar to write through.
        _require_private_dir(archive.rpartition("/")[0], lstat)
        _require_plain_file_or_absent(archive, lstat, "tar archive")
        return Decision(argv=args, umask=0o077)

    cat_match = _CAT_TO_FILE_RE.match(command)
    if cat_match:
        # A restore dump sent on stdin into a root-only temp directory.
        directory, name = _split_in_dir(cat_match.group(1), policy.private_temp_dir)
        _require(name.endswith(".dump"), f"upload target not allowed: {name!r}")
        return Decision(argv=["cat"], umask=0o077, stdout=Redirect(directory, name))

    try:
        args = shlex.split(command)
    except ValueError as exc:
        raise Refused(f"unparsable command: {exc}") from exc
    _require(args, "empty command")
    stdin_path = None
    if len(args) >= 3 and args[-2] == "<":
        stdin_path, args = args[-1], args[:-2]
    tool = args[0]
    _require(stdin_path is None or tool == "runuser", "input redirection not allowed here")

    if tool == "sudo":
        _require(len(args) >= 4 and args[1:3] == ["-u", "postgres"], "only sudo -u postgres is allowed")
        _check_postgres(policy, args[3:], None)
        return Decision(argv=["sudo", "-n", "-u", "postgres", "--", *args[3:]])

    if tool == "runuser":
        _require(len(args) >= 5 and args[1] == "-u" and args[3] == "--", "unexpected runuser arguments")
        if args[2] == "postgres":
            return Decision(argv=args, stdin=_check_postgres(policy, args[4:], stdin_path))
        _require(stdin_path is None, "input redirection not allowed here")
        _check_sqlite(policy, args[2], args[4:])
        return Decision(argv=args)

    if tool == "systemctl":
        if len(args) == 5 and args[1:4] == ["show", "--property=LoadState", "--value"]:
            _require(args[4] in policy.units, f"unit not allowed: {args[4]!r}")
            return Decision(argv=args)
        _require(len(args) == 3 and args[1] in ("start", "stop"), "unexpected systemctl arguments")
        _require(args[2] in policy.units, f"unit not allowed: {args[2]!r}")
        return Decision(argv=args)

    if tool == "scp":
        user = _check_scp(policy, args, realpath, lstat)
        return Decision(argv=args if user is None else ["runuser", "-u", user, "--", *args])

    if tool == "rsync":
        user = _check_rsync(policy, args, realpath)
        return Decision(argv=args if user is None else ["runuser", "-u", user, "--", *args])

    if tool == "rm":
        if args[1:2] == ["-f"] and len(args) == 3 and _is_temp_dump(policy, args[2], ("dump", "restore")):
            return Decision(argv=args)
        if args[1:2] == ["-f"] and len(args) == 4:
            wal, shm = args[2], args[3]
            _require(wal.endswith("-wal") and shm.endswith("-shm") and wal[:-4] == shm[:-4], "unexpected rm arguments")
            _require_in_roots(policy, wal[:-4], realpath)
            _root, owner = _require_mutable(policy, wal, realpath)
            _require_mutable(policy, shm, realpath)
            return Decision(argv=[], mutation=Mutation("rm", [wal, shm], user=owner.split(":", 1)[0]))
        if args[1:3] == ["-rf", "--"] and len(args) == 4:
            target = args[3]
            _require(
                (policy.private_media_paths and _PRIVATE_TMP_DIR_RE.match(target))
                or policy.private_temp_dir(target)
                or policy.snapshot_for_temp_dir(target),
                f"rm -rf target not allowed: {target!r}",
            )
            return Decision(argv=args)
        raise Refused("unexpected rm arguments")

    if tool == "mktemp":
        if args == _PRIVATE_MKTEMP:
            _require(policy.private_media_paths, "unexpected mktemp arguments")
            return Decision(argv=args)
        _require(len(args) == 3 and args[1] == "-d", "unexpected mktemp arguments")
        templates = set(policy.temp_dirs) | {s.temp_dir for s in policy.sqlite_snapshots}
        _require(args[2] in templates, f"mktemp template not allowed: {args[2]!r}")
        return Decision(argv=args)

    if tool == "cat":
        # Read a SQLite snapshot out of its temp dir. The service user owns that
        # directory, so the guard opens the file itself (no symlinks, one link).
        _require(len(args) == 2, "unexpected cat arguments")
        directory, name = _split_in_dir(args[1], lambda d: policy.snapshot_for_temp_dir(d) is not None)
        snapshot = policy.snapshot_for_temp_dir(directory)
        assert snapshot is not None
        return Decision(argv=["cat"], stdin=Redirect(directory, name, owners=(snapshot.user,)))

    if tool == "sha256sum":
        # Only inside a root-only temp dir, where nobody else can place a symlink.
        _require(len(args) == 2, "unexpected sha256sum arguments")
        directory, name = _split_in_dir(args[1], policy.private_temp_dir)
        _require(name.endswith(".dump"), f"sha256sum target not allowed: {args[1]!r}")
        _require_private_dir(directory, lstat)
        _require_plain_file_or_absent(args[1], lstat, "sha256sum target")
        return Decision(argv=args)

    if tool == "du":
        _require(len(args) == 4 and args[1:3] == ["-sb", "--"], "unexpected du arguments")
        _require(args[3] in policy.private_media_paths, f"du target not allowed: {args[3]!r}")
        return Decision(argv=args)

    if tool == "sh":
        _require(len(args) == 3 and args[1] == "-c", "unexpected sh arguments")
        allowed = {private_media_probe_script(p) for p in policy.private_media_paths}
        _require(args[2] in allowed, "sh script not allowed")
        return Decision(argv=["sh", "-c", args[2]])

    if tool == "readlink":
        _require(len(args) == 3 and args[1] == "-f", "unexpected readlink arguments")
        _require_in_roots(policy, args[2], realpath)
        return Decision(argv=args)

    if tool == "test":
        _require(len(args) == 3 and args[1] in ("-e", "-d", "-f"), "unexpected test arguments")
        _require_in_roots(policy, args[2], realpath)
        return Decision(argv=args)

    if tool == "mv":
        _require(len(args) == 3, "unexpected mv arguments")
        source, target = args[1], args[2]
        source_root = _require_mutable(policy, source, realpath)
        target_root = _require_mutable(policy, target, realpath)
        replace = source == target + ".tmp"
        if not replace:
            # Anything but putting an uploaded <path>.tmp in place: a rename
            # within one root onto a name that does not exist yet.
            _require(source_root == target_root, "mv across roots not allowed")
            _require(_lstat_or_none(target, lstat, "mv target") is None, f"mv target exists: {target!r}")
        return Decision(argv=[], mutation=Mutation("mv", [source, target], replace=replace,
                                                   user=target_root[1].split(":", 1)[0]))

    if tool == "mkdir":
        # As the root's owner, like the uploads that fill the directory.
        _require(len(args) == 3 and args[1] == "-p", "unexpected mkdir arguments")
        _root, owner = _require_in_roots(policy, args[2], realpath)
        return Decision(argv=["runuser", "-u", owner.split(":", 1)[0], "--", *args])

    if tool == "chmod":
        _require(len(args) == 3 and args[1] in _CHMOD_MODES, "unexpected chmod arguments")
        _root, owner = _require_mutable(policy, args[2], realpath)
        return Decision(argv=[], mutation=Mutation("chmod", [args[2]], mode=int(args[1], 8),
                                                   user=owner.split(":", 1)[0]))

    if tool == "chown":
        return Decision(argv=[], mutation=_check_chown(policy, args, realpath, lstat))

    if tool == "curl":
        _require(len(args) == 5 and args[1:4] == ["-fsS", "-o", "/dev/null"], "unexpected curl arguments")
        _require(args[4] in policy.ready_urls, f"URL not allowed: {args[4]!r}")
        return Decision(argv=args)

    raise Refused(f"command not allowed: {tool!r}")


def _user_uids(users: tuple[str, ...], include_self: bool = True) -> set[int]:
    uids = {os.geteuid()} if include_self else set()
    for user in users:
        try:
            uids.add(pwd.getpwnam(user).pw_uid)
        except KeyError:
            pass
    return uids


def open_redirect(redirect: Redirect, create: bool) -> int:
    """Open a Redirect's file without following symlinks; return the fd."""
    dir_fd = os.open(redirect.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(dir_fd)
        _require(st.st_uid in _user_uids(redirect.owners), f"unexpected owner of {redirect.directory!r}")
        _require(not st.st_mode & 0o077, f"{redirect.directory!r} is accessible to others")
        if create:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        else:
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(redirect.name, flags, 0o600, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise Refused(f"not a plain file: {redirect.directory}/{redirect.name}")
    os.set_blocking(fd, True)
    return fd


# --- Mutations: made by the guard itself, on file descriptors ----------------
#
# perform() never hands a pathname to a tool or to a path-based system call.
# It opens / and then each directory of the path with O_NOFOLLOW|O_DIRECTORY,
# so a symlink anywhere on the path is refused (ELOOP/ENOTDIR) instead of
# followed, and it works on the last entry relative to the directory it
# opened: renameat (renameat2 RENAME_NOREPLACE when the target must not
# exist)/unlinkat on the name, or fchmod/fchown on a descriptor opened with
# O_NOFOLLOW whose inode must be the one lstat saw. chown -R walks
# the tree the same way, one directory descriptor per level, and leaves
# symlinks in it as they are. A regular file to change must have one link,
# so a hard link cannot bring a file from outside the root into it.
#
# Paths in the reasons are ascii(): a name in a tree the service user filled
# is escaped like everything else that reaches the log. chown -R visits names
# in byte order.
#
# `hook(event, path)`, for the tests only: called with ("dir", <path>) after
# each directory on the way was opened, with ("stat", <path>) after an entry
# passed lstat, right before it is opened, and with ("rename", <target>)
# right before mv renames.

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_NODE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY


class _OsRefused(Refused):
    """Refused because of an OS error; `errno` tells rm -f a missing path."""

    def __init__(self, what: str, path: str, exc: OSError) -> None:
        super().__init__(f"{what}: {path!a}: {exc.strerror}")
        self.errno = exc.errno


def _is_link(dir_fd: int, name: str) -> bool:
    """Whether a failed O_NOFOLLOW open met a symlink (Linux says ELOOP, macOS ENOTDIR)."""
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def _open_parent(path: str, hook) -> tuple[int, str]:
    """Open the directory holding `path` from /, following no symlink: (fd, name)."""
    parts = path.split("/")[1:]
    _require(path.startswith("/") and parts and all(p not in ("", ".", "..") for p in parts), f"unsafe path: {path!a}")
    try:
        fd = os.open("/", _DIR_FLAGS)
    except OSError as exc:
        raise _OsRefused("cannot open", "/", exc) from exc
    prefix = ""
    try:
        for part in parts[:-1]:
            prefix += "/" + part
            try:
                next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                if _is_link(fd, part):
                    raise Refused(f"symbolic link in the path: {prefix!a}") from exc
                raise _OsRefused("cannot open", prefix, exc) from exc
            os.close(fd)
            fd = next_fd
            if hook is not None:
                hook("dir", prefix)
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]


def _open_entry(dir_fd: int, name: str, path: str, op: str, hook, skip_links: bool = False):
    """Open the entry `name` of `dir_fd` without following it: (fd, fstat), or
    None for a symlink with `skip_links`. Only a directory or a regular file
    with one link, and only the inode lstat saw."""
    try:
        seen = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as exc:
        raise _OsRefused("cannot stat", path, exc) from exc
    if stat.S_ISLNK(seen.st_mode):
        if skip_links:
            return None
        raise Refused(f"{op} target is a symbolic link: {path!a}")
    is_dir = stat.S_ISDIR(seen.st_mode)
    _require(is_dir or stat.S_ISREG(seen.st_mode), f"{op} target is not a regular file or directory: {path!a}")
    if hook is not None:
        hook("stat", path)
    try:
        fd = os.open(name, _NODE_FLAGS | (os.O_DIRECTORY if is_dir else 0), dir_fd=dir_fd)
    except OSError as exc:
        if _is_link(dir_fd, name):
            raise Refused(f"{op} target is a symbolic link: {path!a}") from exc
        raise _OsRefused("cannot open", path, exc) from exc
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise _OsRefused("cannot stat", path, exc) from exc
        _require((st.st_dev, st.st_ino) == (seen.st_dev, seen.st_ino), f"{op} target was replaced: {path!a}")
        _require(stat.S_ISDIR(st.st_mode) or st.st_nlink == 1, f"{op} target has other hard links: {path!a}")
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def _owner_ids(owner: str) -> tuple[int, int]:
    user, _, group = owner.partition(":")
    try:
        return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError:
        raise Refused(f"unknown owner: {owner!a}") from None


def _fchown(fd: int, uid: int, gid: int, path: str) -> None:
    try:
        os.fchown(fd, uid, gid)
    except OSError as exc:
        raise _OsRefused("chown failed", path, exc) from exc


def _chown_tree(top_fd: int, top: str, uid: int, gid: int, hook) -> None:
    """chown -R below the directory `top_fd`; one open directory per level."""

    def entries(fd: int, path: str):
        try:
            return iter(sorted(os.listdir(fd), key=os.fsencode))
        except OSError as exc:
            raise _OsRefused("cannot list", path, exc) from exc

    stack = [(top_fd, top, entries(top_fd, top))]
    try:
        while stack:
            dir_fd, dir_path, names = stack[-1]
            name = next(names, None)
            if name is None:
                stack.pop()
                if dir_fd != top_fd:
                    os.close(dir_fd)
                continue
            path = f"{dir_path}/{name}"
            opened = _open_entry(dir_fd, name, path, "chown", hook, skip_links=True)
            if opened is None:
                continue  # a symlink: neither followed nor changed
            fd, st = opened
            try:
                _fchown(fd, uid, gid, path)
                if stat.S_ISDIR(st.st_mode):
                    stack.append((fd, path, entries(fd, path)))
                    fd = -1
            finally:
                if fd != -1:
                    os.close(fd)
    finally:
        for dir_fd, _path, _names in stack:
            if dir_fd != top_fd:
                os.close(dir_fd)


def _change(mutation: Mutation, hook) -> None:
    """chmod or chown of one path (chown -R: and everything below it)."""
    _require(len(mutation.paths) == 1 and (mutation.op == "chown" or mutation.mode is not None),
             f"unusable mutation: {mutation.op!a}")
    path = mutation.paths[0]
    uid, gid = _owner_ids(mutation.owner or "") if mutation.op == "chown" else (-1, -1)
    dir_fd, name = _open_parent(path, hook)
    try:
        fd, st = _open_entry(dir_fd, name, path, mutation.op, hook)
    finally:
        os.close(dir_fd)
    try:
        if mutation.op == "chmod":
            try:
                os.fchmod(fd, mutation.mode)  # type: ignore[arg-type]
            except OSError as exc:
                raise _OsRefused("chmod failed", path, exc) from exc
            return
        if mutation.private:
            # Still the fresh snapshot temp dir check() saw: root's, no group/other access.
            _require(
                stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077,
                f"not a private directory: {path!a}",
            )
        _fchown(fd, uid, gid, path)
        if mutation.recursive and stat.S_ISDIR(st.st_mode):
            _chown_tree(fd, path, uid, gid, hook)
    finally:
        os.close(fd)


def _rename_noreplace(source_fd: int, source: str, target_fd: int, target: str) -> None:
    """renameat2(RENAME_NOREPLACE): EEXIST instead of replacing an existing
    target, in one step (macOS, for the tests: renameatx_np(RENAME_EXCL))."""
    libc = ctypes.CDLL(None, use_errno=True)
    for symbol, flag in (("renameat2", 1), ("renameatx_np", 4)):
        function = getattr(libc, symbol, None)
        if function is not None:
            break
    else:
        raise OSError(errno.ENOSYS, os.strerror(errno.ENOSYS))
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_fd, os.fsencode(source), target_fd, os.fsencode(target), flag) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _rename(mutation: Mutation, hook) -> None:
    _require(len(mutation.paths) == 2, "unusable mutation: 'mv'")
    source, target = mutation.paths
    source_fd, source_name = _open_parent(source, hook)
    try:
        target_fd, target_name = _open_parent(target, hook)
        try:
            if hook is not None:
                hook("rename", target)
            try:
                if mutation.replace:
                    os.rename(source_name, target_name, src_dir_fd=source_fd, dst_dir_fd=target_fd)
                else:
                    # A rename onto a name that does not exist yet: never replaces one.
                    _rename_noreplace(source_fd, source_name, target_fd, target_name)
            except OSError as exc:
                if exc.errno == errno.EEXIST and not mutation.replace:
                    raise Refused(f"mv target exists: {target!a}") from exc
                raise Refused(f"mv failed: {source!a} -> {target!a}: {exc.strerror}") from exc
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)


def _remove(mutation: Mutation, hook) -> None:
    """rm -f: a missing path (or directory on its way) is fine."""
    for path in mutation.paths:
        try:
            dir_fd, name = _open_parent(path, hook)
        except _OsRefused as exc:
            if exc.errno == errno.ENOENT:
                continue
            raise
        try:
            os.unlink(name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise _OsRefused("rm failed", path, exc) from exc
        finally:
            os.close(dir_fd)


def become(user: str) -> None:
    """Drop to `user` for good (supplementary groups, gid, uid), when running as
    root: chmod, mv and rm then only do what the root's owner could do itself,
    whatever it changes in its tree meanwhile. Not root (tests): unchanged."""
    if os.geteuid() != 0:
        return
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        raise Refused(f"unknown user: {user!a}") from None
    _require(entry.pw_uid != 0, f"will not run as root: {user!a}")
    os.setgroups([entry.pw_gid])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)
    _require(os.geteuid() == entry.pw_uid and os.getuid() == entry.pw_uid, f"cannot run as {user!a}")


def perform(mutation: Mutation, hook=None) -> None:
    """Make the change a mutation decision describes; raise Refused if it cannot."""
    if mutation.op in ("chmod", "chown"):
        _change(mutation, hook)
    elif mutation.op == "mv":
        _rename(mutation, hook)
    elif mutation.op == "rm":
        _remove(mutation, hook)
    else:
        raise Refused(f"unknown mutation: {mutation.op!a}")


def _log(priority: int, message: str) -> None:
    try:
        syslog.openlog(PROGRAM, syslog.LOG_PID, syslog.LOG_AUTH)
        syslog.syslog(priority, message[:1000])
    except OSError:
        pass


def load_policy(path: str) -> Policy:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise Refused("policy must be a JSON object")
    return Policy.from_dict(data)


_POLICY_ERRORS = (Refused, OSError, ValueError, KeyError, TypeError, AttributeError)


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "--check-policy":
        try:
            load_policy(argv[2])
        except _POLICY_ERRORS as exc:
            print(f"{PROGRAM}: invalid policy: {exc}", file=sys.stderr)
            return 1
        return 0
    if len(argv) != 2:
        print(f"{PROGRAM}: usage: {PROGRAM} <policy.json> | --check-policy <policy.json>", file=sys.stderr)
        return 2
    command = os.environ.get("SSH_ORIGINAL_COMMAND")
    client = os.environ.get("SSH_CLIENT", "-").split(" ")[0]
    if command is None:
        _log(syslog.LOG_WARNING, f"refused interactive session from {client}")
        print(f"{PROGRAM}: interactive sessions are not allowed", file=sys.stderr)
        return 1
    try:
        policy = load_policy(argv[1])
    except _POLICY_ERRORS as exc:
        _log(syslog.LOG_ERR, f"policy error ({type(exc).__name__}): refusing {command!r}")
        print(f"{PROGRAM}: policy error", file=sys.stderr)
        return 1
    try:
        decision = check(command, policy)
        if decision.mutation is not None:
            # Made here, on file descriptors; nothing is executed. chmod, mv and
            # rm as the root's owner, chown as root.
            if decision.mutation.user is not None:
                become(decision.mutation.user)
            perform(decision.mutation)
        if decision.umask is not None:
            os.umask(decision.umask)
        for redirect, target, create in ((decision.stdin, 0, False), (decision.stdout, 1, True)):
            if redirect is not None:
                fd = open_redirect(redirect, create)
                os.dup2(fd, target)
                os.close(fd)
    except (Refused, OSError) as exc:
        _log(syslog.LOG_WARNING, f"refused from {client}: {exc}: {command!r}")
        print(f"{PROGRAM}: command not allowed", file=sys.stderr)
        return 1

    _log(syslog.LOG_INFO, f"allowed from {client}: {command!r}")
    if decision.mutation is not None:
        return 0
    os.environ["PATH"] = SAFE_PATH
    try:
        os.execvp(decision.argv[0], decision.argv)
    except OSError as exc:
        print(f"{PROGRAM}: cannot run {decision.argv[0]}: {exc.strerror}", file=sys.stderr)
        return 127
    return 0  # pragma: no cover - execvp does not return


if __name__ == "__main__":
    sys.exit(main(sys.argv))
