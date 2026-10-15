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
quoting of the original string cannot smuggle extra commands through.
"""

from __future__ import annotations

import json
import os
import re
import shlex
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
_RSYNC_FLAGS_RE = re.compile(r"^-[A-Za-z.]+$")


class Refused(Exception):
    """The command is not on the allowlist."""


@dataclass
class Policy:
    dump_databases: set[str] = field(default_factory=set)
    restore_databases: dict[str, str] = field(default_factory=dict)
    temp_file_prefixes: list[str] = field(default_factory=list)
    units: set[str] = field(default_factory=set)
    private_media_paths: set[str] = field(default_factory=set)
    path_roots: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        postgres = data.get("postgres") or {}
        policy = cls(
            dump_databases=set(postgres.get("dump_databases") or []),
            restore_databases=dict(postgres.get("restore_databases") or {}),
            temp_file_prefixes=list(postgres.get("temp_file_prefixes") or []),
            units=set(data.get("units") or []),
            private_media_paths={p.rstrip("/") for p in data.get("private_media_paths") or []},
            path_roots=[
                (str(entry["path"]).rstrip("/"), str(entry["owner"]))
                for entry in data.get("path_roots") or []
            ],
        )
        for name in policy.dump_databases | set(policy.restore_databases) | set(policy.restore_databases.values()):
            _require(_SAFE_NAME_RE.match(name), f"invalid database or role name in policy: {name!r}")
        for prefix in policy.temp_file_prefixes:
            _require(re.fullmatch(r"[a-z0-9_]+", prefix), f"invalid temp file prefix in policy: {prefix!r}")
        for unit in policy.units:
            _require(_SAFE_NAME_RE.match(unit), f"invalid unit name in policy: {unit!r}")
        for path in policy.private_media_paths:
            _require(_is_safe_path(path) and path.count("/") >= 2, f"invalid private media path: {path!r}")
        for root, owner in policy.path_roots:
            _require(_is_safe_path(root) and root.count("/") >= 2, f"invalid path root: {root!r}")
            _require(_SAFE_OWNER_RE.match(owner), f"invalid owner for {root}: {owner!r}")
        return policy


@dataclass
class Decision:
    argv: list[str]
    umask: int | None = None


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


def private_media_probe_script(path: str) -> str:
    """The probe python_podcast_production_db_backup.py.j2 sends under sh -c."""
    quoted = shlex.quote(path)
    return (
        f"if test -L {quoted}; then echo symlink; "
        f"elif test -d {quoted}; then echo present; "
        f"elif test -e {quoted}; then echo notdir; "
        f"else echo missing; fi"
    )


def _check_postgres(policy: Policy, args: list[str]) -> None:
    tool, rest = args[0], args[1:]
    if tool == "pg_dump":
        _require(len(rest) == 3 and rest[0] == "--format=custom", "unexpected pg_dump arguments")
        _require(rest[1].startswith("--file=") and rest[2].startswith("--dbname="), "unexpected pg_dump arguments")
        dump_file = rest[1][len("--file="):]
        database = rest[2][len("--dbname="):]
        _require(database in policy.dump_databases, f"pg_dump of {database!r} not allowed")
        _require(_is_temp_dump(policy, dump_file, ("dump",)), f"pg_dump target not allowed: {dump_file!r}")
        return
    if tool == "dropdb":
        _require(len(rest) == 3 and rest[:2] == ["--if-exists", "--force"], "unexpected dropdb arguments")
        _require(rest[2] in policy.restore_databases, f"dropdb of {rest[2]!r} not allowed")
        return
    if tool == "createdb":
        _require(len(rest) == 2 and rest[0].startswith("--owner="), "unexpected createdb arguments")
        database, owner = rest[1], rest[0][len("--owner="):]
        _require(policy.restore_databases.get(database) == owner, f"createdb {database!r} owner {owner!r} not allowed")
        return
    if tool == "pg_restore":
        _require(len(rest) == 5, "unexpected pg_restore arguments")
        _require(rest[0] == "--exit-on-error" and rest[2] == "--no-owner", "unexpected pg_restore arguments")
        _require(rest[1].startswith("--dbname=") and rest[3].startswith("--role="), "unexpected pg_restore arguments")
        database, role, dump_file = rest[1][len("--dbname="):], rest[3][len("--role="):], rest[4]
        _require(policy.restore_databases.get(database) == role, f"pg_restore into {database!r} as {role!r} not allowed")
        _require(_is_temp_dump(policy, dump_file, ("restore",)), f"pg_restore source not allowed: {dump_file!r}")
        return
    if tool == "psql":
        _require(len(rest) == 4 and rest[0] == "-d" and rest[2:] == ["-c", "SELECT 1"], "unexpected psql arguments")
        _require(
            rest[1] in policy.restore_databases or rest[1] in policy.dump_databases,
            f"psql on {rest[1]!r} not allowed",
        )
        return
    raise Refused(f"postgres tool not allowed: {tool!r}")


def _check_scp(policy: Policy, args: list[str], realpath) -> None:
    _require(len(args) == 3 and args[1] in ("-f", "-t"), "unexpected scp arguments")
    mode, path = args[1], args[2]
    _require(_is_safe_path(path), f"unsafe scp path: {path!r}")
    if mode == "-f":
        if _is_temp_dump(policy, path, ("dump",)):
            return
        if policy.private_media_paths and _PRIVATE_ARCHIVE_RE.match(path):
            return
        _require_in_roots(policy, path, realpath)
        return
    if _is_temp_dump(policy, path, ("restore",)):
        return
    _require(path.endswith(".tmp"), f"scp upload target not allowed: {path!r}")
    _require_in_roots(policy, path, realpath)


def _check_rsync(policy: Policy, args: list[str], realpath) -> None:
    _require(len(args) >= 5 and args[1] == "--server", "unexpected rsync arguments")
    rest = args[2:]
    sender = rest[0] == "--sender"
    if sender:
        rest = rest[1:]
    _require(len(rest) >= 3 and _RSYNC_FLAGS_RE.match(rest[0]), "unexpected rsync flags")
    options, dot, path = rest[1:-2], rest[-2], rest[-1]
    allowed_options = {"--safe-links"} if sender else {"--delete"}
    _require(dot == "." and set(options) <= allowed_options and len(options) == len(set(options)), "unexpected rsync options")
    _require(path.endswith("/"), "rsync path must be a directory with a trailing slash")
    _require_in_roots(policy, path.rstrip("/"), realpath)


def check(command: str, policy: Policy, realpath=os.path.realpath) -> Decision:
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
        return Decision(argv=args, umask=0o077)

    try:
        args = shlex.split(command)
    except ValueError as exc:
        raise Refused(f"unparsable command: {exc}") from exc
    _require(args, "empty command")
    tool = args[0]

    if tool == "sudo":
        _require(len(args) >= 4 and args[1:3] == ["-u", "postgres"], "only sudo -u postgres is allowed")
        _check_postgres(policy, args[3:])
        return Decision(argv=["sudo", "-n", "-u", "postgres", "--", *args[3:]])

    if tool == "systemctl":
        if len(args) == 5 and args[1:4] == ["show", "--property=LoadState", "--value"]:
            _require(args[4] in policy.units, f"unit not allowed: {args[4]!r}")
            return Decision(argv=args)
        _require(len(args) == 3 and args[1] in ("start", "stop"), "unexpected systemctl arguments")
        _require(args[2] in policy.units, f"unit not allowed: {args[2]!r}")
        return Decision(argv=args)

    if tool == "scp":
        _check_scp(policy, args, realpath)
        return Decision(argv=args)

    if tool == "rsync":
        _check_rsync(policy, args, realpath)
        return Decision(argv=args)

    if tool == "rm":
        if args[1:2] == ["-f"] and len(args) == 3 and _is_temp_dump(policy, args[2], ("dump", "restore")):
            return Decision(argv=args)
        if args[1:2] == ["-f"] and len(args) == 4:
            wal, shm = args[2], args[3]
            _require(wal.endswith("-wal") and shm.endswith("-shm") and wal[:-4] == shm[:-4], "unexpected rm arguments")
            _require_in_roots(policy, wal[:-4], realpath)
            _require_in_roots(policy, wal, realpath)
            _require_in_roots(policy, shm, realpath)
            return Decision(argv=args)
        if args[1:3] == ["-rf", "--"] and len(args) == 4 and policy.private_media_paths:
            _require(_PRIVATE_TMP_DIR_RE.match(args[3]), f"rm -rf target not allowed: {args[3]!r}")
            return Decision(argv=args)
        raise Refused("unexpected rm arguments")

    if tool == "mktemp":
        _require(args == _PRIVATE_MKTEMP and policy.private_media_paths, "unexpected mktemp arguments")
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
        _require(len(args) == 3 and args[1] in ("-e", "-d"), "unexpected test arguments")
        _require_in_roots(policy, args[2], realpath)
        return Decision(argv=args)

    if tool == "mv":
        _require(len(args) == 3 and args[1] == args[2] + ".tmp", "unexpected mv arguments")
        _require_in_roots(policy, args[1], realpath)
        _require_in_roots(policy, args[2], realpath)
        return Decision(argv=args)

    if tool == "mkdir":
        _require(len(args) == 3 and args[1] == "-p", "unexpected mkdir arguments")
        _require_in_roots(policy, args[2], realpath)
        return Decision(argv=args)

    if tool == "chown":
        if len(args) == 4 and args[1] == "-R":
            owner, path = args[2], args[3]
        else:
            _require(len(args) == 3, "unexpected chown arguments")
            owner, path = args[1], args[2]
        _root, root_owner = _require_in_roots(policy, path, realpath)
        _require(owner == root_owner, f"owner {owner!r} not allowed for {path!r}")
        return Decision(argv=args)

    raise Refused(f"command not allowed: {tool!r}")


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
    except Refused as exc:
        _log(syslog.LOG_WARNING, f"refused from {client}: {exc}: {command!r}")
        print(f"{PROGRAM}: command not allowed", file=sys.stderr)
        return 1

    _log(syslog.LOG_INFO, f"allowed from {client}: {command!r}")
    os.environ["PATH"] = SAFE_PATH
    if decision.umask is not None:
        os.umask(decision.umask)
    try:
        os.execvp(decision.argv[0], decision.argv)
    except OSError as exc:
        print(f"{PROGRAM}: cannot run {decision.argv[0]}: {exc.strerror}", file=sys.stderr)
        return 127
    return 0  # pragma: no cover - execvp does not return


if __name__ == "__main__":
    sys.exit(main(sys.argv))
