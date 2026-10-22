"""Run a registered Echoport backup synchronously and verify its artifact.

The step a deploy (or an explicit backup command) runs before it changes
anything:

1. ``manage.py backup <target> --triggered-by <label>`` on the Echoport host,
   as the Echoport user, from the Echoport site directory. Echoport's command
   blocks until the run has finished and exits non-zero when the target is
   unknown or not active, another run of it is active, it times out, or the
   run fails.
2. Its output is parsed: run ID, ``bucket/key`` and size must be there, the key
   must lie under ``<target>/`` and the size must be positive. A checksum is
   read when the output carries one (Echoport stores it, but its command does
   not print it yet).
3. The object is checked independently of Echoport's own result: ``mc stat``
   through Echoport's mc alias must find a file of exactly that size. With a
   checksum it is also streamed through ``sha256sum`` (``verify_checksum``).

Any failure raises :class:`EchoportBackupError` naming the step; the caller
stops before its first change. On success :class:`EchoportBackupResult` holds
the run ID and object for the deploy's evidence and a restore hint.

The host side needs nothing but bash, Echoport and mc: the scripts below are
sent on stdin through a :data:`~ops_deploy.backups.remote.Runner`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from ops_deploy.backups.remote import CommandResult, RemoteCommandError, Runner

Become = Literal["runuser", "sudo", "none"]

TARGET_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
LABEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,99}")
USER_PATTERN = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
ALIAS_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,63}")
_PATH_PATTERN = re.compile(r"/[A-Za-z0-9._/+@-]*")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_SHA256 = re.compile(r"[0-9a-f]{64}")

# Runs a command as the Echoport user. root uses runuser (no PAM prompt, no
# sudoers entry); a non-root SSH user needs passwordless sudo (-n: never asks).
_PRELUDE = """set -euo pipefail
become=$1
run_as=$2
shift 2
as_user() {
    case "$become" in
        runuser) runuser -u "$run_as" -- "$@" ;;
        sudo) sudo -n -H -u "$run_as" -- "$@" ;;
        none) "$@" ;;
        *) echo "unknown become method: $become" >&2; return 2 ;;
    esac
}
"""

BACKUP_SCRIPT = (
    _PRELUDE
    + """site=$1
python=$2
target=$3
triggered_by=$4
cd "$site"
as_user "$python" manage.py backup "$target" --triggered-by "$triggered_by"
"""
)

STAT_SCRIPT = (
    _PRELUDE
    + """mc=$1
object=$2
as_user "$mc" stat --json "$object"
"""
)

CHECKSUM_SCRIPT = (
    _PRELUDE
    + """mc=$1
object=$2
as_user "$mc" cat "$object" | sha256sum
"""
)


class EchoportBackupError(RuntimeError):
    """The backup or its verification failed; nothing after it may run."""


def _require(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def _require_path(value: str, what: str) -> str:
    if not _PATH_PATTERN.fullmatch(value) or value == "/" or ".." in value.split("/"):
        raise ValueError(f"{what} must be an absolute path without '..' (got {value!r})")
    return value


@dataclass(frozen=True)
class EchoportSite:
    """Where Echoport runs on its host and how its user reaches MinIO.

    ``python`` defaults to the site's ``.venv``. ``become`` is ``runuser`` when
    the SSH user is root, ``sudo`` for a user with passwordless sudo, ``none``
    when the SSH user is the Echoport user.
    """

    site_path: str
    user: str
    minio_alias: str
    python: str | None = None
    mc_path: str = "/usr/local/bin/mc"
    become: Become = "runuser"

    def __post_init__(self) -> None:
        _require_path(self.site_path, "site_path")
        _require(USER_PATTERN, self.user, "Echoport user")
        _require(ALIAS_PATTERN, self.minio_alias, "mc alias")
        _require_path(self.python_path, "python")
        _require_path(self.mc_path, "mc_path")
        if self.become not in ("runuser", "sudo", "none"):
            raise ValueError(f"invalid become method: {self.become!r}")

    @property
    def python_path(self) -> str:
        return self.python or f"{self.site_path}/.venv/bin/python"

    def object_path(self, bucket: str, key: str) -> str:
        return f"{self.minio_alias}/{bucket}/{key}"


@dataclass(frozen=True)
class ReportedRun:
    """What ``manage.py backup`` printed for a successful run."""

    run_id: int
    bucket: str
    key: str
    size_bytes: int
    checksum_sha256: str | None


@dataclass(frozen=True)
class EchoportBackupResult:
    """A verified backup run: the evidence a deploy records."""

    target: str
    triggered_by: str
    run_id: int
    bucket: str
    key: str
    size_bytes: int
    checksum_sha256: str | None
    checksum_verified: bool
    object_size: int
    object_last_modified: str | None
    started_at: str
    finished_at: str

    @property
    def object(self) -> str:
        return f"{self.bucket}/{self.key}"

    @property
    def restore_hint(self) -> str:
        return f"manage.py restore {self.target} {self.run_id}"

    def as_record(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "triggered_by": self.triggered_by,
            "run_id": self.run_id,
            "object": self.object,
            "size_bytes": self.size_bytes,
            "checksum_sha256": self.checksum_sha256,
            "checksum_verified": self.checksum_verified,
            "object_size": self.object_size,
            "object_last_modified": self.object_last_modified,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "restore": self.restore_hint,
        }


def _field(lines: list[str], name: str) -> str | None:
    prefix = f"{name}:"
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return None


def parse_backup_output(target: str, stdout: str) -> ReportedRun:
    """The run ``manage.py backup`` reported, or :class:`EchoportBackupError`."""

    lines = [_ANSI.sub("", line).strip() for line in stdout.splitlines()]
    if "Backup completed successfully!" not in lines:
        raise EchoportBackupError(f"{target}: Echoport did not report a successful run")
    run_id = _field(lines, "Run ID")
    storage = _field(lines, "Storage")
    size = _field(lines, "Size")
    if run_id is None or not run_id.isdigit() or int(run_id) <= 0:
        raise EchoportBackupError(f"{target}: no run ID in Echoport's output")
    if storage is None or "/" not in storage:
        raise EchoportBackupError(f"{target}: run {run_id}: no bucket/key in Echoport's output")
    bucket, key = storage.split("/", 1)
    parts = key.split("/")
    if not bucket or not key.startswith(f"{target}/") or "" in parts or ".." in parts or "." in parts:
        raise EchoportBackupError(f"{target}: run {run_id}: object {storage!r} is not under {target}/")
    match = re.fullmatch(r"([0-9][0-9,]*) bytes", size or "")
    if match is None or int(match.group(1).replace(",", "")) <= 0:
        raise EchoportBackupError(f"{target}: run {run_id}: no positive size in Echoport's output (got {size!r})")
    checksum = None
    for name in ("Checksum", "SHA256", "SHA-256", "Checksum (sha256)"):
        value = _field(lines, name)
        if value is not None:
            if not _SHA256.fullmatch(value.lower()):
                raise EchoportBackupError(f"{target}: run {run_id}: malformed checksum {value!r}")
            checksum = value.lower()
    return ReportedRun(int(run_id), bucket, key, int(match.group(1).replace(",", "")), checksum)


def parse_stat_output(stdout: str) -> tuple[int, str | None]:
    """Size and last-modified time of the file ``mc stat --json`` reported."""

    records: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    if len(records) != 1:
        raise EchoportBackupError(f"mc stat returned {len(records)} objects, expected exactly one")
    record = records[0]
    size = record.get("size")
    if record.get("status") != "success" or record.get("type", "file") != "file" or not isinstance(size, int):
        raise EchoportBackupError("mc stat did not report a file with a size")
    modified = record.get("lastModified")
    return size, modified if isinstance(modified, str) else None


def _run(runner: Runner, script: str, args: list[str], timeout: float, step: str) -> CommandResult:
    try:
        return runner(script, args, timeout)
    except RemoteCommandError as exc:
        raise EchoportBackupError(f"{step}: {exc}") from exc


def _tail(result: CommandResult) -> str:
    text = (result.stderr.strip() or result.stdout.strip()).splitlines()
    return text[-1] if text else "no output"


def _now() -> datetime:
    return datetime.now(UTC)


def run_echoport_backup(
    runner: Runner,
    site: EchoportSite,
    target: str,
    *,
    triggered_by: str,
    timeout: float = 3 * 3600,
    check_timeout: float = 120,
    checksum_timeout: float = 3600,
    verify_checksum: bool = True,
    clock: Callable[[], datetime] = _now,
) -> EchoportBackupResult:
    """Run ``target``'s backup now, wait for it and verify the artifact.

    ``runner`` reaches the Echoport host. ``timeout`` bounds the whole backup
    (Echoport has its own per-target timeout below it); ``check_timeout`` the
    ``mc stat``. Raises :class:`EchoportBackupError` on any failure and
    :class:`ValueError` on a malformed target or label.
    """

    _require(TARGET_PATTERN, target, "Echoport target")
    _require(LABEL_PATTERN, triggered_by, "triggered-by label")
    become = [site.become, site.user]
    started = clock()

    backup = _run(
        runner,
        BACKUP_SCRIPT,
        [*become, site.site_path, site.python_path, target, triggered_by],
        timeout,
        f"{target}: backup",
    )
    if not backup.ok:
        raise EchoportBackupError(f"{target}: backup failed (exit {backup.returncode}): {_tail(backup)}")
    run = parse_backup_output(target, backup.stdout)

    object_path = site.object_path(run.bucket, run.key)
    stat = _run(runner, STAT_SCRIPT, [*become, site.mc_path, object_path], check_timeout, f"{target}: mc stat")
    if not stat.ok:
        raise EchoportBackupError(
            f"{target}: run {run.run_id}: object {run.bucket}/{run.key} not found in MinIO: {_tail(stat)}"
        )
    try:
        object_size, modified = parse_stat_output(stat.stdout)
    except EchoportBackupError as exc:
        raise EchoportBackupError(f"{target}: run {run.run_id}: {exc}") from None
    if object_size != run.size_bytes:
        raise EchoportBackupError(
            f"{target}: run {run.run_id}: object is {object_size} bytes, Echoport reported {run.size_bytes}"
        )

    verified = False
    if run.checksum_sha256 is not None and verify_checksum:
        digest = _run(
            runner, CHECKSUM_SCRIPT, [*become, site.mc_path, object_path], checksum_timeout, f"{target}: checksum"
        )
        actual = digest.stdout.split()[0].lower() if digest.ok and digest.stdout.split() else ""
        if not _SHA256.fullmatch(actual):
            raise EchoportBackupError(f"{target}: run {run.run_id}: could not hash the object: {_tail(digest)}")
        if actual != run.checksum_sha256:
            raise EchoportBackupError(f"{target}: run {run.run_id}: object checksum differs from Echoport's")
        verified = True

    return EchoportBackupResult(
        target=target,
        triggered_by=triggered_by,
        run_id=run.run_id,
        bucket=run.bucket,
        key=run.key,
        size_bytes=run.size_bytes,
        checksum_sha256=run.checksum_sha256,
        checksum_verified=verified,
        object_size=object_size,
        object_last_modified=modified,
        started_at=started.isoformat(timespec="seconds"),
        finished_at=clock().isoformat(timespec="seconds"),
    )
