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

A target whose run stores a prefix of objects plus a ``manifest.json``
(``artifact="manifest"``, the rclone media runners) has no single object to
``mc stat``; its gate replaces step 3, see :func:`run_echoport_backup` and
"Manifest artifacts" in the Backups documentation page.

Any failure raises :class:`EchoportBackupError` naming the step; the caller
stops before its first change. On success :class:`EchoportBackupResult` holds
the run ID and object for the deploy's evidence and a restore hint.

The host side needs nothing but bash, Echoport and mc: the scripts below are
sent on stdin through a :data:`~ops_deploy.backups.remote.Runner`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from ops_deploy.backups.remote import CommandResult, RemoteCommandError, Runner

Become = Literal["runuser", "sudo", "none"]
Artifact = Literal["file", "manifest"]

TARGET_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
LABEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,99}")
USER_PATTERN = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
ALIAS_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,63}")
_PATH_PATTERN = re.compile(r"/[A-Za-z0-9._/+@-]*")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_OBJECTS_PREFIX = re.compile(r"[A-Za-z0-9._/-]{1,512}")

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


# A manifest artifact's run: Echoport's own record of it, read as the Echoport
# user through ``manage.py shell``. The run ID comes in the environment; the
# script prints one marked JSON line (``null`` when there is no such run).
RUN_RECORD_MARKER = "ECHOPORT_RUN_RECORD "
_RUN_RECORD_CODE = """import json, os
from backups.models import BackupRun
run = BackupRun.objects.select_related("target").filter(pk=int(os.environ["ECHOPORT_VERIFY_RUN_ID"])).first()
record = None if run is None else {
    "id": run.pk,
    "target": run.target.name,
    "status": run.status,
    "triggered_by": run.triggered_by,
    "storage_bucket": run.storage_bucket,
    "storage_key": run.storage_key,
    "size_bytes": run.size_bytes,
    "checksum_sha256": run.checksum_sha256,
    "file_count": run.file_count,
}
print("ECHOPORT_RUN_RECORD " + json.dumps(record))
"""
assert RUN_RECORD_MARKER in _RUN_RECORD_CODE

RUN_RECORD_SCRIPT = (
    _PRELUDE
    + """site=$1
python=$2
run_id=$3
code=$(cat <<"PY"
"""
    + _RUN_RECORD_CODE
    + """PY
)
cd "$site"
as_user env "ECHOPORT_VERIFY_RUN_ID=$run_id" "$python" manage.py shell -c "$code" </dev/null
"""
)

# The manifest is a few hundred bytes; anything above this is not one (its
# size is checked with ``mc stat`` before it is read).
MANIFEST_MAX_BYTES = 65536
MANIFEST_NAME = "manifest.json"
# base64, so the controller hashes the stored bytes, not decoded text.
MANIFEST_SCRIPT = (
    _PRELUDE
    + """mc=$1
object=$2
as_user "$mc" cat "$object" </dev/null | base64
"""
)

# ``mc du`` of the run's objects: one JSON record with their count and bytes.
LISTING_SCRIPT = (
    _PRELUDE
    + """mc=$1
prefix=$2
as_user "$mc" du --json "$prefix" </dev/null
"""
)


class EchoportBackupError(RuntimeError):
    """The backup or its verification failed; nothing after it may run."""


class ManifestCheckError(EchoportBackupError):
    """A check of the manifest gate failed (message: ``<check>: <reason>``)."""


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
class ManifestEvidence:
    """What the manifest gate checked for a manifest artifact.

    ``manifest_sha256`` is the hash of the manifest file only (Echoport's
    stored checksum of the run); the objects are checked by count and total
    bytes, their contents are not hashed.
    """

    manifest: str
    manifest_sha256: str
    objects_prefix: str
    object_count: int
    object_bytes: int


@dataclass(frozen=True)
class EchoportBackupResult:
    """A verified backup run: the evidence a deploy records.

    For a manifest artifact ``key`` is the run's prefix, ``object_size`` the
    listed bytes of its objects and ``manifest`` what the gate checked;
    ``checksum_sha256`` stays ``None`` (no checksum covers the objects).
    """

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
    artifact: Artifact = "file"
    manifest: ManifestEvidence | None = None

    @property
    def object(self) -> str:
        return f"{self.bucket}/{self.key}"

    @property
    def restore_hint(self) -> str:
        return f"manage.py restore {self.target} {self.run_id}"

    def as_record(self) -> dict[str, Any]:
        record = {
            "target": self.target,
            "artifact": self.artifact,
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
        if self.manifest is not None:
            record["manifest"] = {
                "object": self.manifest.manifest,
                "sha256": self.manifest.manifest_sha256,
                "sha256_scope": "manifest file only",
                "objects_prefix": self.manifest.objects_prefix,
                "object_count": self.manifest.object_count,
                "object_bytes": self.manifest.object_bytes,
            }
        return record


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


def _marked_json(stdout: str, marker: str) -> Any:
    lines = [line[len(marker) :] for line in stdout.splitlines() if line.startswith(marker)]
    if len(lines) != 1:
        raise ValueError(f"{len(lines)} marked lines, expected exactly one")
    return json.loads(lines[0])


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _same(actual: object, expected: object) -> bool:
    """Equal, and an int only as an int (not ``1.0`` or ``True``)."""

    if isinstance(expected, int):
        return _int(actual) == expected
    return actual == expected


def check_run_record(target: str, triggered_by: str, run: ReportedRun, stdout: str) -> tuple[str, int]:
    """Echoport's record of ``run``: its checksum and file count, or an error.

    The record must be the reported run (ID, target, label, bucket, key and
    size), successful, with a SHA-256 and a positive file count.
    """

    try:
        record = _marked_json(stdout, RUN_RECORD_MARKER)
    except ValueError as exc:
        raise ManifestCheckError(f"run record: unreadable ({exc})") from None
    if not isinstance(record, dict):
        raise ManifestCheckError(f"run record: Echoport has no run {run.run_id}")
    expected: dict[str, object] = {
        "id": run.run_id,
        "target": target,
        "status": "success",
        "triggered_by": triggered_by,
        "storage_bucket": run.bucket,
        "storage_key": run.key,
        "size_bytes": run.size_bytes,
    }
    for name, value in expected.items():
        if not _same(record.get(name), value):
            raise ManifestCheckError(f"run record: {name} is {record.get(name)!r}, expected {value!r}")
    checksum = record.get("checksum_sha256")
    if not isinstance(checksum, str) or not _SHA256.fullmatch(checksum):
        raise ManifestCheckError("run record: no SHA-256 of the manifest")
    count = _int(record.get("file_count"))
    if count is None or count <= 0:
        raise ManifestCheckError(f"run record: no positive file count (got {record.get('file_count')!r})")
    return checksum, count


def decode_manifest(stdout: str, size: int) -> bytes:
    """The manifest's stored bytes from ``MANIFEST_SCRIPT``'s base64 output."""

    try:
        content = base64.b64decode("".join(stdout.split()), validate=True)
    except binascii.Error:
        raise ManifestCheckError("manifest: unreadable output of mc cat") from None
    if len(content) != size:
        raise ManifestCheckError(f"manifest: read {len(content)} bytes, mc stat reported {size}")
    return content


def check_manifest(target: str, run: ReportedRun, content: bytes, checksum: str, count: int) -> str:
    """The manifest's objects prefix, after checking it against the run.

    Its SHA-256 must be Echoport's checksum of the run; it must name the
    target, the run's bucket and prefix, Echoport's byte total and file count,
    and an objects prefix under ``<target>/``.
    """

    if len(content) > MANIFEST_MAX_BYTES:
        raise ManifestCheckError(f"manifest: larger than {MANIFEST_MAX_BYTES} bytes")
    if hashlib.sha256(content).hexdigest() != checksum:
        raise ManifestCheckError("manifest: its SHA-256 differs from Echoport's checksum of the run")
    try:
        manifest = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ManifestCheckError("manifest: not JSON") from None
    if not isinstance(manifest, dict):
        raise ManifestCheckError("manifest: not a JSON object")
    expected: dict[str, object] = {
        "target": target,
        "storage_bucket": run.bucket,
        "storage_prefix": run.key,
        "bytes": run.size_bytes,
        "count": count,
    }
    for name, value in expected.items():
        if not _same(manifest.get(name), value):
            raise ManifestCheckError(f"manifest: {name} is {manifest.get(name)!r}, expected {value!r}")
    if "run_id" in manifest and not _same(manifest["run_id"], run.run_id):
        raise ManifestCheckError(f"manifest: run_id is {manifest['run_id']!r}, expected {run.run_id}")
    prefix = manifest.get("objects_prefix")
    parts = prefix.split("/") if isinstance(prefix, str) else []
    if (
        not isinstance(prefix, str)
        or not _OBJECTS_PREFIX.fullmatch(prefix)
        or parts[0] != target
        or len(parts) < 2
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise ManifestCheckError(f"manifest: objects_prefix {prefix!r} is not under {target}/")
    return prefix


def parse_listing_output(stdout: str, expected_prefix: str) -> tuple[int, int]:
    """Object count and bytes ``mc du --json`` reported for ``expected_prefix``."""

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
        raise ManifestCheckError(f"listing: mc du returned {len(records)} records, expected exactly one")
    record = records[0]
    count, size = _int(record.get("objects")), _int(record.get("size"))
    if (
        record.get("status") != "success"
        or record.get("isVersions") is True
        or str(record.get("prefix", "")).rstrip("/") != expected_prefix
        or count is None
        or size is None
    ):
        raise ManifestCheckError("listing: mc du did not report the objects prefix with a count and size")
    return count, size


def _gate_step(
    runner: Runner, script: str, args: list[str], timeout: float, *, target: str, where: str, name: str
) -> CommandResult:
    result = _run(runner, script, args, timeout, f"{target}: {name}")
    if not result.ok:
        raise EchoportBackupError(f"{where}: {name}: failed (exit {result.returncode}): {_tail(result)}")
    return result


def _verify_manifest(
    runner: Runner,
    site: EchoportSite,
    target: str,
    triggered_by: str,
    run: ReportedRun,
    become: list[str],
    check_timeout: float,
    listing_timeout: float,
) -> ManifestEvidence:
    """The manifest gate: run record, manifest, listing; any mismatch raises.

    A failed check or command raises ``<target>: run <id>: manifest gate:
    <check>: ...``; ssh trouble (no result, timeout) keeps the shape of the
    other steps, ``<target>: <check>: ...``.
    """

    where = f"{target}: run {run.run_id}: manifest gate"
    manifest_key = f"{run.key}/{MANIFEST_NAME}"
    manifest_path = site.object_path(run.bucket, manifest_key)

    def command(script: str, args: list[str], timeout: float, name: str) -> CommandResult:
        return _gate_step(runner, script, [*become, *args], timeout, target=target, where=where, name=name)

    try:
        record = command(
            RUN_RECORD_SCRIPT, [site.site_path, site.python_path, str(run.run_id)], check_timeout, "run record"
        )
        checksum, count = check_run_record(target, triggered_by, run, record.stdout)

        stat = command(STAT_SCRIPT, [site.mc_path, manifest_path], check_timeout, "manifest")
        try:
            size, _ = parse_stat_output(stat.stdout)
        except EchoportBackupError as exc:
            raise ManifestCheckError(f"manifest: {exc}") from None
        if size > MANIFEST_MAX_BYTES:
            raise ManifestCheckError(f"manifest: larger than {MANIFEST_MAX_BYTES} bytes")
        fetched = command(MANIFEST_SCRIPT, [site.mc_path, manifest_path], check_timeout, "manifest")
        content = decode_manifest(fetched.stdout, size)
        objects_prefix = check_manifest(target, run, content, checksum, count)

        listed_prefix = f"{run.bucket}/{objects_prefix}/objects"
        listing = command(
            LISTING_SCRIPT, [site.mc_path, f"{site.minio_alias}/{listed_prefix}/"], listing_timeout, "listing"
        )
        listed_count, listed_bytes = parse_listing_output(listing.stdout, listed_prefix)
        if listed_count <= 0:
            raise ManifestCheckError(f"listing: no objects under {listed_prefix}/")
        if listed_count != count:
            raise ManifestCheckError(f"listing: {listed_count} objects, the manifest names {count}")
        if listed_bytes != run.size_bytes:
            raise ManifestCheckError(f"listing: {listed_bytes} bytes, the manifest names {run.size_bytes}")
    except ManifestCheckError as exc:
        raise EchoportBackupError(f"{where}: {exc}") from None
    return ManifestEvidence(
        manifest=f"{run.bucket}/{manifest_key}",
        manifest_sha256=checksum,
        objects_prefix=f"{run.bucket}/{objects_prefix}/objects",
        object_count=listed_count,
        object_bytes=listed_bytes,
    )


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
    artifact: Artifact = "file",
    listing_timeout: float = 900,
    clock: Callable[[], datetime] = _now,
) -> EchoportBackupResult:
    """Run ``target``'s backup now, wait for it and verify the artifact.

    ``runner`` reaches the Echoport host. ``timeout`` bounds the whole backup
    (Echoport has its own per-target timeout below it); ``check_timeout`` the
    ``mc stat``, the run record and the manifest fetch. Raises
    :class:`EchoportBackupError` on any failure and :class:`ValueError` on a
    malformed target, label or artifact type.

    ``artifact`` says what the run stores. ``"file"`` (default): one object at
    the reported key, checked with ``mc stat`` (and its checksum when
    reported). ``"manifest"``: a prefix with ``manifest.json`` and the
    objects under the manifest's ``objects_prefix``/``objects``; checked
    against Echoport's run record (ID, target, label, key, size, the
    manifest's SHA-256, file count), the manifest itself and an ``mc du`` of
    the objects (count and bytes; ``listing_timeout``). Object contents are
    not hashed.
    """

    _require(TARGET_PATTERN, target, "Echoport target")
    _require(LABEL_PATTERN, triggered_by, "triggered-by label")
    if artifact not in ("file", "manifest"):
        raise ValueError(f"invalid artifact type: {artifact!r}")
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

    if artifact == "manifest":
        evidence = _verify_manifest(runner, site, target, triggered_by, run, become, check_timeout, listing_timeout)
        return EchoportBackupResult(
            target=target,
            triggered_by=triggered_by,
            run_id=run.run_id,
            bucket=run.bucket,
            key=run.key,
            size_bytes=run.size_bytes,
            checksum_sha256=None,
            checksum_verified=False,
            object_size=evidence.object_bytes,
            object_last_modified=None,
            started_at=started.isoformat(timespec="seconds"),
            finished_at=clock().isoformat(timespec="seconds"),
            artifact="manifest",
            manifest=evidence,
        )

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
