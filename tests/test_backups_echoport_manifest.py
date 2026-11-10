"""The manifest gate of :func:`run_echoport_backup` (``artifact="manifest"``).

A manifest target (the rclone media runners) stores a prefix with
``manifest.json`` and its objects under the manifest's ``objects_prefix``.
The gate checks Echoport's run record, the manifest and an ``mc du`` of the
objects. The first tests drive it with a fake runner; the last ones run the
real scripts with bash and stub ``runuser``, Echoport and ``mc``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.backups import (
    CommandResult,
    EchoportBackupError,
    EchoportBackupResult,
    EchoportSite,
    RemoteCommandError,
    SubprocessRunner,
    run_echoport_backup,
)
from ops_deploy.backups.echoport_sync import (
    BACKUP_SCRIPT,
    CHECKSUM_SCRIPT,
    LISTING_SCRIPT,
    MANIFEST_MAX_BYTES,
    MANIFEST_SCRIPT,
    RUN_RECORD_MARKER,
    RUN_RECORD_SCRIPT,
    STAT_SCRIPT,
    parse_listing_output,
)

SITE = EchoportSite(site_path="/srv/echoport/site", user="echoport", minio_alias="minio")
TARGET = "homepage-media"
LABEL = "ops-control:manual:homepage@production"
RUN_ID = 6208
PREFIX = "homepage-media/2026-11-10T01-15-01"
BYTES = 109595116357
COUNT = 114862


def backup_output(*, run_id: int = RUN_ID, storage: str = f"backups/{PREFIX}", size: int = BYTES) -> str:
    return (
        f"Starting backup for target '{TARGET}'...\n"
        "Backup completed successfully!\n"
        f"  Run ID: {run_id}\n"
        f"  Storage: {storage}\n"
        f"  Size: {size:,} bytes\n"
        "  Duration: 158.3s\n"
    )


def manifest_bytes(**changes: object) -> bytes:
    manifest: dict[str, object] = {
        "target": TARGET,
        "timestamp": "2026-11-10T01:17:39.200978+00:00",
        "source_bucket": "media.example",
        "storage_bucket": "backups",
        "storage_prefix": PREFIX,
        "objects_prefix": "homepage-media/current",
        "bytes": BYTES,
        "count": COUNT,
    }
    for name, value in changes.items():
        if value is None:
            manifest.pop(name, None)
        else:
            manifest[name] = value
    return json.dumps(manifest, indent=2).encode()


MANIFEST = manifest_bytes()


def record_output(content: bytes = MANIFEST, /, **changes: object) -> str:
    record: dict[str, object] = {
        "id": RUN_ID,
        "target": TARGET,
        "status": "success",
        "triggered_by": LABEL,
        "storage_bucket": "backups",
        "storage_key": PREFIX,
        "size_bytes": BYTES,
        "checksum_sha256": hashlib.sha256(content).hexdigest(),
        "file_count": COUNT,
    }
    record.update(changes)
    return f"15 objects imported automatically.\n{RUN_RECORD_MARKER}{json.dumps(record)}\n"


def listing_output(*, count: int = COUNT, size: int = BYTES, **extra: object) -> str:
    record: dict[str, object] = {
        "prefix": "backups/homepage-media/current/objects",
        "size": size,
        "objects": count,
        "status": "success",
        "isVersions": False,
    }
    record.update(extra)
    return json.dumps(record) + "\n"


SCRIPTS = {
    BACKUP_SCRIPT: "backup",
    STAT_SCRIPT: "stat",
    CHECKSUM_SCRIPT: "checksum",
    RUN_RECORD_SCRIPT: "record",
    MANIFEST_SCRIPT: "manifest",
    LISTING_SCRIPT: "listing",
}


class FakeRunner:
    """Answers each script with a queued result; records every call."""

    def __init__(self, **answers: CommandResult | Exception) -> None:
        self.answers = answers
        self.calls: list[tuple[str, list[str], float]] = []

    def __call__(self, script: str, args: Sequence[str], timeout: float) -> CommandResult:
        name = SCRIPTS[script]
        self.calls.append((name, list(args), timeout))
        answer = self.answers[name]
        if isinstance(answer, Exception):
            raise answer
        return answer

    @property
    def steps(self) -> list[str]:
        return [name for name, _, _ in self.calls]


def ok(stdout: str) -> CommandResult:
    return CommandResult(0, stdout, "")


def cat(content: bytes) -> CommandResult:
    """``MANIFEST_SCRIPT``'s answer: the object base64-encoded, wrapped as GNU's."""

    encoded = base64.b64encode(content).decode()
    return ok("".join(encoded[i : i + 76] + "\n" for i in range(0, len(encoded), 76)))


def stat_of(content: bytes) -> CommandResult:
    return ok(json.dumps({"status": "success", "type": "file", "size": len(content)}) + "\n")


def good(**answers: CommandResult | Exception) -> FakeRunner:
    defaults: dict[str, CommandResult | Exception] = {
        "backup": ok(backup_output()),
        "record": ok(record_output()),
        "stat": stat_of(MANIFEST),
        "manifest": cat(MANIFEST),
        "listing": ok(listing_output()),
    }
    return FakeRunner(**{**defaults, **answers})


def clock() -> datetime:
    return datetime(2026, 11, 10, 1, 15, tzinfo=UTC)


def run(runner: FakeRunner) -> EchoportBackupResult:
    return run_echoport_backup(runner, SITE, TARGET, triggered_by=LABEL, artifact="manifest", clock=clock)


# --- positive ---------------------------------------------------------------


def test_manifest_artifact_is_verified() -> None:
    runner = good()
    result = run(runner)
    assert runner.steps == ["backup", "record", "stat", "manifest", "listing"]
    assert (result.run_id, result.object, result.artifact) == (RUN_ID, f"backups/{PREFIX}", "manifest")
    assert result.size_bytes == result.object_size == BYTES
    # No checksum covers the objects: the manifest's hash is evidence of the
    # manifest only and is not reported as the run's checksum.
    assert result.checksum_sha256 is None
    assert not result.checksum_verified
    assert result.manifest is not None
    assert result.manifest.manifest == f"backups/{PREFIX}/manifest.json"
    assert result.manifest.manifest_sha256 == hashlib.sha256(MANIFEST).hexdigest()
    assert result.manifest.objects_prefix == "backups/homepage-media/current/objects"
    assert (result.manifest.object_count, result.manifest.object_bytes) == (COUNT, BYTES)
    record = result.as_record()
    assert record["artifact"] == "manifest"
    assert record["manifest"]["sha256_scope"] == "manifest file only"
    assert record["manifest"]["object_count"] == COUNT
    assert result.restore_hint == f"manage.py restore {TARGET} {RUN_ID}"

    become = ["runuser", "echoport"]
    assert runner.calls[1][1] == [*become, "/srv/echoport/site", "/srv/echoport/site/.venv/bin/python", str(RUN_ID)]
    manifest = [*become, "/usr/local/bin/mc", f"minio/backups/{PREFIX}/manifest.json"]
    assert runner.calls[2][1] == runner.calls[3][1] == manifest
    assert runner.calls[4][1] == [*become, "/usr/local/bin/mc", "minio/backups/homepage-media/current/objects/"]
    assert runner.calls[4][2] == 900


def test_manifest_with_the_run_id_is_accepted() -> None:
    content = manifest_bytes(run_id=RUN_ID)
    runner = good(record=ok(record_output(content)), stat=stat_of(content), manifest=cat(content))
    assert run(runner).run_id == RUN_ID


def test_file_artifact_is_unchanged_by_default() -> None:
    runner = FakeRunner(
        backup=ok(backup_output()),
        stat=ok(json.dumps({"status": "success", "type": "file", "size": BYTES}) + "\n"),
    )
    result = run_echoport_backup(runner, SITE, TARGET, triggered_by=LABEL, clock=clock)
    assert runner.steps == ["backup", "stat"]
    assert result.artifact == "file"
    assert result.manifest is None
    assert "manifest" not in result.as_record()


def test_a_file_check_of_a_manifest_run_still_fails() -> None:
    """The old gate keeps failing a prefix: only the explicit type passes it."""

    missing = CommandResult(1, '{"status": "error"}\n', "")
    runner = FakeRunner(backup=ok(backup_output()), stat=missing)
    with pytest.raises(EchoportBackupError, match="not found in MinIO"):
        run_echoport_backup(runner, SITE, TARGET, triggered_by=LABEL, clock=clock)


# --- negative ---------------------------------------------------------------


def expect_failure(runner: FakeRunner, message: str) -> str:
    with pytest.raises(EchoportBackupError, match=message) as info:
        run(runner)
    text = str(info.value)
    assert text.startswith(f"{TARGET}: ")
    return text


def test_missing_manifest_fails() -> None:
    missing = CommandResult(1, '{"status": "error"}\n', "mc: <ERROR> Object does not exist.\n")
    runner = good(stat=missing)
    text = expect_failure(runner, r"manifest gate: manifest: failed \(exit 1\)")
    assert text.startswith(f"{TARGET}: run {RUN_ID}: manifest gate: ")
    assert runner.steps == ["backup", "record", "stat"]


def test_unreadable_manifest_fails() -> None:
    gone = CommandResult(1, "", "mc: <ERROR> Object does not exist.\n")
    expect_failure(good(manifest=gone), r"manifest gate: manifest: failed \(exit 1\)")


def test_manifest_folder_fails() -> None:
    folder = ok(json.dumps({"status": "success", "type": "folder", "size": 0}) + "\n")
    expect_failure(good(stat=folder), "manifest gate: manifest: mc stat did not report a file")


def test_empty_manifest_fails() -> None:
    expect_failure(good(stat=stat_of(b""), manifest=cat(b"")), "SHA-256 differs")


def test_manifest_read_short_fails() -> None:
    expect_failure(
        good(manifest=cat(MANIFEST[:-1])), f"read {len(MANIFEST) - 1} bytes, mc stat reported {len(MANIFEST)}"
    )


def test_manifest_output_that_is_not_base64_fails() -> None:
    expect_failure(good(manifest=ok("{not base64}\n")), "unreadable output of mc cat")


def test_manifest_bytes_are_hashed_exactly() -> None:
    # A CRLF copy of the manifest is other bytes: its hash differs.
    crlf = MANIFEST.replace(b"\n", b"\r\n")
    expect_failure(good(stat=stat_of(crlf), manifest=cat(crlf)), "SHA-256 differs")


def test_manifest_not_matching_echoports_checksum_fails() -> None:
    tampered = manifest_bytes(source_bucket="other")
    runner = good(stat=stat_of(tampered), manifest=cat(tampered))
    expect_failure(runner, "SHA-256 differs from Echoport's checksum")


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"count": COUNT - 1}, f"count is {COUNT - 1}, expected {COUNT}"),
        ({"count": float(COUNT)}, "count is"),
        ({"bytes": BYTES + 1}, "bytes is"),
        ({"run_id": RUN_ID - 1}, f"run_id is {RUN_ID - 1}, expected {RUN_ID}"),
        ({"target": "python-podcast-media"}, "target is"),
        ({"storage_prefix": "homepage-media/2026-11-09T20-03-24"}, "storage_prefix is"),
        ({"storage_bucket": "other"}, "storage_bucket is"),
        ({"objects_prefix": "python-podcast-media/current"}, "objects_prefix"),
        ({"objects_prefix": "homepage-media/../x"}, "objects_prefix"),
        ({"objects_prefix": "homepage-media"}, "objects_prefix"),
        ({"objects_prefix": None}, "objects_prefix"),
    ],
)
def test_manifest_contradicting_the_run_fails(changes: dict[str, object], message: str) -> None:
    content = manifest_bytes(**changes)
    # Echoport's checksum matches the file, so only the content check fails.
    runner = good(record=ok(record_output(content)), stat=stat_of(content), manifest=cat(content))
    expect_failure(runner, message)
    assert runner.steps == ["backup", "record", "stat", "manifest"]


def test_manifest_that_is_not_json_fails() -> None:
    content = b"not json"
    runner = good(record=ok(record_output(content)), stat=stat_of(content), manifest=cat(content))
    expect_failure(runner, "manifest: not JSON")


def test_oversized_manifest_fails_before_it_is_read() -> None:
    content = b" " * (MANIFEST_MAX_BYTES + 1)
    runner = good(record=ok(record_output(content)), stat=stat_of(content))
    expect_failure(runner, "larger than")
    assert runner.steps == ["backup", "record", "stat"]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"id": RUN_ID + 1}, "run record: id is"),
        ({"target": "homepage-production-db"}, "run record: target is"),
        ({"status": "failed"}, "run record: status is"),
        ({"triggered_by": "schedule"}, "run record: triggered_by is"),
        ({"storage_key": "homepage-media/2026-11-09T20-03-24"}, "run record: storage_key is"),
        ({"size_bytes": BYTES - 1}, "run record: size_bytes is"),
        ({"checksum_sha256": ""}, "no SHA-256"),
        ({"file_count": 0}, "no positive file count"),
        ({"file_count": None}, "no positive file count"),
    ],
)
def test_run_record_contradicting_the_report_fails(changes: dict[str, object], message: str) -> None:
    runner = good(record=ok(record_output(**changes)))
    expect_failure(runner, message)
    assert runner.steps == ["backup", "record"]


def test_unknown_run_fails() -> None:
    expect_failure(good(record=ok(f"{RUN_RECORD_MARKER}null\n")), f"Echoport has no run {RUN_ID}")


@pytest.mark.parametrize("stdout", ["", "nothing marked\n", record_output() + record_output()])
def test_unreadable_run_record_fails(stdout: str) -> None:
    expect_failure(good(record=ok(stdout)), "run record: unreadable")


def test_run_record_command_failure_fails() -> None:
    expect_failure(good(record=CommandResult(1, "", "Traceback ...\n")), r"run record: failed \(exit 1\)")


def test_ssh_failures_keep_the_step_shape() -> None:
    # As for the other steps: "<target>: <step>: <ssh error>", no gate prefix.
    expect_failure(good(record=RemoteCommandError("ssh: no result")), f"^{TARGET}: run record: ssh: no result")
    expect_failure(good(listing=RemoteCommandError("ssh: no result")), f"^{TARGET}: listing: ssh: no result")


def test_check_failures_are_prefixed_even_for_a_target_named_like_a_check() -> None:
    runner = good(listing=ok(listing_output(count=COUNT - 1)))
    runner.answers["backup"] = ok(backup_output().replace(TARGET, "listing"))
    content = manifest_bytes(target="listing", storage_prefix=PREFIX.replace(TARGET, "listing"))
    content = content.replace(b"homepage-media/current", b"listing/current")
    runner.answers["record"] = ok(
        record_output(content, target="listing", storage_key=PREFIX.replace(TARGET, "listing"))
    )
    runner.answers["stat"] = stat_of(content)
    runner.answers["manifest"] = cat(content)
    runner.answers["listing"] = ok(listing_output(count=COUNT - 1, prefix="backups/listing/current/objects"))
    with pytest.raises(EchoportBackupError, match=f"^listing: run {RUN_ID}: manifest gate: listing: "):
        run_echoport_backup(runner, SITE, "listing", triggered_by=LABEL, artifact="manifest")


def test_wrong_count_in_the_listing_fails() -> None:
    expect_failure(
        good(listing=ok(listing_output(count=COUNT - 3))), f"{COUNT - 3} objects, the manifest names {COUNT}"
    )


def test_wrong_bytes_in_the_listing_fails() -> None:
    expect_failure(good(listing=ok(listing_output(size=BYTES - 1))), f"{BYTES - 1} bytes, the manifest names {BYTES}")


def test_empty_prefix_fails() -> None:
    expect_failure(good(listing=ok(listing_output(count=0, size=0))), "no objects under")


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        listing_output() + listing_output(),
        listing_output(status="error"),
        listing_output(isVersions=True),
        listing_output(prefix="backups/homepage-media/current/objects-old"),
        listing_output(count="many"),  # type: ignore[arg-type]
        listing_output(objects=True),
    ],
)
def test_unusable_listing_fails(stdout: str) -> None:
    expect_failure(good(listing=ok(stdout)), "listing: ")


def test_listing_failure_fails() -> None:
    expect_failure(good(listing=CommandResult(1, "", "mc: error\n")), r"listing: failed \(exit 1\)")


def test_listing_accepts_a_trailing_slash() -> None:
    stdout = listing_output(prefix="backups/homepage-media/current/objects/")
    assert parse_listing_output(stdout, "backups/homepage-media/current/objects") == (COUNT, BYTES)


def test_failed_backup_never_reaches_the_gate() -> None:
    runner = good(backup=CommandResult(1, "", "CommandError: Backup failed\n"))
    with pytest.raises(EchoportBackupError, match="backup failed"):
        run(runner)
    assert runner.steps == ["backup"]


def test_unknown_artifact_type_never_reaches_the_host() -> None:
    runner = good()
    with pytest.raises(ValueError, match="artifact"):
        run_echoport_backup(runner, SITE, TARGET, triggered_by=LABEL, artifact="prefix")  # type: ignore[arg-type]
    assert runner.calls == []


def test_gate_scripts_are_fish_and_quote_safe() -> None:
    for script in (RUN_RECORD_SCRIPT, MANIFEST_SCRIPT, LISTING_SCRIPT):
        assert "\\" not in script
        assert "'" not in script


# --- the real scripts, with stubs --------------------------------------------


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


FAKE_MODELS = """
import json, os


class _Target:
    def __init__(self, name):
        self.name = name


class _Run:
    def __init__(self, data):
        self.pk = data["id"]
        self.target = _Target(data["target"])
        for key, value in data.items():
            if key not in ("id", "target"):
                setattr(self, key, value)


class _Query:
    def __init__(self, runs):
        self.runs = runs

    def select_related(self, *names):
        return self

    def filter(self, pk):
        return _Query([run for run in self.runs if run.pk == pk])

    def first(self):
        return self.runs[0] if self.runs else None


class _Manager:
    @property
    def runs(self):
        with open(os.environ["FAKE_RUNS"]) as handle:
            return [_Run(data) for data in json.load(handle)]

    def select_related(self, *names):
        return _Query(self.runs).select_related(*names)


class BackupRun:
    objects = _Manager()
"""


@pytest.fixture
def host(tmp_path: Path) -> tuple[SubprocessRunner, EchoportSite, Path, Path]:
    """A fake Echoport host: site dir with a fake ``backups.models``, store, mc."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    site = tmp_path / "site"
    (site / ".venv" / "bin").mkdir(parents=True)
    (site / "manage.py").write_text("")
    (site / "backups").mkdir()
    (site / "backups" / "__init__.py").write_text("")
    (site / "backups" / "models.py").write_text(FAKE_MODELS)
    store = tmp_path / "minio"
    run_dir = store / "backups" / PREFIX
    run_dir.mkdir(parents=True)
    objects = store / "backups" / "homepage-media" / "current" / "objects"
    (objects / "media").mkdir(parents=True)
    (objects / "media" / "a.jpg").write_bytes(b"aaaa")
    (objects / "media" / "b.jpg").write_bytes(b"bbbbbb")
    manifest = manifest_bytes(bytes=10, count=2)
    (run_dir / "manifest.json").write_bytes(manifest)
    runs = tmp_path / "runs.json"
    record = json.loads(record_output(manifest, size_bytes=10, file_count=2).splitlines()[1][len(RUN_RECORD_MARKER) :])
    runs.write_text(json.dumps([record]))
    log = tmp_path / "calls.log"
    _stub(
        bin_dir / "runuser",
        f'[ "$1" = -u ] && [ "$3" = -- ] || exit 9\necho "runuser $2" >>{log}\nshift 3\nexec "$@"\n',
    )
    _stub(
        site / ".venv" / "bin" / "python",
        f'[ -f manage.py ] || {{ echo "not in the site dir" >&2; exit 7; }}\n'
        f'echo "python $1 $2" >>{log}\n'
        'if [ "$2" = shell ]; then\n'
        '  [ "$3" = -c ] || exit 8\n'
        '  echo "15 objects imported automatically."\n'
        f'  exec env FAKE_RUNS={runs} python3 -c "$4"\n'
        "fi\n"
        'printf "Starting backup...\\nBackup completed successfully!\\n  Run ID: 6208\\n'
        f'  Storage: backups/{PREFIX}\\n  Size: 10 bytes\\n"\n',
    )
    _stub(
        bin_dir / "mc",
        f'echo "mc $*" >>{log}\n'
        f"store={store}\n"
        'if [ "$1" = stat ]; then\n'
        '  file="$store/${3#minio/}"\n'
        '  [ -f "$file" ] || { echo \'{"status":"error"}\'; exit 1; }\n'
        '  printf \'{"status":"success","type":"file","size":%s}\\n\' "$(wc -c <"$file" | tr -d " ")"\n'
        'elif [ "$1" = cat ]; then cat "$store/${2#minio/}"\n'
        'elif [ "$1" = du ]; then\n'
        '  dir="$store/${3#minio/}"\n'
        '  count=$(find "$dir" -type f | wc -l | tr -d " ")\n'
        '  size=$(find "$dir" -type f -exec cat {} + | wc -c | tr -d " ")\n'
        '  printf \'{"prefix":"%s","size":%s,"objects":%s,"status":"success","isVersions":false}\\n\' '
        '"${3#minio/}" "$size" "$count"\n'
        "else exit 5; fi\n",
    )
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    runner = SubprocessRunner(env=env)
    echoport = EchoportSite(site_path=str(site), user="echoport", minio_alias="minio", mc_path=str(bin_dir / "mc"))
    return runner, echoport, log, objects


def test_real_scripts_verify_a_manifest_run(host: tuple[SubprocessRunner, EchoportSite, Path, Path]) -> None:
    runner, site, log, _ = host
    result = run_echoport_backup(runner, site, TARGET, triggered_by=LABEL, artifact="manifest")
    assert result.manifest is not None
    assert (result.run_id, result.manifest.object_count, result.manifest.object_bytes) == (RUN_ID, 2, 10)
    calls = log.read_text().splitlines()
    assert "python manage.py shell" in calls
    assert f"mc stat --json minio/backups/{PREFIX}/manifest.json" in calls
    assert f"mc cat minio/backups/{PREFIX}/manifest.json" in calls
    assert "mc du --json minio/backups/homepage-media/current/objects/" in calls


def test_real_scripts_fail_on_a_changed_prefix(host: tuple[SubprocessRunner, EchoportSite, Path, Path]) -> None:
    runner, site, _, objects = host
    (objects / "media" / "c.jpg").write_bytes(b"c")
    with pytest.raises(EchoportBackupError, match="3 objects, the manifest names 2"):
        run_echoport_backup(runner, site, TARGET, triggered_by=LABEL, artifact="manifest")


def test_real_scripts_fail_on_an_empty_prefix(host: tuple[SubprocessRunner, EchoportSite, Path, Path]) -> None:
    runner, site, _, objects = host
    for path in (objects / "media").iterdir():
        path.unlink()
    with pytest.raises(EchoportBackupError, match="no objects under"):
        run_echoport_backup(runner, site, TARGET, triggered_by=LABEL, artifact="manifest")


def test_real_scripts_fail_without_a_manifest(host: tuple[SubprocessRunner, EchoportSite, Path, Path]) -> None:
    runner, site, log, objects = host
    (objects.parent.parent / "2026-11-10T01-15-01" / "manifest.json").unlink()
    with pytest.raises(EchoportBackupError, match=r"manifest gate: manifest: failed \(exit 1\)"):
        run_echoport_backup(runner, site, TARGET, triggered_by=LABEL, artifact="manifest")
    assert not any(line.startswith(("mc cat", "mc du")) for line in log.read_text().splitlines())


def test_real_scripts_hash_the_stored_bytes(host: tuple[SubprocessRunner, EchoportSite, Path, Path]) -> None:
    # A manifest whose bytes are not UTF-8 text reaches the hash unchanged.
    runner, site, _, objects = host
    manifest = objects.parent.parent / "2026-11-10T01-15-01" / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\xff\r\n")
    with pytest.raises(EchoportBackupError, match="SHA-256 differs"):
        run_echoport_backup(runner, site, TARGET, triggered_by=LABEL, artifact="manifest")


def test_real_scripts_fail_on_another_run_id(host: tuple[SubprocessRunner, EchoportSite, Path, Path]) -> None:
    runner, site, _, _ = host
    runs = Path(site.site_path).parent / "runs.json"
    records: list[dict[str, Any]] = json.loads(runs.read_text())
    records[0]["id"] = RUN_ID + 1
    runs.write_text(json.dumps(records))
    with pytest.raises(EchoportBackupError, match=f"Echoport has no run {RUN_ID}"):
        run_echoport_backup(runner, site, TARGET, triggered_by=LABEL, artifact="manifest")
