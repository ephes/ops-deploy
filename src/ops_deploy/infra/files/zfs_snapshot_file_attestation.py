#!/usr/bin/env python3
"""Attest that files exist in a source snapshot replicated to another pool.

The helper is deliberately read-only: it only runs ``zfs list/get`` and
``zpool get``.  Importing, mounting, snapshotting, replication, and physical
custody are responsibilities of the attended caller.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Iterable, Mapping
import unicodedata


SCHEMA_VERSION = 1
REQUEST_KIND = "zfs_snapshot_file_replication_attestation_request"
RESPONSE_KIND = "zfs_snapshot_file_replication_attestation_response"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_FILES = 200
MAX_ATTESTED_FILE_BYTES = 16 * 1024 * 1024
MAX_PATH_DEPTH = 64
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
DEFAULT_COMMAND_TIMEOUT_SECONDS = 30.0
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DATASET_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:%-]*$")
DECIMAL_PATTERN = re.compile(r"^[1-9][0-9]{0,19}$")
MAX_UINT64 = (1 << 64) - 1

REQUEST_FIELDS = (
    "schema_version",
    "kind",
    "request_id",
    "created_at",
    "source_dataset",
    "target_dataset",
    "files",
)
REQUEST_FILE_FIELDS = ("id", "relative_path", "expected_bytes", "sha256")
RESPONSE_FIELDS = (
    "schema_version",
    "kind",
    "request_id",
    "request_sha256",
    "status",
    "reason_code",
    "observed_at",
    "observer_host",
    "source",
    "target",
    "target_readonly",
    "target_receive_resume_token",
    "files",
)
SNAPSHOT_EVIDENCE_FIELDS = (
    "dataset",
    "pool",
    "pool_guid",
    "snapshot",
    "snapshot_guid",
    "creation_epoch",
    "createtxg",
)
RESPONSE_FILE_FIELDS = (
    "id",
    "relative_path",
    "expected_bytes",
    "expected_sha256",
    "observed_bytes",
    "observed_sha256",
    "status",
)
REASON_CODES = frozenset(
    {
        "file_digest_mismatch",
        "file_missing",
        "file_not_regular",
        "file_read_changed",
        "file_size_mismatch",
        "file_too_large",
        "no_common_snapshot",
        "pool_guid_not_distinct",
        "receive_incomplete",
        "request_changed",
        "request_invalid",
        "request_too_large",
        "request_unavailable",
        "request_unsafe",
        "source_not_mounted",
        "source_snapshot_changed",
        "source_snapshot_unavailable",
        "target_not_readonly",
        "target_snapshot_changed",
        "topology_mismatch",
        "zfs_command_output_too_large",
        "zfs_command_timeout",
        "zfs_output_invalid",
        "zfs_query_failed",
    }
)


class AttestationError(RuntimeError):
    """A closed, operator-actionable attestation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RequestedFile:
    file_id: str
    relative_path: str
    expected_bytes: int
    sha256: str


@dataclass(frozen=True)
class AttestationRequest:
    request_id: str
    created_at: str
    source_dataset: str
    target_dataset: str
    files: tuple[RequestedFile, ...]


@dataclass(frozen=True)
class Snapshot:
    full_name: str
    name: str
    guid: str
    creation_epoch: int
    createtxg: str


@dataclass(frozen=True)
class DatasetRuntime:
    mounted: bool
    mountpoint: str


CommandRunner = Callable[[tuple[str, ...]], str]


def _has_control_characters(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _is_uint64_decimal(value: Any) -> bool:
    return (
        isinstance(value, str)
        and DECIMAL_PATTERN.fullmatch(value) is not None
        and int(value) <= MAX_UINT64
    )


def _closed_object(
    value: Any,
    fields: Iterable[str],
    *,
    label: str,
    error_code: str = "request_invalid",
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttestationError(error_code, f"{label} must be a JSON object")
    expected = tuple(fields)
    if set(value) != set(expected) or len(value) != len(expected):
        raise AttestationError(
            error_code, f"{label} must contain exactly: {', '.join(expected)}"
        )
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError("request_invalid", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_string(value: Any, *, label: str, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or _has_control_characters(value)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise AttestationError("request_invalid", f"{label} must be a non-empty string")
    return value


def _validate_timestamp(value: Any, *, label: str) -> str:
    text = _require_string(value, label=label, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationError("request_invalid", f"{label} must be RFC 3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AttestationError("request_invalid", f"{label} must include a timezone")
    return text


def validate_dataset(value: Any, *, label: str) -> str:
    dataset = _require_string(value, label=label, maximum=255)
    if "@" in dataset or "#" in dataset:
        raise AttestationError(
            "request_invalid", f"{label} must name a filesystem dataset"
        )
    components = dataset.split("/")
    if any(
        not DATASET_COMPONENT_PATTERN.fullmatch(component) for component in components
    ):
        raise AttestationError(
            "request_invalid", f"{label} is not a safe ZFS dataset name"
        )
    return dataset


def validate_relative_path(value: Any, *, label: str) -> str:
    text = _require_string(value, label=label, maximum=4096)
    if "\\" in text or "\x00" in text or text.startswith("/") or text.endswith("/"):
        raise AttestationError(
            "request_invalid", f"{label} must be a normalized relative path"
        )
    path = PurePosixPath(text)
    components = path.parts
    if (
        not components
        or len(components) > MAX_PATH_DEPTH
        or len(text.encode("utf-8")) > 4096
        or any(
            component in ("", ".", "..") or len(component.encode("utf-8")) > 255
            for component in components
        )
    ):
        raise AttestationError(
            "request_invalid", f"{label} contains an unsafe path component"
        )
    if str(path) != text:
        raise AttestationError(
            "request_invalid", f"{label} must be a normalized relative path"
        )
    return text


def _is_within_root(path: str, root: str) -> bool:
    path_parts = PurePosixPath(path).parts
    root_parts = PurePosixPath(root).parts
    return (
        len(path_parts) > len(root_parts)
        and path_parts[: len(root_parts)] == root_parts
    )


def parse_request(
    raw: bytes,
    *,
    expected_source: str,
    expected_target: str,
    allowed_relative_root: str,
) -> AttestationRequest:
    if len(raw) > MAX_REQUEST_BYTES:
        raise AttestationError("request_too_large", "request exceeds the byte limit")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except UnicodeDecodeError as exc:
        raise AttestationError("request_invalid", "request must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise AttestationError("request_invalid", "request must be valid JSON") from exc
    document = _closed_object(value, REQUEST_FIELDS, label="request")
    if document["schema_version"] != SCHEMA_VERSION or isinstance(
        document["schema_version"], bool
    ):
        raise AttestationError("request_invalid", "unsupported request schema_version")
    if document["kind"] != REQUEST_KIND:
        raise AttestationError("request_invalid", "unsupported request kind")
    request_id = _require_string(
        document["request_id"], label="request_id", maximum=128
    )
    if not ID_PATTERN.fullmatch(request_id):
        raise AttestationError(
            "request_invalid", "request_id contains unsafe characters"
        )
    created_at = _validate_timestamp(document["created_at"], label="created_at")
    source = validate_dataset(document["source_dataset"], label="source_dataset")
    target = validate_dataset(document["target_dataset"], label="target_dataset")
    if source != expected_source or target != expected_target:
        raise AttestationError(
            "topology_mismatch",
            "request dataset pair does not match the attended command",
        )
    raw_files = document["files"]
    if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= MAX_FILES:
        raise AttestationError(
            "request_invalid", f"files must contain 1-{MAX_FILES} entries"
        )
    files: list[RequestedFile] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, raw_file in enumerate(raw_files):
        item = _closed_object(raw_file, REQUEST_FILE_FIELDS, label=f"files[{index}]")
        file_id = _require_string(item["id"], label=f"files[{index}].id", maximum=128)
        if not ID_PATTERN.fullmatch(file_id):
            raise AttestationError("request_invalid", f"files[{index}].id is unsafe")
        relative_path = validate_relative_path(
            item["relative_path"], label=f"files[{index}].relative_path"
        )
        if not _is_within_root(relative_path, allowed_relative_root):
            raise AttestationError(
                "request_unsafe",
                f"files[{index}].relative_path is outside the allowed root",
            )
        digest = _require_string(
            item["sha256"], label=f"files[{index}].sha256", maximum=64
        )
        if not HASH_PATTERN.fullmatch(digest):
            raise AttestationError(
                "request_invalid", f"files[{index}].sha256 is invalid"
            )
        expected_bytes = item["expected_bytes"]
        if (
            not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or not 1 <= expected_bytes <= MAX_ATTESTED_FILE_BYTES
        ):
            raise AttestationError(
                "request_invalid",
                f"files[{index}].expected_bytes must be an integer within the byte limit",
            )
        if file_id in seen_ids or relative_path in seen_paths:
            raise AttestationError(
                "request_invalid", "file ids and relative paths must be unique"
            )
        seen_ids.add(file_id)
        seen_paths.add(relative_path)
        files.append(RequestedFile(file_id, relative_path, expected_bytes, digest))
    return AttestationRequest(request_id, created_at, source, target, tuple(files))


def validate_executable_path(value: Any, *, label: str) -> str:
    text = _require_string(value, label=label, maximum=4096)
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts or os.fspath(path) != text:
        raise AttestationError(
            "request_invalid", f"{label} must be a normalized absolute path"
        )
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise AttestationError("request_invalid", f"{label} is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise AttestationError(
            "request_invalid", f"{label} must be a non-symlink executable regular file"
        )
    return text


class ReadOnlyCommandAdapter:
    """Run the fixed ZFS read surface with bounded resources and minimal env."""

    def __init__(
        self,
        *,
        zfs_path: str,
        zpool_path: str,
        timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
    ) -> None:
        self.zfs_path = validate_executable_path(zfs_path, label="zfs path")
        self.zpool_path = validate_executable_path(zpool_path, label="zpool path")
        if not isinstance(timeout_seconds, (int, float)) or isinstance(
            timeout_seconds, bool
        ):
            raise AttestationError("request_invalid", "command timeout must be numeric")
        if not 0 < timeout_seconds <= 300:
            raise AttestationError(
                "request_invalid", "command timeout is outside the safe range"
            )
        if (
            not isinstance(max_output_bytes, int)
            or isinstance(max_output_bytes, bool)
            or not 1024 <= max_output_bytes <= 16 * 1024 * 1024
        ):
            raise AttestationError(
                "request_invalid", "command output limit is outside the safe range"
            )
        self.timeout_seconds = float(timeout_seconds)
        self.max_output_bytes = max_output_bytes

    def __call__(self, argv: tuple[str, ...]) -> str:
        if not argv or argv[0] not in ("zfs", "zpool"):
            raise AttestationError(
                "zfs_query_failed", "unsupported command adapter request"
            )
        executable = self.zfs_path if argv[0] == "zfs" else self.zpool_path
        return run_bounded_command(
            (executable, *argv[1:]),
            timeout_seconds=self.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
        )


def run_bounded_command(
    argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
) -> str:
    environment = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as exc:
        raise AttestationError(
            "zfs_query_failed", "could not execute read-only ZFS command"
        ) from exc
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    failure: AttestationError | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = AttestationError(
                    "zfs_command_timeout", "read-only ZFS command timed out"
                )
                break
            events = selector.select(remaining)
            if not events:
                failure = AttestationError(
                    "zfs_command_timeout", "read-only ZFS command timed out"
                )
                break
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                buffer.extend(chunk)
                if len(buffer) > max_output_bytes:
                    failure = AttestationError(
                        "zfs_command_output_too_large",
                        "read-only ZFS command exceeded its output limit",
                    )
                    break
            if failure is not None:
                break
        if failure is not None:
            process.kill()
        return_code = process.wait(timeout=5)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if failure is not None:
        raise failure
    if return_code != 0:
        raise AttestationError(
            "zfs_query_failed", "read-only ZFS command returned nonzero"
        )
    if buffers["stderr"]:
        raise AttestationError(
            "zfs_query_failed", "read-only ZFS command wrote to stderr"
        )
    try:
        return bytes(buffers["stdout"]).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AttestationError(
            "zfs_output_invalid", "ZFS command output is not UTF-8"
        ) from exc


def _command(runner: CommandRunner, *argv: str) -> str:
    try:
        return runner(tuple(argv))
    except AttestationError:
        raise
    except Exception as exc:
        raise AttestationError(
            "zfs_query_failed", f"read-only command failed: {argv[0]}"
        ) from exc


def list_snapshots(dataset: str, *, runner: CommandRunner) -> list[Snapshot]:
    output = _command(
        runner,
        "zfs",
        "list",
        "-H",
        "-p",
        "-d",
        "1",
        "-t",
        "snapshot",
        "-o",
        "name,guid,creation,createtxg",
        "-s",
        "creation",
        dataset,
    )
    snapshots: list[Snapshot] = []
    seen_guids: set[str] = set()
    prefix = f"{dataset}@"
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            raise AttestationError(
                "zfs_output_invalid", "snapshot query returned malformed output"
            )
        full_name, guid, creation_raw, createtxg = fields
        if not full_name.startswith(prefix) or not full_name[len(prefix) :]:
            raise AttestationError(
                "zfs_output_invalid", "snapshot query escaped the requested dataset"
            )
        name = full_name[len(prefix) :]
        if "/" in name or name in (".", "..") or "\x00" in name:
            raise AttestationError("zfs_output_invalid", "snapshot name is unsafe")
        if not _is_uint64_decimal(guid) or not _is_uint64_decimal(createtxg):
            raise AttestationError(
                "zfs_output_invalid", "snapshot GUID or createtxg is invalid"
            )
        try:
            creation_epoch = int(creation_raw)
        except ValueError as exc:
            raise AttestationError(
                "zfs_output_invalid", "snapshot creation is invalid"
            ) from exc
        if creation_epoch < 0 or guid in seen_guids:
            raise AttestationError(
                "zfs_output_invalid", "snapshot query returned invalid identities"
            )
        seen_guids.add(guid)
        snapshots.append(Snapshot(full_name, name, guid, creation_epoch, createtxg))
    return snapshots


def newest_common_snapshot(
    source_snapshots: Iterable[Snapshot], target_snapshots: Iterable[Snapshot]
) -> tuple[Snapshot, Snapshot]:
    targets = {snapshot.guid: snapshot for snapshot in target_snapshots}
    common = [snapshot for snapshot in source_snapshots if snapshot.guid in targets]
    if not common:
        raise AttestationError(
            "no_common_snapshot", "datasets have no common snapshot GUID"
        )
    source = max(
        common, key=lambda snapshot: (snapshot.creation_epoch, int(snapshot.createtxg))
    )
    return source, targets[source.guid]


def pool_guid(pool: str, *, runner: CommandRunner) -> str:
    output = _command(runner, "zpool", "get", "-H", "-p", "-o", "value", "guid", pool)
    lines = output.splitlines()
    if len(lines) != 1 or not _is_uint64_decimal(lines[0]):
        raise AttestationError(
            "zfs_output_invalid", "pool GUID query returned malformed output"
        )
    return lines[0]


def target_receive_state(
    dataset: str, *, runner: CommandRunner
) -> tuple[str, str | None]:
    output = _command(
        runner,
        "zfs",
        "get",
        "-H",
        "-p",
        "-o",
        "property,value",
        "readonly,receive_resume_token",
        dataset,
    )
    properties: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] in properties:
            raise AttestationError(
                "zfs_output_invalid", "target property query is malformed"
            )
        properties[fields[0]] = fields[1]
    if set(properties) != {"readonly", "receive_resume_token"}:
        raise AttestationError(
            "zfs_output_invalid", "target property query is incomplete"
        )
    if properties["readonly"] != "on":
        raise AttestationError(
            "target_not_readonly", "target dataset readonly property is not on"
        )
    token = properties["receive_resume_token"]
    if token != "-":
        raise AttestationError(
            "receive_incomplete", "target dataset has a receive resume token"
        )
    return properties["readonly"], None


def source_runtime(dataset: str, *, runner: CommandRunner) -> DatasetRuntime:
    output = _command(
        runner,
        "zfs",
        "get",
        "-H",
        "-p",
        "-o",
        "property,value",
        "mounted,mountpoint",
        dataset,
    )
    properties: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] in properties:
            raise AttestationError(
                "zfs_output_invalid", "source property query is malformed"
            )
        properties[fields[0]] = fields[1]
    if set(properties) != {"mounted", "mountpoint"}:
        raise AttestationError(
            "zfs_output_invalid", "source property query is incomplete"
        )
    if properties["mounted"] != "yes":
        raise AttestationError("source_not_mounted", "source dataset is not mounted")
    mountpoint = properties["mountpoint"]
    if (
        not mountpoint.startswith("/")
        or mountpoint in ("/", "none", "legacy")
        or len(mountpoint.encode("utf-8")) > 4096
        or _has_control_characters(mountpoint)
        or unicodedata.normalize("NFC", mountpoint) != mountpoint
    ):
        raise AttestationError("zfs_output_invalid", "source mountpoint is unsafe")
    return DatasetRuntime(mounted=True, mountpoint=mountpoint)


def _open_absolute_directory(path: str) -> int:
    components = PurePosixPath(path).parts
    if not components or components[0] != "/":
        raise AttestationError(
            "source_snapshot_unavailable", "snapshot root is not absolute"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for component in components[1:]:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except OSError as exc:
        os.close(fd)
        raise AttestationError(
            "source_snapshot_unavailable",
            "could not open the source snapshot root safely",
        ) from exc


def _open_child_directory(parent_fd: int, component: str) -> int:
    try:
        return os.open(
            component,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise AttestationError(
            "file_missing", "attested file parent is unavailable"
        ) from exc


def hash_regular_file(
    root_fd: int, relative_path: str, *, expected_bytes: int
) -> tuple[str, int]:
    components = PurePosixPath(relative_path).parts
    current_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            next_fd = _open_child_directory(current_fd, component)
            os.close(current_fd)
            current_fd = next_fd
        try:
            file_fd = os.open(
                components[-1],
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=current_fd,
            )
        except OSError as exc:
            raise AttestationError(
                "file_missing", "attested file is unavailable"
            ) from exc
        try:
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode):
                raise AttestationError(
                    "file_not_regular", "attested path is not a regular file"
                )
            if info.st_nlink != 1:
                raise AttestationError(
                    "file_not_regular", "attested file must have exactly one link"
                )
            if info.st_size > MAX_ATTESTED_FILE_BYTES:
                raise AttestationError(
                    "file_too_large", "attested file exceeds the byte limit"
                )
            if info.st_size != expected_bytes:
                raise AttestationError(
                    "file_size_mismatch",
                    "attested file does not match its requested byte count",
                )
            digest = hashlib.sha256()
            observed = 0
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > MAX_ATTESTED_FILE_BYTES:
                    raise AttestationError(
                        "file_too_large", "attested file exceeds the byte limit"
                    )
                digest.update(chunk)
            if observed != info.st_size:
                raise AttestationError(
                    "file_read_changed", "attested file size changed while reading"
                )
            return digest.hexdigest(), observed
        finally:
            os.close(file_fd)
    finally:
        os.close(current_fd)


def _snapshot_evidence(
    dataset: str, pool: str, pool_id: str, snapshot: Snapshot
) -> dict[str, Any]:
    return {
        "dataset": dataset,
        "pool": pool,
        "pool_guid": pool_id,
        "snapshot": snapshot.full_name,
        "snapshot_guid": snapshot.guid,
        "creation_epoch": snapshot.creation_epoch,
        "createtxg": snapshot.createtxg,
    }


def attest(
    request: AttestationRequest,
    *,
    runner: CommandRunner,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    source_pool = request.source_dataset.split("/", 1)[0]
    target_pool = request.target_dataset.split("/", 1)[0]
    source_pool_guid = pool_guid(source_pool, runner=runner)
    target_pool_guid = pool_guid(target_pool, runner=runner)
    if source_pool_guid == target_pool_guid:
        raise AttestationError(
            "pool_guid_not_distinct",
            "source and target datasets belong to the same pool GUID",
        )
    target_receive_state(request.target_dataset, runner=runner)
    source_snapshot, target_snapshot = newest_common_snapshot(
        list_snapshots(request.source_dataset, runner=runner),
        list_snapshots(request.target_dataset, runner=runner),
    )
    runtime = source_runtime(request.source_dataset, runner=runner)
    snapshot_path = str(
        PurePosixPath(runtime.mountpoint) / ".zfs" / "snapshot" / source_snapshot.name
    )
    root_fd = _open_absolute_directory(snapshot_path)
    try:
        file_results: list[dict[str, Any]] = []
        for requested in request.files:
            observed_digest, observed_bytes = hash_regular_file(
                root_fd,
                requested.relative_path,
                expected_bytes=requested.expected_bytes,
            )
            if observed_digest != requested.sha256:
                raise AttestationError(
                    "file_digest_mismatch",
                    "attested file does not match its requested SHA-256",
                )
            file_results.append(
                {
                    "id": requested.file_id,
                    "relative_path": requested.relative_path,
                    "expected_bytes": requested.expected_bytes,
                    "expected_sha256": requested.sha256,
                    "observed_bytes": observed_bytes,
                    "observed_sha256": observed_digest,
                    "status": "verified",
                }
            )
    finally:
        os.close(root_fd)
    _confirm_snapshot(
        request.source_dataset,
        source_snapshot,
        runner=runner,
        failure_code="source_snapshot_changed",
    )
    _confirm_snapshot(
        request.target_dataset,
        target_snapshot,
        runner=runner,
        failure_code="target_snapshot_changed",
    )
    source = _snapshot_evidence(
        request.source_dataset, source_pool, source_pool_guid, source_snapshot
    )
    target = _snapshot_evidence(
        request.target_dataset, target_pool, target_pool_guid, target_snapshot
    )
    return source, target, file_results


def _confirm_snapshot(
    dataset: str,
    expected: Snapshot,
    *,
    runner: CommandRunner,
    failure_code: str,
) -> None:
    matches = [
        snapshot
        for snapshot in list_snapshots(dataset, runner=runner)
        if snapshot.full_name == expected.full_name
    ]
    if matches != [expected]:
        raise AttestationError(
            failure_code, "selected snapshot disappeared or changed during attestation"
        )


def build_response(
    *,
    request_id: str | None,
    request_sha256: str | None,
    status_value: str,
    reason_code: str | None,
    observed_at: str,
    observer_host: str,
    source: Mapping[str, Any] | None,
    target: Mapping[str, Any] | None,
    target_readonly: str | None,
    target_receive_resume_token: str | None,
    files: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    response = {
        "schema_version": SCHEMA_VERSION,
        "kind": RESPONSE_KIND,
        "request_id": request_id,
        "request_sha256": request_sha256,
        "status": status_value,
        "reason_code": reason_code,
        "observed_at": observed_at,
        "observer_host": observer_host,
        "source": None if source is None else dict(source),
        "target": None if target is None else dict(target),
        "target_readonly": target_readonly,
        "target_receive_resume_token": target_receive_resume_token,
        "files": [dict(item) for item in files],
    }
    validate_response(response)
    return response


def validate_response(value: Any) -> dict[str, Any]:
    document = _closed_object(
        value, RESPONSE_FIELDS, label="response", error_code="response_invalid"
    )
    if (
        document["schema_version"] != SCHEMA_VERSION
        or isinstance(document["schema_version"], bool)
        or document["kind"] != RESPONSE_KIND
    ):
        raise AttestationError("response_invalid", "unsupported response schema")
    if document["request_id"] is not None and (
        not isinstance(document["request_id"], str)
        or not ID_PATTERN.fullmatch(document["request_id"])
    ):
        raise AttestationError("response_invalid", "response request_id is invalid")
    if document["request_sha256"] is not None and (
        not isinstance(document["request_sha256"], str)
        or not HASH_PATTERN.fullmatch(document["request_sha256"])
    ):
        raise AttestationError("response_invalid", "response request_sha256 is invalid")
    _validate_timestamp(document["observed_at"], label="observed_at")
    _require_string(document["observer_host"], label="observer_host", maximum=255)
    status_value = document["status"]
    if status_value not in ("verified", "blocked"):
        raise AttestationError("response_invalid", "response status is invalid")
    if status_value == "blocked":
        if (
            not isinstance(document["reason_code"], str)
            or document["reason_code"] not in REASON_CODES
        ):
            raise AttestationError(
                "response_invalid", "blocked response requires reason_code"
            )
        if (
            document["source"] is not None
            or document["target"] is not None
            or document["target_readonly"] is not None
            or document["target_receive_resume_token"] is not None
            or document["files"] != []
        ):
            raise AttestationError(
                "response_invalid", "blocked response must not contain evidence"
            )
        return document
    if document["reason_code"] is not None:
        raise AttestationError(
            "response_invalid", "verified response cannot have reason_code"
        )
    if document["request_id"] is None or document["request_sha256"] is None:
        raise AttestationError(
            "response_invalid", "verified response requires request identity"
        )
    if (
        document["target_readonly"] != "on"
        or document["target_receive_resume_token"] is not None
    ):
        raise AttestationError(
            "response_invalid", "verified target receive state is invalid"
        )
    evidence_documents: dict[str, dict[str, Any]] = {}
    for label in ("source", "target"):
        evidence = _closed_object(
            document[label],
            SNAPSHOT_EVIDENCE_FIELDS,
            label=f"response {label}",
            error_code="response_invalid",
        )
        evidence_documents[label] = evidence
        validate_dataset(evidence["dataset"], label=f"response {label} dataset")
        validate_dataset(evidence["pool"], label=f"response {label} pool")
        if (
            "/" in evidence["pool"]
            or evidence["dataset"].split("/", 1)[0] != evidence["pool"]
        ):
            raise AttestationError(
                "response_invalid", f"response {label} pool is invalid"
            )
        for field in ("pool_guid", "snapshot_guid", "createtxg"):
            if not _is_uint64_decimal(evidence[field]):
                raise AttestationError(
                    "response_invalid", f"response {label} {field} is invalid"
                )
        if (
            not isinstance(evidence["creation_epoch"], int)
            or isinstance(evidence["creation_epoch"], bool)
            or evidence["creation_epoch"] < 0
        ):
            raise AttestationError(
                "response_invalid", f"response {label} creation is invalid"
            )
        snapshot_value = evidence["snapshot"]
        snapshot_prefix = f"{evidence['dataset']}@"
        if (
            not isinstance(snapshot_value, str)
            or not snapshot_value.startswith(snapshot_prefix)
            or not snapshot_value[len(snapshot_prefix) :]
            or "@" in snapshot_value[len(snapshot_prefix) :]
            or "/" in snapshot_value[len(snapshot_prefix) :]
        ):
            raise AttestationError(
                "response_invalid", f"response {label} snapshot is invalid"
            )
    if (
        evidence_documents["source"]["snapshot_guid"]
        != evidence_documents["target"]["snapshot_guid"]
    ):
        raise AttestationError("response_invalid", "response snapshot GUIDs differ")
    if (
        evidence_documents["source"]["pool_guid"]
        == evidence_documents["target"]["pool_guid"]
    ):
        raise AttestationError(
            "response_invalid", "response pool GUIDs are not distinct"
        )
    raw_files = document["files"]
    if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= MAX_FILES:
        raise AttestationError(
            "response_invalid", "verified response files are invalid"
        )
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, value_file in enumerate(raw_files):
        item = _closed_object(
            value_file,
            RESPONSE_FILE_FIELDS,
            label=f"response files[{index}]",
            error_code="response_invalid",
        )
        if item["status"] != "verified":
            raise AttestationError(
                "response_invalid", "response file status is invalid"
            )
        validate_relative_path(item["relative_path"], label="response relative_path")
        if not isinstance(item["id"], str) or not ID_PATTERN.fullmatch(item["id"]):
            raise AttestationError("response_invalid", "response file id is invalid")
        for field in ("expected_sha256", "observed_sha256"):
            if not isinstance(item[field], str) or not HASH_PATTERN.fullmatch(
                item[field]
            ):
                raise AttestationError(
                    "response_invalid", f"response file {field} is invalid"
                )
        if item["expected_sha256"] != item["observed_sha256"]:
            raise AttestationError("response_invalid", "response file digests differ")
        for field in ("expected_bytes", "observed_bytes"):
            if (
                not isinstance(item[field], int)
                or isinstance(item[field], bool)
                or not 1 <= item[field] <= MAX_ATTESTED_FILE_BYTES
            ):
                raise AttestationError(
                    "response_invalid", f"response file {field} is invalid"
                )
        if item["expected_bytes"] != item["observed_bytes"]:
            raise AttestationError(
                "response_invalid", "response file byte counts differ"
            )
        if item["id"] in seen_ids or item["relative_path"] in seen_paths:
            raise AttestationError(
                "response_invalid", "response file identities are duplicated"
            )
        seen_ids.add(item["id"])
        seen_paths.add(item["relative_path"])
    return document


def _open_private_directory(path: Path) -> int:
    if not path.is_absolute() or path == Path("/"):
        raise AttestationError(
            "state_unsafe", "attestation directory must be an absolute non-root path"
        )
    try:
        fd = _open_absolute_directory(os.fspath(path))
        info = os.fstat(fd)
    except AttestationError as exc:
        raise AttestationError(
            "state_unsafe", "attestation directory is unavailable"
        ) from exc
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise AttestationError(
            "state_unsafe",
            "attestation directory must be owned by the caller and mode 0700",
        )
    return fd


def _direct_child_name(path: Path, directory: Path, *, label: str) -> str:
    if (
        not path.is_absolute()
        or path.parent != directory
        or path.name in ("", ".", "..")
    ):
        raise AttestationError(
            "state_unsafe",
            f"{label} must be a direct child of the attestation directory",
        )
    return path.name


def read_private_request(directory_fd: int, name: str) -> bytes:
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise AttestationError(
            "request_unavailable", "request file is unavailable"
        ) from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise AttestationError(
                "request_unsafe",
                "request must be single-link, caller-owned, regular, and inaccessible to group/other",
            )
        if info.st_size > MAX_REQUEST_BYTES:
            raise AttestationError(
                "request_too_large", "request exceeds the byte limit"
            )
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(fd, 128 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > MAX_REQUEST_BYTES:
                raise AttestationError(
                    "request_too_large", "request exceeds the byte limit"
                )
            chunks.append(chunk)
        if observed != info.st_size:
            raise AttestationError(
                "request_changed", "request size changed while reading"
            )
        return b"".join(chunks)
    finally:
        os.close(fd)


def atomic_write_response(
    directory_fd: int, name: str, response: Mapping[str, Any]
) -> None:
    raw = (
        json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    temporary_name: str | None = None
    fd: int | None = None
    try:
        for _attempt in range(100):
            candidate = f".{name}.{secrets.token_hex(8)}.tmp"
            try:
                fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_fd,
                )
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        if fd is None or temporary_name is None:
            raise AttestationError(
                "response_write_failed", "could not allocate response temporary file"
            )
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o600)
        os.close(fd)
        fd = None
        os.replace(
            temporary_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd
        )
        temporary_name = None
        os.fsync(directory_fd)
    except AttestationError:
        raise
    except OSError as exc:
        raise AttestationError(
            "response_write_failed", "could not write response atomically"
        ) from exc
    finally:
        if fd is not None:
            os.close(fd)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_cli(args: argparse.Namespace, *, runner: CommandRunner | None = None) -> int:
    directory = Path(args.attestation_dir)
    request_path = Path(args.request)
    response_path = Path(args.response)
    allowed_root = validate_relative_path(
        args.allowed_relative_root, label="allowed relative root"
    )
    expected_source = validate_dataset(args.expected_source, label="expected source")
    expected_target = validate_dataset(args.expected_target, label="expected target")
    if expected_source.split("/", 1)[0] == expected_target.split("/", 1)[0]:
        raise AttestationError(
            "topology_mismatch", "expected datasets must name different pools"
        )
    if runner is None:
        runner = ReadOnlyCommandAdapter(
            zfs_path=args.zfs_path,
            zpool_path=args.zpool_path,
            timeout_seconds=args.command_timeout_seconds,
            max_output_bytes=args.max_command_output_bytes,
        )
    request_name = _direct_child_name(request_path, directory, label="request")
    response_name = _direct_child_name(response_path, directory, label="response")
    if request_name == response_name:
        raise AttestationError("state_unsafe", "request and response paths must differ")
    directory_fd = _open_private_directory(directory)
    request_id: str | None = None
    request_digest: str | None = None
    observed = utc_now()
    host = socket.gethostname()
    exit_code = 0
    try:
        try:
            raw = read_private_request(directory_fd, request_name)
            request_digest = hashlib.sha256(raw).hexdigest()
            request = parse_request(
                raw,
                expected_source=expected_source,
                expected_target=expected_target,
                allowed_relative_root=allowed_root,
            )
            request_id = request.request_id
            source, target, files = attest(request, runner=runner)
            response = build_response(
                request_id=request_id,
                request_sha256=request_digest,
                status_value="verified",
                reason_code=None,
                observed_at=observed,
                observer_host=host,
                source=source,
                target=target,
                target_readonly="on",
                target_receive_resume_token=None,
                files=files,
            )
        except AttestationError as exc:
            exit_code = 1
            response = build_response(
                request_id=request_id,
                request_sha256=request_digest,
                status_value="blocked",
                reason_code=exc.code,
                observed_at=observed,
                observer_host=host,
                source=None,
                target=None,
                target_readonly=None,
                target_receive_resume_token=None,
                files=(),
            )
            print(f"attestation blocked: {exc.code}: {exc}", file=sys.stderr)
        atomic_write_response(directory_fd, response_name, response)
    finally:
        os.close(directory_fd)
    return exit_code


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation-dir", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--response", required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--allowed-relative-root", required=True)
    parser.add_argument("--zfs-path", required=True)
    parser.add_argument("--zpool-path", required=True)
    parser.add_argument(
        "--command-timeout-seconds",
        type=float,
        default=DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--max-command-output-bytes",
        type=int,
        default=MAX_COMMAND_OUTPUT_BYTES,
    )
    return parser


def main() -> int:
    try:
        return run_cli(argument_parser().parse_args())
    except AttestationError as exc:
        print(f"attestation failed: {exc.code}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
