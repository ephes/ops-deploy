"""Bounded Paperless/Tantivy metadata inspection; never opens a search index.

The caller supplies a separately validated live-document COUNT and the expected
release schema/language sentinels. This module reads only two named metadata
files and returns aggregate counts/reasons, never document or index contents.
Equal counts cannot establish content freshness or segment-body integrity.
"""

import json
import os
import stat
import sys
from pathlib import Path

LIMIT = 1024 * 1024
MAX_COUNT = 2**63 - 1
MAX_SEGMENTS = 10000


class UnsafeIndexMetadata(RuntimeError):
    """Refuse unsafe paths or unreadable files instead of starting a repair."""


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate metadata key")
        value[key] = item
    return value


def read_metadata(directory, name):
    """Read one regular, bounded file without following its final symlink."""
    try:
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise UnsafeIndexMetadata("cannot safely open index directory") from error
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise UnsafeIndexMetadata("cannot safely read index metadata") from error
    finally:
        os.close(directory_fd)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafeIndexMetadata("index metadata is not a regular file")
        if metadata.st_size > LIMIT:
            return None
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(LIMIT + 1)
        if len(body) > LIMIT:
            return None
        try:
            return json.loads(body, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError):
            return None
    finally:
        os.close(fd)


def integer(value, maximum=MAX_COUNT):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid index metadata count")
    return value


def inspect_index(directory, document_count, expected, *, triggers=()):
    """Return whether the approved conditional reindex has a concrete trigger.

    `document_count` must count Document.objects (deleted_at IS NULL), obtained
    through a separate read-only SQL transaction. Release/package/migration and
    explicit-force decisions are passed as named triggers by the deploy caller.
    No application import, Tantivy opener, traversal or database call occurs here.
    """
    integer(document_count)
    if not isinstance(expected, dict) or set(expected) != {"schema_version", "schema_fingerprint", "language"}:
        raise ValueError("expected schema sentinels are required")
    integer(expected["schema_version"])
    if not isinstance(expected["schema_fingerprint"], str) or not expected["schema_fingerprint"]:
        raise ValueError("expected schema fingerprint is required")
    if expected["language"] is not None and not isinstance(expected["language"], str):
        raise ValueError("invalid expected search language")
    allowed = {"release", "packages", "migrations", "force"}
    if not isinstance(triggers, (tuple, list)) or any(item not in allowed for item in triggers):
        raise ValueError("unknown reindex trigger")
    directory = Path(directory)
    if directory.is_symlink():
        raise UnsafeIndexMetadata("index directory must not be a symlink")
    reasons = list(dict.fromkeys(triggers))
    sentinels = read_metadata(directory, ".index_settings.json")
    if not isinstance(sentinels, dict):
        reasons.append("missing-or-invalid-sentinels")
    elif any(type(sentinels.get(key)) is not type(value) or sentinels.get(key) != value for key, value in expected.items()):
        reasons.append("schema-or-language-mismatch")
    meta = read_metadata(directory, "meta.json")
    indexed_count = None
    try:
        if not isinstance(meta, dict) or not isinstance(meta.get("segments"), list):
            raise ValueError("missing segment metadata")
        segments = meta["segments"]
        if len(segments) > MAX_SEGMENTS:
            raise ValueError("too many segments")
        seen = set()
        total = 0
        for segment in segments:
            if not isinstance(segment, dict) or not isinstance(segment.get("segment_id"), str):
                raise ValueError("invalid segment")
            identity = segment["segment_id"]
            if not identity or identity in seen:
                raise ValueError("duplicate or empty segment")
            seen.add(identity)
            count = integer(segment.get("max_doc"), 2**32 - 1)
            deletes = segment.get("deletes")
            if deletes is None:
                deleted = 0
            elif isinstance(deletes, dict):
                deleted = integer(deletes.get("num_deleted_docs"), count)
            else:
                raise ValueError("invalid delete metadata")
            total = integer(total + count - deleted)
        indexed_count = total
        if total != document_count:
            reasons.append("document-count-mismatch")
    except ValueError:
        reasons.append("missing-or-invalid-index-metadata")
    return {"reindex": bool(reasons), "reasons": reasons, "document_count": document_count, "indexed_count": indexed_count}


def main():
    try:
        body = sys.stdin.buffer.read(65537)
        if len(body) > 65536:
            raise ValueError("index inspection payload exceeds size limit")
        settings = json.loads(body, object_pairs_hook=unique_object)
        if not isinstance(settings, dict) or set(settings) != {"directory", "document_count", "expected", "triggers"}:
            raise ValueError("invalid index inspection payload")
        result = inspect_index(
            settings["directory"], settings["document_count"], settings["expected"], triggers=settings["triggers"]
        )
    except (ValueError, TypeError, OSError, UnsafeIndexMetadata, RecursionError):
        print("Paperless index metadata inspection refused", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
