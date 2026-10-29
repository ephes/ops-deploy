"""Synthetic structural index checks; no application/database or inventory access."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "paperless_index_state",
    Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/index_state.py",
)
assert SPEC is not None
assert SPEC.loader is not None
INDEX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INDEX)
EXPECTED = {"schema_version": 2, "schema_fingerprint": "synthetic-schema", "language": "en"}


def metadata(path: Path, segments: list[dict[str, Any]]) -> None:
    (path / "meta.json").write_text(json.dumps({"segments": segments}))
    (path / ".index_settings.json").write_text(json.dumps(EXPECTED))


def test_counts_subtract_tantivy_deletions_and_ignore_no_documents(tmp_path: Path) -> None:
    metadata(tmp_path, [{"segment_id": "synthetic", "max_doc": 5, "deletes": {"num_deleted_docs": 2}}])
    assert INDEX.inspect_index(tmp_path, 3, EXPECTED) == {
        "reindex": False,
        "reasons": [],
        "document_count": 3,
        "indexed_count": 3,
    }
    result = INDEX.inspect_index(tmp_path, 4, EXPECTED)
    assert result["reindex"]
    assert result["reasons"] == ["document-count-mismatch"]
    metadata(tmp_path, [])
    assert INDEX.inspect_index(tmp_path, 0, EXPECTED)["reindex"] is False
    assert INDEX.inspect_index(tmp_path, 1, EXPECTED)["reindex"] is True


def test_deeply_nested_metadata_requests_repair(tmp_path: Path) -> None:
    metadata(tmp_path, [])
    (tmp_path / "meta.json").write_bytes(b"[" * 200000)
    assert INDEX.inspect_index(tmp_path, 0, EXPECTED)["reasons"] == ["missing-or-invalid-index-metadata"]


@pytest.mark.parametrize("trigger", ["release", "packages", "migrations", "force"])
def test_declared_trigger_does_not_require_count_drift(tmp_path: Path, trigger: str) -> None:
    metadata(tmp_path, [])
    assert INDEX.inspect_index(tmp_path, 0, EXPECTED, triggers=[trigger])["reasons"] == [trigger]


@pytest.mark.parametrize(
    ("key", "value"), [("language", "de"), ("schema_version", 1), ("schema_fingerprint", "changed")]
)
def test_stale_sentinel_with_matching_count_requires_rebuild(tmp_path: Path, key: str, value: Any) -> None:
    metadata(tmp_path, [])
    (tmp_path / ".index_settings.json").write_text(json.dumps({**EXPECTED, key: value}))
    assert INDEX.inspect_index(tmp_path, 0, EXPECTED)["reasons"] == ["schema-or-language-mismatch"]


@pytest.mark.parametrize(
    "meta",
    [
        {},
        [],
        {"segments": None},
        {"segments": [1]},
        {"segments": [{"segment_id": "a", "max_doc": True}]},
        {"segments": [{"segment_id": "a", "max_doc": -1}]},
        {"segments": [{"segment_id": "a", "max_doc": 2**32}]},
        {"segments": [{"segment_id": "a", "max_doc": 1, "deletes": {"num_deleted_docs": 2}}]},
        {"segments": [{"segment_id": "a", "max_doc": 1, "deletes": []}]},
        {"segments": [{"segment_id": "a", "max_doc": 1}, {"segment_id": "a", "max_doc": 1}]},
    ],
)
def test_malformed_metadata_cannot_be_healthy(tmp_path: Path, meta: Any) -> None:
    metadata(tmp_path, [])
    (tmp_path / "meta.json").write_text(json.dumps(meta))
    assert INDEX.inspect_index(tmp_path, 0, EXPECTED)["reasons"] == ["missing-or-invalid-index-metadata"]


def test_missing_duplicate_and_oversize_metadata_are_not_accepted(tmp_path: Path) -> None:
    assert INDEX.inspect_index(tmp_path, 0, EXPECTED)["reindex"] is True
    metadata(tmp_path, [])
    for body in ('{"segments":[],"segments":[]}', "{", " " * (INDEX.LIMIT + 1)):
        (tmp_path / "meta.json").write_text(body)
        assert INDEX.inspect_index(tmp_path, 0, EXPECTED)["reasons"] == ["missing-or-invalid-index-metadata"]


def test_symlink_and_special_file_refuse_without_reading_destination(tmp_path: Path) -> None:
    metadata(tmp_path, [])
    target = tmp_path / "unrelated"
    target.write_text("must never be read as index metadata")
    (tmp_path / "meta.json").unlink()
    (tmp_path / "meta.json").symlink_to(target)
    with pytest.raises(INDEX.UnsafeIndexMetadata):
        INDEX.inspect_index(tmp_path, 0, EXPECTED)
    assert target.read_text() == "must never be read as index metadata"
    (tmp_path / "meta.json").unlink()
    os.mkfifo(tmp_path / "meta.json")
    with pytest.raises(INDEX.UnsafeIndexMetadata):
        INDEX.inspect_index(tmp_path, 0, EXPECTED)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(INDEX.UnsafeIndexMetadata):
        INDEX.inspect_index(alias, 0, EXPECTED)


@pytest.mark.parametrize("count", [True, -1, 1.2, "0", 2**63])
def test_invalid_database_count_refuses_before_metadata_reads(tmp_path: Path, count: Any) -> None:
    with pytest.raises(ValueError, match="invalid index metadata count"):
        INDEX.inspect_index(tmp_path, count, EXPECTED)
