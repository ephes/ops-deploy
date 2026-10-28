"""Release-source schema expectations and strict aggregate count boundaries."""

import hashlib
import json
import shlex
from pathlib import Path

import pytest

from ops_deploy.services.paperless.index_contract import (
    document_count_command,
    expected_index_sentinels,
    parse_document_count,
)


def test_actual_release_descriptors_bind_schema_fingerprint() -> None:
    fixture = json.loads((Path(__file__).parent / "parity/paperless/index-schema-3.2.1.json").read_text())
    expected = expected_index_sentinels(fixture["release"], "eng+deu")
    assert expected["schema_version"] == fixture["schema_version"] == 2
    actual = hashlib.blake2b(json.dumps(fixture["field_descriptors"]).encode()).hexdigest()
    assert expected["schema_fingerprint"] == actual == fixture["schema_fingerprint"]


@pytest.mark.parametrize(
    ("ocr", "language"), [("eng+deu", "en"), ("DEU+eng", "de"), ("jpn", None), ("chi_sim+eng", None)]
)
def test_search_language_uses_primary_upstream_mapping(ocr: str, language: str | None) -> None:
    assert expected_index_sentinels("3.2.1", ocr)["language"] == language


def test_unsupported_release_cannot_reuse_current_schema() -> None:
    with pytest.raises(ValueError, match="release contract"):
        expected_index_sentinels("3.0.4", "eng")


@pytest.mark.parametrize("ocr", ["", "eng\nPAPERLESS_URL=bad", "eng+", "../deu"])
def test_invalid_language_refuses(ocr: str) -> None:
    with pytest.raises(ValueError, match="OCR language"):
        expected_index_sentinels("3.2.1", ocr)


@pytest.mark.parametrize(("text", "value"), [("0", 0), ("2\n", 2), ("9223372036854775807\n", 2**63 - 1)])
def test_sql_count_is_one_bounded_integer(text: str, value: int) -> None:
    assert parse_document_count(text) == value


@pytest.mark.parametrize(
    "text", ["", "-1", "True", " 2", "2\n3\n", "BEGIN\n2\nCOMMIT\n", "01", "9223372036854775808", "1" * 100]
)
def test_extra_output_or_invalid_count_refuses(text: str) -> None:
    with pytest.raises(ValueError, match="count"):
        parse_document_count(text)


def test_aggregate_uses_only_readonly_bounded_transaction() -> None:
    argv = shlex.split(document_count_command("paperless", 5432))
    assert argv[:-1] == [
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-XAtq",
        "-v",
        "ON_ERROR_STOP=1",
        "-p",
        "5432",
        "-d",
        "paperless",
        "-c",
    ]
    assert argv[-1] == (
        "BEGIN READ ONLY; SET LOCAL statement_timeout = '30s'; "
        "SELECT count(*) FROM public.documents_document WHERE deleted_at IS NULL; ROLLBACK;"
    )


@pytest.mark.parametrize("database", ["-dpostgres", "paperless;DROP DATABASE x", "a'", "public.docs", "a\nb"])
def test_count_database_cannot_change_command_or_sql(database: str) -> None:
    with pytest.raises(ValueError, match="database name"):
        document_count_command(database, 5432)


@pytest.mark.parametrize("port", [True, 0, 65536])
def test_count_port_is_a_real_bounded_integer(port: int) -> None:
    with pytest.raises(ValueError, match="port"):
        document_count_command("paperless", port)
