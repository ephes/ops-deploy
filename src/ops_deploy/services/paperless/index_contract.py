"""Release-bound index expectations; no application/backend import or database I/O.

The schema fingerprint is derived from unmodified 3.2.1 release source with its
locked whoosh-compat types (tests/parity/paperless/index-schema-3.2.1.json).
Actual full-application/native validation remains part of the deployment fixture.
"""

from __future__ import annotations

import re
import shlex

SCHEMA_VERSION = 2
SCHEMA_FINGERPRINT = (
    "71d572bdddc3094b8e24cc2f456b5d57ef74133afa647d14f870109f433251120"
    "f29d9f96645c492e3f5ec34ca8737c04116aba027ca062970653977a8556163"
)
# paperless.settings._get_search_language_setting, exact 3.2.1 mapping.
OCR_TO_SEARCH = {
    "ara": "ar",
    "dan": "da",
    "nld": "nl",
    "eng": "en",
    "fin": "fi",
    "fra": "fr",
    "deu": "de",
    "ell": "el",
    "hun": "hu",
    "ita": "it",
    "nor": "no",
    "por": "pt",
    "ron": "ro",
    "rus": "ru",
    "spa": "es",
    "swe": "sv",
    "tam": "ta",
    "tur": "tr",
}


# Current role has no explicit PAPERLESS_SEARCH_LANGUAGE setting. Infer from its
# configured OCR language exactly as upstream does; do not silently consult the
# controller's environment or import the installed application's index backend.
def expected_index_sentinels(version: str, ocr_language: str) -> dict[str, str | int | None]:
    if version != "3.2.1":
        raise ValueError("Paperless index expectations require the supported release contract")
    if not ocr_language or not re.fullmatch(r"[A-Za-z_]+(?:\+[A-Za-z_]+)*", ocr_language):
        raise ValueError("invalid OCR language list")
    primary = ocr_language.split("+", maxsplit=1)[0].lower()
    return {
        "schema_version": SCHEMA_VERSION,
        "schema_fingerprint": SCHEMA_FINGERPRINT,
        "language": OCR_TO_SEARCH.get(primary),
    }


def parse_document_count(stdout: str) -> int:
    """Accept exactly one bounded SQL aggregate, never individual rows/content."""
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,18})\n?", stdout):
        raise ValueError("invalid Paperless live-document count result")
    count = int(stdout)
    if count > 2**63 - 1:
        raise ValueError("Paperless live-document count exceeds supported range")
    return count


def document_count_command(database: str, port: int) -> str:
    """One aggregate in a read-only transaction; no application/index initializer.

    The public.documents_document relation and soft-delete predicate follow the
    exact release source. Full deployed schema parity remains a native-fixture
    requirement. Missing schema/query errors refuse rather than assuming zero.
    PostgreSQL peer authentication uses the established local postgres account;
    no password or document value is passed through argv or returned.
    """
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,62}", database):
        raise ValueError("invalid Paperless database name")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid PostgreSQL port")
    sql = (
        "BEGIN READ ONLY; SET LOCAL statement_timeout = '30s'; "
        "SELECT count(*) FROM public.documents_document WHERE deleted_at IS NULL; ROLLBACK;"
    )
    return shlex.join(
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "-XAtq",
            "-v",
            "ON_ERROR_STOP=1",
            "-p",
            str(port),
            "-d",
            database,
            "-c",
            sql,
        ]
    )
