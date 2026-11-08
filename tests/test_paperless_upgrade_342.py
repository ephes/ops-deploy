"""Release upgrade admission and root-only search regression contracts."""

import importlib
import shlex
import sqlite3

from ops_deploy.services.paperless.config import RELEASE_SHA256, PaperlessConfig
from ops_deploy.services.paperless.index_contract import document_count_command, expected_index_sentinels


def test_verified_release_and_thumbnail_dependency() -> None:
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    assert cfg.version == "3.4.2"
    assert RELEASE_SHA256 == "599be82cd8fc184436b757f9b193101fb71a90bf0facf5695dcda43152fffc85"
    packages = importlib.import_module("ops_deploy.services.paperless.deploy").PACKAGES
    assert "poppler-utils" in packages
    assert "imagemagick" not in packages


def test_index_contract_counts_only_live_roots() -> None:
    assert expected_index_sentinels("3.4.2", "eng")["schema_version"] == 4
    assert "deleted_at IS NULL AND root_document_id IS NULL" in document_count_command("paperless", 5432)


def test_version_rows_and_deleted_roots_do_not_trigger_perpetual_reindex() -> None:
    sql = shlex.split(document_count_command("paperless", 5432))[-1]
    count_query = next(part.strip() for part in sql.split(";") if "SELECT count(*)" in part)
    with sqlite3.connect(":memory:") as database:
        database.execute("ATTACH DATABASE ':memory:' AS public")
        database.execute("CREATE TABLE public.documents_document (deleted_at TEXT, root_document_id INTEGER)")
        database.executemany(
            "INSERT INTO public.documents_document VALUES (?, ?)",
            [(None, None), (None, 1), (None, 1), ("2026-11-01", None)],
        )
        assert database.execute(count_query).fetchone() == (1,)


def test_managed_environment_drops_removed_upstream_settings() -> None:
    from importlib.resources import files

    template = files("ops_deploy.services.paperless").joinpath("templates/paperless.env.j2").read_text()
    for removed in (
        "PAPERLESS_CONVERT_BINARY",
        "PAPERLESS_CONVERT_MEMORY_LIMIT",
        "PAPERLESS_CONVERT_TMPDIR",
        "PAPERLESS_GS_BINARY",
        "MAGICK_TMPDIR",
    ):
        assert removed not in template
