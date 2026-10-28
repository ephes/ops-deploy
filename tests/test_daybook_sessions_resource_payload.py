"""Private resource transport construction, original epoch guard and code binding."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_sessions.deploy import IDENTITY_MODULES, resource_payload
from ops_deploy.services.daybook_sessions.render import _resource_texts
from tests import test_daybook_sessions_source as source_cases
from tests.test_daybook_sessions_resources import config, secrets, studio

checkout = source_cases.checkout
git = source_cases.git


def test_internal_render_rows_repr_hides_all_private_bodies() -> None:
    rows = _resource_texts(studio(), secrets())
    for value in secrets().values():
        assert value not in repr(rows)
    assert any(row.private for row in rows)


def test_private_identity_intent_is_preserved_in_payload_but_hidden_from_config_repr() -> None:
    private = "UNUSABLE-PRIVATE-IDENTITY-TITLE"
    cfg = config(daybook_weeknotes_identity_seed_moves=[{"from_title": private}])
    assert private not in repr(cfg)
    assert cfg.model_dump()["daybook_weeknotes_identity_seed_moves"] == [{"from_title": private}]


def test_retired_weeknotes_requires_original_requested_epoch_before_resource_install(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    _data, _bundle, source = checkout
    with pytest.raises(ValueError, match="original verified identity epoch"):
        resource_payload(studio(daybook_sessions_repo_ref=source.commit), secrets(), source)


def test_plain_resource_payload_has_no_identity_bypass_or_application_call(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    _data, _bundle, source = checkout
    cfg = config(daybook_sessions_repo_ref=source.commit)
    payload = resource_payload(cfg, secrets(), source)
    assert payload["identity"] == {"required": False}
    assert payload["source"]["revision"] == source.commit
    env = next(row for row in payload["resources"] if row["path"] == cfg.daybook_sessions_env_file)
    assert "fixture-secret" in env["content"]  # only intended for protected stdin
    assert env["mode"] == 0o600
    assert "identity_verified" not in payload


def test_epoch_payload_binds_exact_helper_and_closed_source_surface(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    _data, _bundle, source = checkout
    for name in IDENTITY_MODULES:
        path = source.path / ("src/daybook/" + name + ".py")
        if not path.exists():
            path.write_text("# owned synthetic code never imported\n")
    git(source.path, "add", ".")
    git(
        source.path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "owned closure",
    )
    revision = git(source.path, "rev-parse", "HEAD")
    cfg = studio(
        daybook_sessions_repo_ref=revision,
        daybook_weeknotes_post_identity_epoch="monday-after-v1",
        daybook_weeknotes_identity_required_repo_ref=revision,
        daybook_weeknotes_identity_seed_moves=[
            {
                "week": "2026-W43",
                "audience": "public",
                "blog_id": 1,
                "post_id": 2,
                "expected_revision_id": 3,
                "from_title": "Owned prior identity",
                "from_slug": "owned-prior",
            }
        ],
    )
    payload = resource_payload(cfg, secrets(), SourceTree(source.path, revision))
    identity = payload["identity"]
    assert identity["required"] is True
    assert len(identity["module_hashes"]) == 12
    for relative, digest in identity["module_hashes"].items():
        assert digest == hashlib.sha256((source.path / relative).read_bytes()).hexdigest()
    helper = next(row for row in payload["resources"] if row["path"] == cfg.daybook_weeknotes_identity_helper_path)
    assert identity["helper_sha256"] == hashlib.sha256(helper["content"].encode()).hexdigest()
    assert identity["seed_intent"]["moves"] == cfg.daybook_weeknotes_identity_seed_moves
    assert "verified" not in identity
