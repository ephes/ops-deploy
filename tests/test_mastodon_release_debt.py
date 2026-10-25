"""A failed release never marks build/cache/rollout work complete."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from tests.test_mastodon_release_source import host_module, release_config


def test_failed_bundle_retries_and_keeps_cache_clear_debt_until_success(tmp_path: Path) -> None:
    module = host_module(tmp_path)
    cfg = release_config().model_dump()
    calls: list[list[str]] = []
    fail = True

    def user(_cfg: Any, argv: list[str], **_kwargs: Any) -> Any:
        calls.append(argv)
        if fail and argv[:2] == ["bundle", "install"]:
            raise RuntimeError("controlled dependency failure")
        return SimpleNamespace(returncode=0, stdout="")

    module.user = user
    module.verify_source = lambda _cfg: None
    with pytest.raises(RuntimeError, match="controlled"):
        module.bundle(cfg)
    assert module.state_read("bundle") is None
    assert module.state_read("pending-rollout") is True
    assert module.state_read("pending-cache-clear") is True
    fail = False
    module.bundle(cfg)
    assert module.state_read("bundle") == module.bundle_key(cfg)
    assert sum(command[:2] == ["bundle", "install"] for command in calls) == 2
    # A failed cache clear cannot release either debt.
    with (
        patch.object(module, "user", side_effect=RuntimeError("controlled clear failure")),
        pytest.raises(RuntimeError, match="clear"),
    ):
        module.cache_clear(cfg)
    assert module.state_read("pending-cache-clear") is True
    assert module.state_read("pending-rollout") is True
    module.cache_clear(cfg)
    assert module.state_read("pending-cache-clear") is None
    assert module.state_read("pending-rollout") is True


def test_environment_only_change_creates_no_cache_clear_debt(tmp_path: Path) -> None:
    module = host_module(tmp_path)
    module.debt(False)
    assert module.state_read("pending-rollout") is True
    assert module.state_read("pending-cache-clear") is None


def test_failed_migration_preserves_prior_history_and_rollout_debt(tmp_path: Path) -> None:
    module = host_module(tmp_path)
    cfg = release_config(migration_versions=["20260101000000", "20260102000000"]).model_dump()
    before = ["20260101000000"]
    module.database_versions = lambda _payload: before
    calls: list[list[str]] = []

    def user(_cfg: Any, argv: list[str], **_kwargs: Any) -> None:
        calls.append(argv)
        if argv[-1] == "db:migrate":
            raise RuntimeError("controlled migration failure")

    module.user = user
    with pytest.raises(RuntimeError, match="migration"):
        module.migrate({"config": cfg})
    assert module.state_read("pending-cache-clear") is True
    assert module.state_read("pending-rollout") is True
    assert before == ["20260101000000"]
    assert calls[0][-1] == "db:migrate:status"
    # A successful retry verifies ALL candidate ids, including post migrations.
    versions = iter([before, cfg["migration_versions"]])
    module.database_versions = lambda _payload: next(versions)
    module.user = lambda *_args, **_kwargs: None
    module.migrate({"config": cfg})
    assert module.state_read("pending-rollout") is True


def test_failed_assets_never_saves_success_and_missing_output_is_not_current(tmp_path: Path) -> None:
    module = host_module(tmp_path)
    cfg = release_config().model_dump()
    module.user = lambda *_args, **_kwargs: None
    module.verify_source = lambda _cfg: None
    module.assets_output = lambda _cfg: False
    with pytest.raises(ValueError, match="complete manifests"):
        module.assets(cfg)
    assert module.state_read("assets") is None
    assert module.state_read("pending-rollout") is True
    module.assets_output = lambda _cfg: True
    module.assets(cfg)
    assert module.state_read("assets") == module.assets_key(cfg)
    # A retained completion marker cannot bypass a missing installed output.
    module.assets_output = lambda _cfg: False
    module.state_write("bundle", module.bundle_key(cfg))
    module.state_write("yarn", module.yarn_key(cfg))
    module.yarn_output = lambda _cfg: True
    module.user = lambda *_args, **_kwargs: SimpleNamespace(returncode=0)
    state = module.dependencies_state(cfg, {"ruby": False, "node": False})
    assert state["assets"] is True
