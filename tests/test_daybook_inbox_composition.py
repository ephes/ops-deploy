"""Final declared keeper/Inbox composition, no app, host or credential calls."""

from __future__ import annotations

from typing import Any

import pytest

from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig
from ops_deploy.services.daybook_operations_runtime.decision import InstalledRuntime
from ops_deploy.services.daybook_operations_runtime.render import render_resource
from ops_deploy.services.daybook_voice_memo_inbox.composition import final_resources
from ops_deploy.services.daybook_voice_memo_inbox.render import resources
from tests.test_daybook_inbox_declaration import config, secrets


def runtime(**values: Any) -> DaybookRuntimeConfig:
    return DaybookRuntimeConfig(user="fixture", revision="a" * 40, **values)


def test_enabled_keeper_final_projection_replaces_only_shared_live_plist() -> None:
    cfg = config()
    original = resources(cfg, secrets())
    profile = runtime()
    final = final_resources(cfg, secrets(), runtime=profile, installed=InstalledRuntime(True, True, True))
    assert len(final) == len(original)
    changed = [(before, after) for before, after in zip(original, final, strict=True) if before != after]
    assert len(changed) == 1
    before, after = changed[0]
    assert before.path == after.path == cfg.daybook_voice_memo_inbox_plist_path
    assert (before.owner, before.group, before.mode) == (after.owner, after.group, after.mode)
    assert after.content.reveal() == render_resource(profile, "runtime.plist.j2").encode()
    assert resources(cfg, secrets()) == original, "installer must retain its original disabled-first resources"


@pytest.mark.parametrize("installed", [None, InstalledRuntime(False, True, True)])
def test_absent_or_disabled_runtime_keeps_original_disabled_install(installed: InstalledRuntime | None) -> None:
    cfg = config()
    assert final_resources(cfg, secrets(), runtime=runtime(), installed=installed) == resources(cfg, secrets())


@pytest.mark.parametrize("values", [{"owner": "user"}, {"label": "owned.other"}, {"python_version": "3.14.8"}])
def test_other_runtime_resource_or_interpreter_binding_is_not_treated_as_current(values: dict[str, Any]) -> None:
    cfg = config()
    with pytest.raises(ValueError, match="original shared"):
        final_resources(cfg, secrets(), runtime=runtime(**values), installed=InstalledRuntime(True, True, True))


def test_observed_enabled_bit_without_declaration_cannot_reassign_plist_ownership() -> None:
    with pytest.raises(ValueError, match="evidence requires"):
        final_resources(config(), secrets(), installed=InstalledRuntime(True, True, True))


@pytest.mark.parametrize("long_enabled", [False, True])
@pytest.mark.parametrize("keeper_enabled", [False, True])
def test_internal_raw_stdin_projection_exactly_matches_public_secret_wrapped_bytes(
    long_enabled: bool, keeper_enabled: bool
) -> None:
    from ops_deploy.services.daybook_voice_memo_inbox.render import _resource_texts
    from ops_deploy.services.daybook_voice_memo_inbox.resource_payload import resource_payload

    cfg = config(daybook_voice_memo_inbox_long_label_enabled=long_enabled)
    profile = runtime()
    observed = InstalledRuntime(keeper_enabled, True, True)
    data = resource_payload(cfg, secrets(), uid=501, runtime=profile, installed=observed)

    def expected(rows: Any) -> list[dict[str, Any]]:
        return [
            {
                "path": row.path,
                "owner": row.owner,
                "group": row.group,
                "mode": row.mode,
                "content": row.content.reveal().decode(),
            }
            for row in rows
        ]

    assert data["resources"] == expected(resources(cfg, secrets()))
    assert data["final_resources"] == expected(final_resources(cfg, secrets(), runtime=profile, installed=observed))
    assert "UNUSABLE-OWNED-CREDENTIAL" not in repr(resources(cfg, secrets()))
    assert "UNUSABLE-OWNED-CREDENTIAL" not in repr(_resource_texts(cfg, secrets()))
