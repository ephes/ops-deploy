"""Filesystem declarations of the sessions layout, no host I/O."""

from __future__ import annotations

import pytest

from ops_deploy.services.daybook_sessions import DaybookSessionsConfig
from ops_deploy.services.daybook_sessions.layout import layout
from tests.test_daybook_sessions_resources import config


def test_disabled_sessions_has_no_filesystem_declarations() -> None:
    result = layout(DaybookSessionsConfig(daybook_sessions_enabled=False))
    assert (result.directories, result.logs, result.retired_timers, result.remove_files) == ((), (), (), ())


@pytest.mark.parametrize("bad", ["relative", "/", "/owned/../other", "/owned/bad\nname"])
def test_legacy_removals_cannot_escape_absolute_declared_file_contract(bad: str) -> None:
    with pytest.raises(ValueError, match="absolute without traversal"):
        layout(config(daybook_sessions_remove_legacy_runner_paths=[bad]))
