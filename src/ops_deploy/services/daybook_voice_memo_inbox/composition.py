"""Final Inbox resource expectations under the original enabled keeper.

Installer actions still use the original disabled-first Inbox resources. This
projection is only for observing the final composed state: the runtime keeper
owns the shared live plist while enabled. It grants no activation or update.
"""

from __future__ import annotations

from collections.abc import Mapping

from ops_deploy.core.secrets import SecretContent
from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig
from ops_deploy.services.daybook_operations_runtime.decision import InstalledRuntime
from ops_deploy.services.daybook_operations_runtime.render import render_resource

from .config import DaybookInboxConfig
from .render import InboxResource, resources


def final_resources(
    cfg: DaybookInboxConfig,
    secrets: Mapping[str, str],
    *,
    runtime: DaybookRuntimeConfig | None = None,
    installed: InstalledRuntime | None = None,
) -> tuple[InboxResource, ...]:
    """Compare the declared shared resource owner, with no new marker or flag."""
    original = resources(cfg, secrets)
    if runtime is None:
        if installed is not None:
            raise ValueError("Inbox runtime evidence requires its declared runtime configuration")
        return original
    if (
        runtime.owner != "root"
        or runtime.user != cfg.daybook_voice_memo_inbox_service_user
        or str(runtime.home) != cfg.daybook_voice_memo_inbox_service_home
        or str(runtime.install_root) != cfg.daybook_voice_memo_inbox_install_root
        or str(runtime.python) != cfg.daybook_voice_memo_inbox_python
        or runtime.python_version != cfg.daybook_voice_memo_inbox_python_version
        or runtime.revision != cfg.daybook_voice_memo_inbox_repo_ref
        or runtime.label != cfg.daybook_voice_memo_inbox_launchd_label
        or str(runtime.plist) != cfg.daybook_voice_memo_inbox_plist_path
        or str(runtime.importer_policy) != cfg.daybook_voice_memo_inbox_policy_path
    ):
        raise ValueError("Inbox and runtime must retain their original shared source and resource bindings")
    if not cfg.daybook_voice_memo_inbox_enabled or installed is None or not installed.enabled:
        return original
    return tuple(
        InboxResource(
            row.path, row.owner, row.group, row.mode, SecretContent(render_resource(runtime, "runtime.plist.j2"))
        )
        if row.path == cfg.daybook_voice_memo_inbox_plist_path
        else row
        for row in original
    )
