"""Original Inbox managed directories and logs, without opening importer data."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .config import DaybookInboxConfig


@dataclass(frozen=True)
class Directory:
    path: str
    owner: str
    group: str
    mode: int


@dataclass(frozen=True)
class Log:
    path: str
    owner: str
    group: str
    mode: int = 0o600


def directories(cfg: DaybookInboxConfig) -> tuple[Directory, ...]:
    if not cfg.daybook_voice_memo_inbox_enabled:
        return ()
    user = cfg.daybook_voice_memo_inbox_service_user
    return (
        Directory(str(PurePosixPath(cfg.daybook_voice_memo_inbox_install_root).parent), "root", "wheel", 0o755),
        Directory(cfg.daybook_voice_memo_inbox_install_root, "root", "wheel", 0o755),
        Directory(cfg.daybook_voice_memo_inbox_service_home + "/Library/LaunchAgents", user, "staff", 0o755),
        Directory(cfg.daybook_voice_memo_inbox_runtime_dir, user, "staff", 0o700),
        Directory(cfg.daybook_voice_memo_inbox_log_dir, user, "staff", 0o700),
        Directory(cfg.daybook_voice_memo_inbox_credential_dir, user, "staff", 0o700),
    )


def logs(cfg: DaybookInboxConfig) -> tuple[Log, ...]:
    if not cfg.daybook_voice_memo_inbox_enabled:
        return ()
    return tuple(
        Log(path, cfg.daybook_voice_memo_inbox_service_user, "staff")
        for path in (
            cfg.daybook_voice_memo_inbox_stdout_log,
            cfg.daybook_voice_memo_inbox_stderr_log,
            cfg.daybook_voice_memo_inbox_long_stdout_log,
            cfg.daybook_voice_memo_inbox_long_stderr_log,
        )
    )
