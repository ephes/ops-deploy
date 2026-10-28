"""Original role filesystem declarations, separate from activation and data."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .config import DaybookSessionsConfig


@dataclass(frozen=True)
class OwnedPath:
    path: str
    owner: str
    group: str
    mode: int
    # Existing private control objects must already satisfy the original
    # ownership/type/mode guards; installation must not silently adopt them.
    strict_existing: bool = False


@dataclass(frozen=True)
class RetiredTimer:
    label: str
    plist: str


@dataclass(frozen=True)
class SessionsLayout:
    directories: tuple[OwnedPath, ...]
    logs: tuple[OwnedPath, ...]
    retired_timers: tuple[RetiredTimer, ...]
    remove_files: tuple[str, ...]


def layout(cfg: DaybookSessionsConfig) -> SessionsLayout:
    if not cfg.daybook_sessions_enabled:
        return SessionsLayout((), (), (), ())
    user, group = cfg.daybook_sessions_service_user, cfg.daybook_sessions_service_group
    owner, scope_group = ("root", "wheel") if cfg.daybook_sessions_launchd_scope == "system" else (user, group)
    directories: dict[str, OwnedPath] = {}

    def directory(path: str, account: str, file_group: str, mode: int, *, strict: bool = False) -> None:
        declared = OwnedPath(path, account, file_group, mode, strict)
        if path in directories and directories[path] != declared:
            raise ValueError("Sessions directory declarations overlap with different metadata")
        directories[path] = declared

    directory(cfg.daybook_sessions_config_dir, owner, scope_group, 0o755)
    directory(cfg.daybook_sessions_log_dir, owner, scope_group, 0o755)
    directory(str(PurePosixPath(cfg.daybook_sessions_launchd_plist_path).parent), owner, scope_group, 0o755)
    directory(str(PurePosixPath(cfg.daybook_sessions_state_path).parent), user, group, 0o750)
    directory(str(PurePosixPath(cfg.daybook_sessions_checkout_path).parent), user, group, 0o755)
    logs = [
        OwnedPath(p, user, group, 0o644) for p in (cfg.daybook_sessions_stdout_log, cfg.daybook_sessions_stderr_log)
    ]
    retired = []
    remove = list(cfg.daybook_sessions_remove_legacy_runner_paths)
    if cfg.daybook_archive_quote_classifier_enabled:
        directory(
            str(PurePosixPath(cfg.daybook_archive_quote_classifier_launchd_plist_path).parent),
            owner,
            scope_group,
            0o755,
        )
        directory(cfg.daybook_sessions_service_home + "/.daybook", user, group, 0o750)
        directory(cfg.daybook_archive_browser_user_data_dir, user, group, 0o700)
        logs.extend(
            OwnedPath(p, user, group, 0o644)
            for p in (cfg.daybook_archive_quote_classifier_stdout_log, cfg.daybook_archive_quote_classifier_stderr_log)
        )
    else:
        remove.extend(
            [
                cfg.daybook_archive_quote_classifier_launchd_plist_path,
                cfg.daybook_archive_quote_classifier_launcher_path,
                cfg.daybook_archive_quote_classifier_env_file,
            ]
        )
    if cfg.daybook_sessions_launchd_manage_state:
        if not cfg.daybook_sessions_launchd_enabled:
            retired.append(RetiredTimer(cfg.daybook_sessions_launchd_label, cfg.daybook_sessions_launchd_plist_path))
        if cfg.daybook_archive_quote_classifier_enabled and not cfg.daybook_archive_quote_classifier_launchd_enabled:
            retired.append(
                RetiredTimer(
                    cfg.daybook_archive_quote_classifier_launchd_label,
                    cfg.daybook_archive_quote_classifier_launchd_plist_path,
                )
            )
    if cfg.daybook_weeknotes_reconcile_enabled:
        directory(cfg.daybook_weeknotes_reconcile_runtime_dir, user, group, 0o700, strict=True)
        directory(cfg.daybook_weeknotes_reconcile_pi_agent_dir, user, group, 0o700, strict=True)
        logs.extend(
            OwnedPath(p, user, group, 0o640)
            for p in (cfg.daybook_weeknotes_reconcile_stdout_log, cfg.daybook_weeknotes_reconcile_stderr_log)
        )
        if cfg.daybook_sessions_launchd_manage_state and cfg.daybook_weeknotes_reconcile_launchd_retired:
            retired.append(
                RetiredTimer(
                    cfg.daybook_weeknotes_reconcile_launchd_label, cfg.daybook_weeknotes_reconcile_launchd_plist_path
                )
            )
    for path in [*directories, *(p.path for p in logs), *remove]:
        parsed = PurePosixPath(path)
        if (
            not parsed.is_absolute()
            or parsed == PurePosixPath("/")
            or ".." in parsed.parts
            or any(c in path for c in "\x00\r\n")
        ):
            raise ValueError("Sessions managed paths must be absolute without traversal")
    if len({p.path for p in logs}) != len(logs) or set(remove) & ({p.path for p in logs} | set(directories)):
        raise ValueError("Sessions managed filesystem paths overlap")
    return SessionsLayout(tuple(directories.values()), tuple(logs), tuple(retired), tuple(dict.fromkeys(remove)))
