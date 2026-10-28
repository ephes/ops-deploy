"""Sessions resource substage, separate from source/Brew/probe orchestration.

Not a standalone role: its caller must first converge original source/runtime
and classifier prerequisites. The full controller orders those stages; no
inventory engine is switched before the owned native proof qualifies.
"""

import pwd

from ops_sessions_controls import browser_access, identity_gate, identity_source_ready, metadata, policy_gate, preflight, seed_auth
from ops_sessions_launchd import Launchd, require_reconcile_quiescence
from ops_sessions_resources import (ResourceError, directory_matches, ensure_directory,
                                    ensure_log, file_matches, put_resource, remove_declared_file)


def controller(data):
    cfg = data["config"]
    uid = pwd.getpwnam(cfg["daybook_sessions_service_user"]).pw_uid
    return Launchd("system" if cfg["daybook_sessions_launchd_scope"] == "system" else "gui/" + str(uid))


def units(data):
    cfg = data["config"]
    if not cfg["daybook_sessions_launchd_manage_state"]:
        return []
    rows = []
    for prefix in ("daybook_sessions", "daybook_archive_quote_classifier", "daybook_weeknotes_reconcile"):
        if prefix == "daybook_weeknotes_reconcile" and not cfg[prefix + "_enabled"]:
            continue
        disabled_component = prefix == "daybook_archive_quote_classifier" and not cfg[prefix + "_enabled"]
        retired = (not cfg[prefix + "_launchd_enabled"] if prefix != "daybook_weeknotes_reconcile"
                   else cfg[prefix + "_launchd_retired"])
        paths = [cfg[prefix + suffix] for suffix in ("_env_file", "_launcher_path", "_launchd_plist_path")]
        start = (cfg["daybook_sessions_launchd_start_service"] if prefix == "daybook_sessions"
                 else cfg["daybook_archive_quote_classifier_run_at_load"] if prefix == "daybook_archive_quote_classifier"
                 else False)
        if prefix == "daybook_archive_quote_classifier":
            paths.append(cfg["daybook_sessions_env_file"])
        rows.append({"label": cfg[prefix + "_launchd_label"], "plist": cfg[prefix + "_launchd_plist_path"], "paths": paths,
                     "retired": retired and not disabled_component,
                     "enabled": cfg[prefix + "_launchd_enabled"] and not disabled_component,
                     "disabled_component": disabled_component, "start": start,
                     "early_quiesced": prefix == "daybook_weeknotes_reconcile"
                                       and cfg["daybook_sessions_launchd_scope"] == "system"})
    return rows


def auth_current(data, *, planning=True):
    cfg = data["config"]
    if not cfg["daybook_weeknotes_reconcile_enabled"]:
        return True
    if planning and cfg["daybook_weeknotes_reconcile_pi_auth_rotate"]:
        return False  # explicit original rotation always requests a managed copy
    return file_matches({"path": cfg["daybook_weeknotes_reconcile_pi_agent_dir"] + "/auth.json",
                         "owner": cfg["daybook_sessions_service_user"],
                         "group": cfg["daybook_sessions_service_group"], "mode": 0o600}, strict=True)


def inspect(data, loader, *, planning=True):
    preflight(data)
    changed = {row["path"] for row in data["resources"] if not file_matches(row, content=True)}
    directories = all(directory_matches(row) for row in data["directories"])
    if directories:
        browser_access(data["config"])
    logs = all(file_matches(row) for row in data["logs"])
    removed = all(metadata(path) is None for path in data["remove_files"])
    rail_paths = {data["config"]["daybook_weeknotes_identity_" + field + "_path"] for field in ("helper", "launcher")}
    identity = not data["identity"]["required"]
    policy = not data["config"]["daybook_weeknotes_reconcile_enabled"]
    # An earlier explicit source operation may be queued (including valid
    # unborn-checkout recovery). Never import old/incomplete application bytes
    # during planning. Apply and final verification bind the actual final code.
    ready = not (planning and data.get("source_changed")) and identity_source_ready(data)
    if ready and not policy:
        policy_gate(data, loader)
        policy = True
    if data["identity"]["required"] and not rail_paths & changed and ready:
        identity = identity_gate(data, loader)["identity_verified"]
    launchd = controller(data)
    timers = True
    for unit in units(data):
        state = launchd.state(unit["label"])
        if unit["retired"]:
            if state["running"] and not unit["early_quiesced"]:
                raise ResourceError("sessions_timer_in_flight")
            timers = (not state["loaded"] and state["disabled"] and metadata(unit["plist"]) is None) and timers
        else:
            timers = ((state["loaded"] and not state["disabled"]) if unit["enabled"]
                      else (not state["loaded"] and (state["disabled"] or unit["disabled_component"]))) and timers
        if planning and unit["enabled"] and unit["start"] and data.get("source_changed"):
            timers = False
    return {"current": not changed and directories and logs and removed and auth_current(data, planning=planning) and identity and policy and timers,
            "identity_verified": bool(identity and data["identity"]["required"])}


def apply(data, loader):
    preflight(data)
    require_reconcile_quiescence(data["config"])
    launchd = controller(data)
    # Refuse every retired in-flight timer before any directory/config/auth work.
    for unit in units(data):
        if unit["retired"]:
            launchd.require_quiet(unit["label"])
    changed = {row["path"] for row in data["resources"] if not file_matches(row, content=True)}
    for row in data["directories"]:
        directory_matches(row)  # inspect all private objects before adopting any
    for row in data["logs"]:
        file_matches(row)  # validate all existing log types before any writes
    for path in data["remove_files"]:
        info = metadata(path)
        if info is not None:
            import stat
            if not (stat.S_ISLNK(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)):
                raise ResourceError("sessions_resource_remove_type_invalid")
    for row in data["directories"]:
        ensure_directory(row)
    browser_access(data["config"])
    rail_paths = {data["config"]["daybook_weeknotes_identity_" + field + "_path"] for field in ("helper", "launcher")}
    for row in data["resources"]:
        if row["path"] in rail_paths:
            put_resource(row)
    # Never render the epoch/checksum/env as verified until this gate succeeds.
    policy_gate(data, loader)
    verified = identity_gate(data, loader)
    seed_auth(data, launchd)
    for row in data["logs"]:
        ensure_log(row)
    for path in data["remove_files"]:
        remove_declared_file(path)
    for row in data["resources"]:
        if row["path"] not in rail_paths:
            put_resource(row)
    for unit in units(data):
        if unit["retired"]:
            launchd.retire(unit["label"], unit["plist"])
        elif unit["enabled"]:
            state = launchd.state(unit["label"])
            restart = unit["start"] and (bool(set(unit["paths"]) & changed)
                                        or bool(data.get("source_changed")) or not state["loaded"])
            launchd.enable(unit["label"], unit["plist"], changed=unit["plist"] in changed, restart=restart)
        else:
            state = launchd.state(unit["label"])
            if state["loaded"]:
                launchd.mutate("bootout", launchd.domain + "/" + unit["label"])
            if not state["disabled"] and not unit["disabled_component"]:
                launchd.mutate("disable", launchd.domain + "/" + unit["label"])
    return verified
