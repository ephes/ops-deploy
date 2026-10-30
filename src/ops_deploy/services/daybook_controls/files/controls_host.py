"""Exact-label controls; no application/source/config/state/log body reads."""

import contextlib
import json
import os
import stat
import sys
import time

from ops_control_filesystem import directory_fd, resource_path
from ops_control_launchd import PhotosControlError, PhotosControls


class ControlError(RuntimeError):
    pass


def removal_paths(data):
    home = resource_path(data["home"])
    plist = home / "Library/LaunchAgents" / (data["label"] + ".plist")
    for path in (home, home / "Library", plist.parent, plist):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ControlError("daybook_control_linked_removal_path")
        if path == plist and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ControlError("daybook_control_invalid_removal_leaf")
        if path != plist and not stat.S_ISDIR(info.st_mode):
            raise ControlError("daybook_control_invalid_removal_parent")
    return plist


def remove_plist(path):
    try:
        with directory_fd(path.parent) as parent:
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ControlError("daybook_control_removal_leaf_changed")
            os.unlink(path.name, dir_fd=parent)
            return True
    except FileNotFoundError:
        return False


def execute(data, *, controls=None, sleep=None):
    service, action = data["service"], data["action"]
    if service not in {"photos", "archive", "attention"} or type(data["uid"]) is not int or data["uid"] <= 0:
        raise ControlError("daybook_control_request_invalid")
    if os.geteuid() != (data["uid"] if service == "archive" else 0):
        raise ControlError("daybook_control_connecting_identity_invalid")
    if (service == "attention" and (action != "remove" or data["confirmed"] is not True)) or (
        service != "attention" and action != "disable"
    ):
        raise ControlError("daybook_control_action_invalid")
    ctl = controls or PhotosControls(data)
    pause = sleep or time.sleep
    plist = removal_paths(data) if service == "attention" else None
    before = {"domain_available": False, "disabled": None, "loaded": None}
    with contextlib.suppress(PhotosControlError):
        before = ctl.snapshot()
    if service == "attention" and not before["domain_available"]:
        raise ControlError("daybook_control_GUI_domain_unavailable")
    # Photos emergency disable attempts both commands even when disable fails.
    # Archive/attention retain their original immediate disable failure.
    disabled = ctl.attempt("disable", ctl.service)
    if not disabled and service != "photos":
        raise ControlError("daybook_control_disable_failed")
    ctl.attempt("bootout", ctl.service)
    if service == "archive":
        # Preserve its original thirty observations/two-second grace period.
        for attempt in range(30):
            observed = ctl.snapshot(final=True)
            if observed["loaded"] is not True:
                break
            if attempt == 29:
                raise ControlError("daybook_control_archive_still_loaded")
            pause(2)
    ctl.require_quiescent()
    removed = remove_plist(plist) if plist is not None else False
    return {
        "schema_version": 1,
        "disabled_unloaded": True,
        "plist_removed": removed,
        "previously_disabled_unloaded": before["disabled"] is True and before["loaded"] is False,
    }


def main():
    try:
        result = execute(json.load(sys.stdin))
    except Exception:
        # No raw launchd result, path, private input or traceback escapes.
        print('{"schema_version":1,"status":"failed","reason":"daybook_control_failed"}', file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
