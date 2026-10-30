"""Original two-lane emergency disable; no app/source/config/data body reads."""

import json
import os
import re
import subprocess
import sys


class InboxControlError(RuntimeError):
    pass


def native_run(argv):
    try:
        return subprocess.run(argv, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise InboxControlError("inbox_emergency_tool_unavailable") from None


def is_disabled(body, label):
    pattern = rb'(?m)^\s*"' + re.escape(label.encode()) + rb'"\s*=>\s*(?:true|disabled)\s*$'
    return re.search(pattern, body) is not None


def execute(data, *, run=None):
    if (
        data["service"] != "inbox"
        or data["action"] != "disable"
        or type(data["uid"]) is not int
        or data["uid"] <= 0
        or os.geteuid() != 0
        or not data["label"]
        or not data["long_label"]
        or data["label"] == data["long_label"]
    ):
        raise InboxControlError("inbox_emergency_request_invalid")
    probe = run or native_run
    domain = "gui/" + str(data["uid"])
    labels = (data["label"], data["long_label"])

    def command(*args):
        return probe(["/bin/launchctl", *args])

    if command("print", domain).returncode != 0:
        raise InboxControlError("inbox_emergency_GUI_domain_unavailable")
    before = command("print-disabled", domain)
    if before.returncode != 0:
        raise InboxControlError("inbox_emergency_prestate_unavailable")
    loaded = [command("print", domain + "/" + label).returncode == 0 for label in labels]
    previous = all(is_disabled(before.stdout, label) and not active for label, active in zip(labels, loaded))
    # Original failed_when:false loops: persist BOTH overrides before either
    # bootout; mutation failures do not skip the remaining lane or final proof.
    for action in ("disable", "bootout"):
        for label in labels:
            try:
                command(action, domain + "/" + label)
            except InboxControlError:
                pass
    disabled = command("print-disabled", domain)
    live_domain = command("print", domain)
    after = [command("print", domain + "/" + label) for label in labels]
    if disabled.returncode != 0 or any(not is_disabled(disabled.stdout, label) for label in labels):
        raise InboxControlError("inbox_emergency_disable_not_proven")
    if live_domain.returncode != 0 or any(
        result.returncode != 113 or b"Could not find service" not in (result.stdout + result.stderr)
        for result in after
    ):
        raise InboxControlError("inbox_emergency_unloaded_not_proven")
    return {"schema_version": 1, "both_disabled_unloaded": True, "previously_disabled_unloaded": previous}


def main():
    try:
        result = execute(json.load(sys.stdin))
    except Exception:
        print('{"schema_version":1,"status":"failed","reason":"inbox_emergency_failed"}', file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
