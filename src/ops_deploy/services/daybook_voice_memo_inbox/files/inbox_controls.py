"""Original Inbox keeper/serve guards. No application, Journal or data reads.

These guards precede managed quiescence and source replacement. They apply to
this protected Inbox interpreter, never unrelated Sessions/Photos checkouts.
"""

import re
import subprocess
import time


class InboxError(RuntimeError):
    pass


class NativeControls:
    def sleep(self, seconds):
        time.sleep(seconds)

    def run(self, argv):
        try:
            return subprocess.run(argv, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise InboxError("inbox_control_probe_unavailable") from None


def label_state(data, probes, label):
    domain = "gui/" + str(data["uid"])
    result = probes.run(["/bin/launchctl", "print", domain + "/" + label])
    if result.returncode == 0:
        return True, result
    diagnostic = (result.stdout or b"") + (getattr(result, "stderr", b"") or b"")
    if result.returncode == 113 and ('Could not find service "' + label + '"').encode() in diagnostic:
        return False, result
    raise InboxError("inbox_control_probe_failed")


def require_runtime_stopped(data, probes):
    # Mirror original role's argument-line test without logging launchctl output
    # (which can contain environment). A legacy ingest label can still be loaded
    # here; the following explicit managed quiescence retires it. The operations
    # keeper must already have been stopped by the normal runtime update fanout.
    domain = "gui/" + str(data["uid"])
    aqua = probes.run(["/bin/launchctl", "print", domain])
    if aqua.returncode:
        raise InboxError("inbox_aqua_unavailable")
    keeper_loaded, keeper = label_state(data, probes, data["label"])
    serving = probes.run(["/usr/bin/pgrep", "-u", data["user"], "-f", "[o]perations serve"])
    if serving.returncode not in {0, 1}:
        raise InboxError("inbox_control_probe_failed")
    if (keeper_loaded and re.search(rb"(?m)^\s*(serve|host-keep)\s*$", keeper.stdout)) or serving.returncode == 0:
        raise InboxError("inbox_operations_runtime_still_running")


def require_inbox_quiescent(data, probes):
    require_runtime_stopped(data, probes)
    domain = "gui/" + str(data["uid"])
    disabled = probes.run(["/bin/launchctl", "print-disabled", domain])
    if disabled.returncode:
        raise InboxError("inbox_disabled_labels_unavailable")
    for label in (data["label"], data["long_label"]):
        match = re.findall(rb'"' + re.escape(label.encode()) + rb'"\s*=>\s*(true|false|disabled|enabled)\b', disabled.stdout)
        if match not in ([b"true"], [b"disabled"]):
            raise InboxError("inbox_label_not_disabled")
        loaded, _ = label_state(data, probes, label)
        if loaded:
            raise InboxError("inbox_label_not_quiescent")


def quiesce_inbox(data, probes):
    """Explicit managed disable/bootout of the original two labels only."""
    require_runtime_stopped(data, probes)  # No mutation while an operations keeper exists.
    domain = "gui/" + str(data["uid"])
    disabled = probes.run(["/bin/launchctl", "print-disabled", domain])
    if disabled.returncode:
        raise InboxError("inbox_disabled_labels_unavailable")
    states = []
    for label in (data["label"], data["long_label"]):
        loaded, _ = label_state(data, probes, label)
        values = re.findall(rb'"' + re.escape(label.encode()) + rb'"\s*=>\s*(true|false|disabled|enabled)\b', disabled.stdout)
        if len(values) > 1:
            raise InboxError("inbox_disabled_label_ambiguous")
        states.append((label, loaded, values in ([b"true"], [b"disabled"])))
    changed = False
    for label, loaded, is_disabled in states:
        if not is_disabled:
            if probes.run(["/bin/launchctl", "disable", domain + "/" + label]).returncode:
                raise InboxError("inbox_disable_failed")
            changed = True
    # Original order: persistently disable BOTH lanes before either bootout.
    for label, loaded, _ in states:
        if loaded:
            if probes.run(["/bin/launchctl", "bootout", domain + "/" + label]).returncode:
                raise InboxError("inbox_bootout_failed")
            changed = True
    # Original launchd termination window: 12 observations, five seconds apart.
    # No transcription completion wait, retry of failed mutations or broad PID matching.
    for label in (data["label"], data["long_label"]):
        for attempt in range(12):
            loaded, _ = label_state(data, probes, label)
            if not loaded:
                break
            if attempt == 11:
                raise InboxError("inbox_label_not_quiescent")
            probes.sleep(5)
    require_inbox_quiescent(data, probes)
    return changed
