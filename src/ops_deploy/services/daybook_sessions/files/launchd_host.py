"""Exact original Sessions timer controls; no process enumeration or app calls."""

import re
import subprocess

from ops_sessions_resources import ResourceError, remove_declared_file


class Launchd:
    def __init__(self, domain):
        self.domain = domain

    def command(self, *args):
        try:
            return subprocess.run(["/bin/launchctl", *args], capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise ResourceError("sessions_launchd_unavailable") from None

    def state(self, label):
        checked = self.command("print", self.domain + "/" + label)
        if checked.returncode not in {0, 113}:
            raise ResourceError("sessions_launchd_unavailable")
        listing = checked.stdout.decode("utf-8", "replace")
        disabled = self.command("print-disabled", self.domain)
        if disabled.returncode:
            raise ResourceError("sessions_launchd_disabled_unavailable")
        rows = re.findall(r'"' + re.escape(label) + r'"\s*=>\s*(true|false|disabled|enabled)\b',
                          disabled.stdout.decode("utf-8", "replace"))
        if len(rows) > 1:
            raise ResourceError("sessions_launchd_disabled_ambiguous")
        return {"loaded": checked.returncode == 0, "disabled": rows in (["true"], ["disabled"]),
                "running": bool(re.search(r"\bstate\s*=\s*(running|spawning)\b", listing))}

    def mutate(self, *args):
        if self.command(*args).returncode:
            raise ResourceError("sessions_launchd_mutation_failed")

    def require_quiet(self, label):
        state = self.state(label)
        if state["running"]:
            raise ResourceError("sessions_timer_in_flight")
        return state

    def retire(self, label, plist):
        state = self.require_quiet(label)
        if state["loaded"]:
            self.mutate("bootout", self.domain + "/" + label)
        if not state["disabled"]:
            self.mutate("disable", self.domain + "/" + label)
        remove_declared_file(plist)
        final = self.state(label)
        if final["loaded"] or not final["disabled"]:
            raise ResourceError("sessions_timer_retirement_failed")

    def enable(self, label, plist, *, changed, restart=False):
        state = self.state(label)
        if changed and state["loaded"]:
            self.mutate("bootout", self.domain, plist)
        if state["disabled"]:
            self.mutate("enable", self.domain + "/" + label)
        if changed or not state["loaded"]:
            self.mutate("bootstrap", self.domain, plist)
        # Sessions/classifier retain their explicit original start/run-at-load
        # flags. Weeknotes ordinary installation never selects this branch.
        if restart:
            self.mutate("kickstart", "-k", self.domain + "/" + label)
        final = self.state(label)
        if not final["loaded"] or final["disabled"]:
            raise ResourceError("sessions_timer_enable_failed")


def require_reconcile_quiescence(cfg):
    if cfg["daybook_sessions_launchd_scope"] != "system" or not cfg["daybook_sessions_launchd_manage_state"]:
        return
    label = "de.wersdoerfer.daybook.weeknotes-reconcile"
    if (cfg["daybook_weeknotes_reconcile_launchd_label"] != label
            or cfg["daybook_weeknotes_reconcile_launchd_plist_path"]
            != "/Library/LaunchDaemons/" + label + ".plist"):
        raise ResourceError("sessions_reconcile_identity_invalid")
    current = Launchd("system").state(label)
    if current["loaded"] or not current["disabled"]:
        raise ResourceError("sessions_reconcile_quiescence_required")


def quiesce_reconcile(cfg):
    """Original early managed boundary, separately before source/config changes."""
    if cfg["daybook_sessions_launchd_scope"] != "system" or not cfg["daybook_sessions_launchd_manage_state"]:
        return
    label = "de.wersdoerfer.daybook.weeknotes-reconcile"
    plist = "/Library/LaunchDaemons/" + label + ".plist"
    if (cfg["daybook_weeknotes_reconcile_launchd_label"] != label
            or cfg["daybook_weeknotes_reconcile_launchd_plist_path"] != plist):
        raise ResourceError("sessions_reconcile_identity_invalid")
    controller = Launchd("system")
    state = controller.state(label)
    if not state["disabled"]:
        controller.mutate("disable", "system/" + label)
    if state["loaded"]:
        controller.mutate("bootout", "system/" + label)
    require_reconcile_quiescence(cfg)
