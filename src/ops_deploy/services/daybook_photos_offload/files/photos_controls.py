"""Original exact-label Photos quiescence and optional activation.

Only selected launchd metadata leaves this helper. No Photos library, ledger,
application, source interpreter or unrelated launchd label is invoked here.
"""

import contextlib
import re
import subprocess


class PhotosControlError(RuntimeError):
    pass


class PhotosControls:
    def __init__(self, data, run=None):
        if type(data["uid"]) is not int or data["uid"] <= 0 or not data["label"]:
            raise PhotosControlError("photos_control_identity_invalid")
        self.data = data
        self.domain = "gui/" + str(data["uid"])
        self.service = self.domain + "/" + data["label"]
        self.run = run or self.native_run

    def native_run(self, argv):
        try:
            return subprocess.run(
                argv, capture_output=True, timeout=30 if argv[1] in {"print", "print-disabled"} else None
            )
        except (OSError, subprocess.TimeoutExpired):
            raise PhotosControlError("photos_control_tool_unavailable") from None

    def command(self, *argv):
        return self.run(["/bin/launchctl", *argv])

    def snapshot(self, *, final=False):
        # Original post-state reads disabled, domain, label in that order; the
        # exact service absence/load check remains the final observation.
        if final:
            disabled = self.command("print-disabled", self.domain)
            domain = self.command("print", self.domain)
            loaded = self.command("print", self.service)
        else:
            domain = self.command("print", self.domain)
            loaded = self.command("print", self.service)
            disabled = self.command("print-disabled", self.domain)
        text = disabled.stdout.decode("utf-8", "replace")
        absent = 'Could not find service "' + self.data["label"] + '" in domain for user gui: ' + str(self.data["uid"])
        known_absent = loaded.returncode == 113 and absent in loaded.stderr.decode("utf-8", "replace")
        pid = re.search(rb"(?m)^\s*pid = ([1-9][0-9]*)\s*$", loaded.stdout) if loaded.returncode == 0 else None
        return {
            "domain_available": domain.returncode == 0,
            "loaded": True if loaded.returncode == 0 else False if known_absent else None,
            "known_absent": known_absent,
            "pid": int(pid[1]) if pid else None,
            "disabled": (
                ('"' + self.data["label"] + '" => disabled') in text or ('"' + self.data["label"] + '" => true') in text
            )
            if disabled.returncode == 0
            else None,
        }

    def require_quiescent(self):
        state = self.snapshot(final=True)
        if (
            not state["domain_available"]
            or state["disabled"] is not True
            or state["loaded"] is not False
            or not state["known_absent"]
        ):
            raise PhotosControlError("photos_control_not_disabled_unloaded")
        return state

    def attempt(self, *argv):
        try:
            return self.command(*argv).returncode == 0
        except PhotosControlError:
            # Original failed_when:false operations still attempt the second
            # exact-label cleanup and require the real final state afterwards.
            return False

    def quiesce(self, *, force=False):
        initial = {"disabled": None}
        if not force:
            # Unknown pre-state cannot skip either cleanup attempt.
            with contextlib.suppress(PhotosControlError):
                initial = self.snapshot()
        changed = False
        if force or initial["disabled"] is not True:
            changed = self.attempt("disable", self.service)
        # Original bootout is unconditional, including an already absent label.
        changed = self.attempt("bootout", self.service) or changed
        self.require_quiescent()
        return {"changed": changed}

    def activate(self):
        try:
            if not self.attempt("enable", self.service):
                raise PhotosControlError("photos_control_enable_failed")
            if not self.attempt("bootstrap", self.domain, self.data["plist"]):
                raise PhotosControlError("photos_control_bootstrap_failed")
            final = self.snapshot(final=True)
            if not final["domain_available"] or final["disabled"] is not False or final["loaded"] is not True:
                raise PhotosControlError("photos_control_activation_not_current")
            return {"activated": True}
        except PhotosControlError:
            # Exact original rescue tries BOTH disable and bootout, then proves
            # disabled/unloaded. Never turn failed activation into success.
            try:
                self.quiesce(force=True)
            except PhotosControlError:
                raise PhotosControlError("photos_control_activation_failed_NOT_quiesced") from None
            raise PhotosControlError("photos_control_activation_failed_quiesced") from None
