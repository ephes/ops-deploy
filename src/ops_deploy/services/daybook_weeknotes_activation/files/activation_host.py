"""Fresh identity verification remains in this protected target process."""

import json
import re
import subprocess
import sys

import ops_weeknotes_identity as identity

PHRASE = "ENABLE monday-after-v1 draft schedule"


class ActivationError(RuntimeError):
    pass


def launch(data, *argv):
    try:
        return subprocess.run([data["activation"]["launchctl_bin"], *argv], capture_output=True,
                              stdin=subprocess.DEVNULL, cwd="/")
    except OSError:
        raise ActivationError("weeknotes_activation_command_unavailable") from None


def disabled(data, result):
    if result.returncode:
        raise ActivationError("weeknotes_activation_state_unavailable")
    label = re.escape(data["scheduler_label"])
    return re.search(r'(?m)^\s*"' + label + r'"\s*=>\s*(?:true|disabled)\s*$', result.stdout.decode("utf-8")) is not None


def activate(data, verified, *, control=None):
    run = control or launch
    activation = data["activation"]
    # Keep original artifact owners/modes and private epoch/proof comparisons.
    for path, uid, mode in (
        (data["env_file"], data["uid"], 0o600),
        (data["proof"], 0, 0o600),
        (data["env_checksum"], 0, 0o644),
        (activation["reconcile_launcher"], 0, 0o755),
        (data["scheduler_plist"], 0, 0o644),
    ):
        identity.read_control(path, uid, mode)
    env = identity.read_control(data["env_file"], data["uid"], 0o600)
    proof = identity.strict_json(identity.read_control(data["proof"], 0, 0o600))
    expected = {"schema_version": 1, "identity_epoch": "monday-after-v1",
                "plan_hash": verified["plan_hash"], "daybook_repo_ref": data["required_revision"]}
    if b"DAYBOOK_WEEKNOTES_POST_IDENTITY_EPOCH=monday-after-v1" not in env.splitlines() or proof != expected:
        raise ActivationError("weeknotes_activation_epoch_or_fresh_proof_mismatch")
    service = "system/" + data["scheduler_label"]
    current = run(data, "print", service).returncode
    if current not in {0, 113}:
        raise ActivationError("weeknotes_activation_state_unavailable")
    if current == 0 or not disabled(data, run(data, "print-disabled", "system")):
        raise ActivationError("weeknotes_activation_requires_disabled_unloaded")
    if run(data, "enable", service).returncode:
        raise ActivationError("weeknotes_activation_enable_failed")
    try:
        bootstrapped = run(data, "bootstrap", "system", data["scheduler_plist"]).returncode == 0
    except Exception:
        raise ActivationError("weeknotes_activation_enabled_bootstrap_failed") from None
    if not bootstrapped:
        raise ActivationError("weeknotes_activation_enabled_bootstrap_failed")
    try:
        verified_state = run(data, "print", service).returncode == 0 and not disabled(data, run(data, "print-disabled", "system"))
    except Exception:
        raise ActivationError("weeknotes_activation_loaded_verification_failed") from None
    if not verified_state:
        raise ActivationError("weeknotes_activation_loaded_verification_failed")


def execute(data, *, runner=None, control=None):
    cfg = data["activation"]
    if cfg["retired"] is not False or cfg["confirmation"] != PHRASE or data["action"] != "apply":
        raise ActivationError("weeknotes_activation_request_refused")
    return identity.execute(data, run=runner, after_verified=lambda request, verified: activate(request, verified, control=control))


def main():
    try:
        raw = sys.stdin.buffer.read(identity.MAX_PRIVATE + 1)
        if len(raw) > identity.MAX_PRIVATE:
            raise ActivationError("weeknotes_activation_request_oversize")
        execute(identity.strict_json(raw))
    except ActivationError as error:
        # Only these packaged fixed categories reach stderr, never app output.
        reason = str(error)
        print(json.dumps({"schema_version": 1, "status": "failed", "reason_code": reason}), file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print('{"schema_version":1,"status":"failed","reason_code":"weeknotes_activation_before_enable_failed"}', file=sys.stderr)
        raise SystemExit(1) from None
    print('{"schema_version":1,"status":"activated","fresh_apply_verified":true}')


if __name__ == "__main__":
    main()
