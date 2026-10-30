"""Explicit original operator; private outputs/body comparisons stay in RAM."""

import hashlib
import hmac
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import sys
import uuid

from ops_identity_filesystem import directory_fd, put_bytes, resource_path

MAX_PRIVATE = 1024 * 1024
PHRASE = "APPLY monday-after-v1 draft identity migration"
HEX = re.compile(r"[0-9a-f]{64}")
WEEK = re.compile(r"[0-9]{4}-W[0-9]{2}")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")


class OperatorError(RuntimeError):
    pass


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise OperatorError("identity_duplicate_json_key")
        value[key] = item
    return value


def strict_json(raw):
    def invalid(_value):
        raise OperatorError("identity_nonfinite_json")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read_control(name, uid, mode, *, limit=MAX_PRIVATE, missing=False):
    path = resource_path(name)
    try:
        with directory_fd(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        if missing:
            return None
        raise OperatorError("identity_control_missing") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != mode or info.st_size > limit):
            raise OperatorError("identity_control_unsafe")
        body, left = [], limit + 1
        while left:
            part = os.read(fd, min(left, 65536))
            if not part:
                break
            body.append(part)
            left -= len(part)
        result = b"".join(body)
        if len(result) > limit:
            raise OperatorError("identity_control_oversize")
        return result
    finally:
        os.close(fd)


def owner_run(data, argv):
    # Original noninteractive service-user login context. No secret value or
    # structured payload enters argv or an explicit switched environment.
    target = ["/usr/bin/sudo", "-H", "-S", "-n", "-i", "-u", data["owner"], "--", *argv]
    try:
        return subprocess.run(target, capture_output=True, cwd="/", stdin=subprocess.DEVNULL)
    except OSError:
        raise OperatorError("identity_owner_command_unavailable") from None


def require_checkout(data, run):
    checkout = resource_path(data["checkout"])
    for name in (checkout, checkout / ".git"):
        with directory_fd(name.parent) as parent:
            info = os.stat(name.name, dir_fd=parent, follow_symlinks=False)
        allowed = stat.S_ISDIR(info.st_mode) or (name.name == ".git" and stat.S_ISREG(info.st_mode))
        if not allowed or stat.S_ISLNK(info.st_mode) or info.st_uid != data["uid"]:
            raise OperatorError("identity_checkout_metadata_invalid")
    for args, expected in (
        (("rev-parse", "HEAD"), data["required_revision"]),
        (("rev-parse", "--show-toplevel"), data["checkout"]),
        (("status", "--porcelain=v1", "--untracked-files=all"), ""),
    ):
        result = run(data, ["/usr/bin/git", "-C", data["checkout"], *args])
        if result.returncode or result.stdout.decode("utf-8").strip() != expected:
            raise OperatorError("identity_checkout_not_exact_clean_Main")


def require_rail(data):
    for key in ("helper", "launcher"):
        expected = data["expected_code"][key]
        body = read_control(data[key], 0, 0o755, limit=expected["size"])
        if len(body) != expected["size"] or not hmac.compare_digest(hashlib.sha256(body).hexdigest(), expected["sha256"]):
            raise OperatorError("identity_installed_rail_mismatch")
    env = read_control(data["env_file"], data["uid"], 0o600)
    checksum = read_control(data["env_checksum"], 0, 0o644)
    parts = checksum.decode("utf-8").strip().split(maxsplit=1)
    if (len(parts) != 2 or not HEX.fullmatch(parts[0]) or parts[1] != data["env_file"]
            or not hmac.compare_digest(hashlib.sha256(env).hexdigest(), parts[0])):
        raise OperatorError("identity_installed_environment_mismatch")


def seed_intent(data):
    return {"schema_version": 1, "identity_epoch": "monday-after-v1", "moves": data["moves"]}


def preserve_seed(data):
    if data["action"] == "status":
        return False
    if not isinstance(data["moves"], list) or not data["moves"]:
        raise OperatorError("identity_private_intent_required")
    runtime = resource_path(data["runtime"])
    with directory_fd(runtime) as parent:
        info = os.fstat(parent)
        if info.st_uid != data["uid"] or stat.S_IMODE(info.st_mode) != 0o700:
            raise OperatorError("identity_runtime_unsafe")
    intended = seed_intent(data)
    before = read_control(data["seed"], data["uid"], 0o600, missing=True)
    if before is None and data["action"] == "prepare":
        put_bytes({"path": data["seed"], "owner": data["owner"], "group": "staff", "mode": 0o600},
                  json.dumps(intended, indent=4, sort_keys=True).encode(), replace=False)
    current = read_control(data["seed"], data["uid"], 0o600)
    if strict_json(current) != intended:
        raise OperatorError("identity_private_intent_mismatch")
    return None


def positive(value, *, optional=False):
    return (optional and value is None) or (type(value) is int and value > 0)


def metadata_value(key, value, week, audience):
    if key.endswith("_hash"):
        return isinstance(value, str) and HEX.fullmatch(value) is not None
    if key == "attempt_id":
        try:
            return str(uuid.UUID(value)) == value
        except (ValueError, TypeError, AttributeError):
            return False
    if key == "quote_assignment_id":
        return value is None or (isinstance(value, str) and re.fullmatch(
            r"daybook:" + re.escape(week) + r":archive:[1-9][0-9]*:[0-9a-f]{32}", value) is not None)
    if key == "steering_ids":
        return isinstance(value, list) and len(value) <= 10000 and all(positive(v) for v in value) and len(set(value)) == len(value)
    if key.endswith("_id"):
        return positive(value, optional=True)
    if key.endswith("_at"):
        return value is None or (isinstance(value, str) and STAMP.fullmatch(value) is not None)
    if key == "week":
        return value == week
    if key == "audience":
        return value == audience
    if key == "reason_code":
        return value is None or (isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]*", value) is not None)
    if key == "status":
        return value in {"running", "fenced", "delivery_intent", "post_cast", "succeeded", "failed", "stale", "superseded"}
    if key == "cast_action":
        return value in {"created", "updated", "unchanged"}
    return False


def status_report(value):
    if not isinstance(value, dict) or set(value) != {"schema_version", "weeks"} or type(value["schema_version"]) is not int or value["schema_version"] != 2:
        raise OperatorError("identity_status_shape_invalid")
    fields = {
        "attempt": {"attempt_id", "week", "audience", "source_hash", "authoring_input_hash", "base_cast_post_id", "base_revision_id", "started_at", "finished_at", "status", "reason_code"},
        "delivery_intent": {"attempt_id", "authored_owned_fields_hash", "expected_cast_post_id", "expected_cast_revision_id", "quote_assignment_id", "steering_ids", "resource_identity_hash", "intended_at"},
        "checkpoint": {"attempt_id", "authored_owned_fields_hash", "cast_post_id", "cast_revision_id", "cast_action", "quote_assignment_id", "steering_ids", "resource_identity_hash", "checkpointed_at"},
        "delivery": {"source_hash", "authoring_input_hash", "cast_post_id", "cast_revision_id", "delivered_at"},
    }
    if not isinstance(value["weeks"], dict):
        raise OperatorError("identity_status_shape_invalid")
    for week, audiences in value["weeks"].items():
        if not WEEK.fullmatch(week) or not isinstance(audiences, dict) or set(audiences) != {"public", "family"}:
            raise OperatorError("identity_status_shape_invalid")
        for audience, record in audiences.items():
            if not isinstance(record, dict) or set(record) != set(fields):
                raise OperatorError("identity_status_shape_invalid")
            for key, payload in record.items():
                if payload is None:
                    continue
                allowed = [fields[key]]
                if key == "checkpoint":
                    allowed.append(fields[key] | {"cast_owned_fields_hash"})
                if (not isinstance(payload, dict) or set(payload) not in allowed
                        or not all(metadata_value(k, v, week, audience) for k, v in payload.items())):
                    raise OperatorError("identity_status_shape_invalid")
    return value


def action_report(action, value):
    if action == "status":
        return status_report(value)
    if action in {"prepare", "verify"}:
        expected = {"plan_prepared", "existing_plan_reused"} if action == "prepare" else {"attestation_verified"}
        if (not isinstance(value, dict) or set(value) != {"schema_version", "status", "plan_hash"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["status"] not in expected or not isinstance(value["plan_hash"], str)
                or not HEX.fullmatch(value["plan_hash"])):
            raise OperatorError("identity_report_invalid")
        # The plan hash stays only in remote memory/the original root proof.
        return {"schema_version": 1, "status": value["status"]}
    expected = {"schema_version", "identity_epoch", "plan_hash", "dry_run", "applied", "status", "reason_code", "moves"}
    apply = action == "apply"
    if (not isinstance(value, dict) or set(value) != expected or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["identity_epoch"] != "monday-after-v1" or value["dry_run"] is not (not apply) or value["applied"] is not apply
            or value["status"] != ("applied" if apply else "dry_run_validated") or value["reason_code"] is not None
            or not isinstance(value["plan_hash"], str) or not HEX.fullmatch(value["plan_hash"])
            or not isinstance(value["moves"], list) or not value["moves"]):
        raise OperatorError("identity_report_invalid")
    move_fields = {"week", "audience", "blog_id", "post_id", "from_or_already_target", "result", "new_revision_id", "reason_code"}
    for move in value["moves"]:
        if (not isinstance(move, dict) or set(move) != move_fields or not isinstance(move["week"], str) or not WEEK.fullmatch(move["week"])
                or move["audience"] not in {"public", "family"} or not positive(move["blog_id"]) or not positive(move["post_id"])
                or move["from_or_already_target"] not in {"from", "to", "target", "already_target"}
                or move["result"] not in ({"moved", "already_target"} if apply else {"would_move", "already_target"})
                or not positive(move["new_revision_id"], optional=not apply) or move["reason_code"] is not None):
            raise OperatorError("identity_report_invalid")
    return {key: item for key, item in value.items() if key != "plan_hash"}


def invoke(data, run, action):
    result = run(data, [data["launcher"], action])
    if result.returncode or len(result.stdout) > MAX_PRIVATE:
        raise OperatorError("identity_launcher_failed")
    value = strict_json(result.stdout)
    return value, action_report(action, value)


def execute(data, *, run=None):
    if (os.geteuid() != 0 or type(data["uid"]) is not int or data["uid"] <= 0
            or pwd.getpwnam(data["owner"]).pw_uid != data["uid"]
            or data["action"] not in {"prepare", "dry-run", "apply", "verify", "status"}
            or (data["action"] == "apply" and data["confirmation"] != PHRASE)):
        raise OperatorError("identity_request_invalid")
    runner = run or owner_run
    require_checkout(data, runner)
    require_rail(data)
    preserve_seed(data)
    raw, report = invoke(data, runner, data["action"])
    proof_written = False
    if data["action"] == "apply":
        verified, _summary = invoke(data, runner, "verify")
        if not hmac.compare_digest(raw["plan_hash"], verified["plan_hash"]):
            raise OperatorError("identity_apply_verify_plan_mismatch")
        body = json.dumps({"schema_version": 1, "identity_epoch": "monday-after-v1", "plan_hash": verified["plan_hash"],
                           "daybook_repo_ref": data["required_revision"]}, indent=4, sort_keys=True).encode()
        before = read_control(data["proof"], 0, 0o600, missing=True)
        if before != body:
            put_bytes({"path": data["proof"], "owner": "root", "group": "wheel", "mode": 0o600}, body)
            proof_written = True
    return {"schema_version": 1, "action": data["action"], "seed_checked": data["action"] != "status", "proof_written": proof_written, "report": report}


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_PRIVATE + 1)
        if len(raw) > MAX_PRIVATE:
            raise OperatorError("identity_request_oversize")
        result = execute(strict_json(raw))
    except Exception:
        print('{"schema_version":1,"status":"failed","reason_code":"identity_operator_failed"}', file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
