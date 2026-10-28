"""Host-local MinIO CLI boundary; no credentials or CLI output leave this process.

The deployed client emits JSON lines, sometimes two errors for one failed stat.
Return codes alone are insufficient: admin info can report status=error with rc0.
Only recognized S3 authentication responses can decide whether a secret matches.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path


class Refused(RuntimeError):
    """A constant, non-sensitive diagnostic safe to return to the controller."""


def protected_text(path, mode):
    """Read a declared root-owned regular file without following a symlink."""
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "r") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
                raise Refused("existing MinIO configuration has foreign ownership or type")
            if stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1 or info.st_size > 65536:
                raise Refused("existing MinIO configuration has unsafe metadata")
            return source.read()
    except OSError:
        raise Refused("existing MinIO configuration is unavailable") from None


def environment_values(text):
    """Parse our literal EnvironmentFile grammar; never execute shell content."""
    values = {}
    allowed = {"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD", "MINIO_VOLUMES", "MINIO_OPTS", "MINIO_KMS_SECRET_KEY"}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r'([A-Z_]+)="([^"\\\r\n\x00]*)"', line)
        if not match or match[1] not in allowed or match[1] in values:
            raise Refused("existing MinIO environment is ambiguous or unsupported")
        values[match[1]] = match[2]
    if not {"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD", "MINIO_VOLUMES", "MINIO_OPTS"} <= values.keys():
        raise Refused("existing MinIO environment is incomplete")
    if not values["MINIO_ROOT_USER"] or not values["MINIO_ROOT_PASSWORD"]:
        raise Refused("existing MinIO root credentials are empty")
    return values


def current_credentials(payload):
    values = environment_values(protected_text(payload["recovery"]["env_file"], 0o600))
    return values["MINIO_ROOT_USER"], values["MINIO_ROOT_PASSWORD"]


def recovery_state(payload):
    """Recognize only pinned-client absence/drift and a known inactive unit."""
    import hashlib

    context = payload["recovery"]
    current = environment_values(protected_text(context["env_file"], 0o600))
    result = subprocess.run(
        ["systemctl", "show", "minio.service", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
         "-p", "FragmentPath", "-p", "DropInPaths", "-p", "NeedDaemonReload"], capture_output=True, text=True, timeout=30,
    )
    if result.returncode or result.stderr:
        raise Refused("MinIO service state is unavailable")
    pairs = [line.split("=", 1) for line in result.stdout.splitlines()]
    if any(len(pair) != 2 for pair in pairs) or len({pair[0] for pair in pairs}) != len(pairs):
        raise Refused("MinIO service state is malformed")
    service = dict(pairs)
    if set(service) != {"LoadState", "ActiveState", "SubState", "FragmentPath", "DropInPaths", "NeedDaemonReload"}:
        raise Refused("MinIO service state is incomplete")
    if service["LoadState"] != "loaded" or service["FragmentPath"] != context["service_unit"] or service["DropInPaths"]:
        raise Refused("MinIO service identity is unknown")
    state = service["ActiveState"], service["SubState"]
    if state not in (("active", "running"), ("inactive", "dead"), ("failed", "failed")):
        raise Refused("MinIO service is in an unknown or transitional state")
    recover_service = state != ("active", "running")
    if recover_service:
        if service["NeedDaemonReload"] != "no":
            raise Refused("inactive MinIO loaded unit differs from its on-disk configuration")
        if protected_text(context["service_unit"], 0o644) != context["unit"]:
            raise Refused("inactive MinIO unit is not the declared owned unit")
        desired = environment_values(context["environment"])
        root_fields = {"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"}
        if {key: value for key, value in current.items() if key not in root_fields} != {
            key: value for key, value in desired.items() if key not in root_fields
        }:
            raise Refused("inactive MinIO has unknown non-root configuration")
        binary = Path(context["bin_path"])
        info = binary.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o755
                or hashlib.sha256(binary.read_bytes()).hexdigest() != context["minio_sha256"]):
            raise Refused("inactive MinIO executable is not pinned")
    client = Path(payload["mc"])
    if client.is_symlink():
        raise Refused("MinIO client path is a symlink")
    recover_client = not client.exists()
    if not recover_client:
        info = client.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise Refused("MinIO client path is not a regular executable")
        recover_client = (info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o755
                          or hashlib.sha256(client.read_bytes()).hexdigest() != context["mc_sha256"])
    return {"recover_client": recover_client, "recover_service": recover_service}


def normalized(policy):
    """Same narrow canonicalization as the legacy minio_policy filter."""
    if not isinstance(policy, dict):
        return policy
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        return dict(policy)
    result = []
    for statement in statements:
        if isinstance(statement, dict):
            statement = dict(statement)
            for field in ("Action", "NotAction", "Resource", "NotResource"):
                value = statement.get(field)
                if isinstance(value, str):
                    value = [value]
                if isinstance(value, list) and all(isinstance(item, str) for item in value):
                    statement[field] = sorted(set(value))
        result.append(statement)
    result.sort(key=lambda value: json.dumps(value, sort_keys=True))
    return {**policy, "Statement": result}


class Reply:
    def __init__(self, code, stdout, stderr):
        self.code = code
        # Unexpected stderr is not silently discarded even if stdout looks valid.
        if stderr.strip():
            raise Refused("client returned unexpected diagnostics")
        try:
            self.rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        except (ValueError, TypeError):
            raise Refused("client returned malformed JSON") from None
        if not self.rows or any(not isinstance(row, dict) for row in self.rows):
            raise Refused("client returned an empty or invalid result")
        if any(row.get("status") not in ("success", "error") for row in self.rows):
            raise Refused("client returned an unknown status")

    @property
    def successful(self):
        return self.code == 0 and all(row["status"] == "success" for row in self.rows)

    def one(self):
        if not self.successful or len(self.rows) != 1:
            raise Refused("client request did not return one successful result")
        return self.rows[0]

    @staticmethod
    def error_code(row):
        error = row.get("error")
        if not isinstance(error, dict):
            return None
        cause = error.get("cause")
        if not isinstance(cause, dict) or not isinstance(cause.get("error"), dict):
            return None
        code = cause["error"].get("Code")
        return code if isinstance(code, str) and code else None

    def absent(self, expected_code):
        """Only a single exact server error proves a missing user or policy."""
        return (
            self.code != 0
            and len(self.rows) == 1
            and self.rows[0]["status"] == "error"
            and self.error_code(self.rows[0]) == expected_code
        )

    def credential_matches(self):
        if self.successful:
            return True
        if self.code == 0 or any(row["status"] != "error" for row in self.rows):
            raise Refused("credential probe returned contradictory status")
        codes = []
        for index, row in enumerate(self.rows):
            code = self.error_code(row)
            if code is not None:
                codes.append(code)
                continue
            # This exact client's stat emits a secondary local fatal error after
            # the recognized S3 response. It is not itself authentication proof.
            error = row.get("error", {})
            secondary = (
                index == 1 and len(self.rows) == 2 and codes and isinstance(error, dict)
                and error.get("type") == "fatal"
                and error.get("cause") == {"message": "Object does not exist", "error": {}}
            )
            if not secondary:
                raise Refused("credential proof failed: transport or unknown response")
        if not codes:
            raise Refused("credential proof has no authenticated server response")
        valid = {"AccessDenied", "NoSuchKey", "NoSuchBucket"}
        invalid = {"SignatureDoesNotMatch", "InvalidAccessKeyId"}
        if set(codes) <= valid:
            return True
        if set(codes) <= invalid:
            return False
        raise Refused("credential proof returned conflicting or unrecognized errors")


class Client:
    def __init__(self, executable, config_dir):
        self.executable = executable
        self.config_dir = str(config_dir)

    def call(self, *args, stdin=None):
        try:
            result = subprocess.run(
                [*self.executable, "--json", "--config-dir", self.config_dir, *args],
                input=stdin, text=True, capture_output=True, timeout=45,
                env={key: value for key, value in os.environ.items() if not key.startswith("MC_")},
            )
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("client could not execute or timed out") from None
        return Reply(result.returncode, result.stdout, result.stderr)

    def import_alias(self, alias, value):
        self.call("alias", "import", alias, stdin=json.dumps(value)).one()

    def prove_secret(self, endpoint, access, secret, target):
        # The private config is disposable, never a rewrite of root's shared mc.
        with tempfile.TemporaryDirectory(prefix="ops-minio-proof-") as directory:
            proof = Client(self.executable, directory)
            proof.import_alias("proof", alias_document(endpoint, access, secret))
            return proof.call("stat", "proof/" + target).credential_matches()


def alias_document(endpoint, access, secret):
    return {"url": endpoint, "accessKey": access, "secretKey": secret, "api": "s3v4", "path": "auto"}


def alias_current(config_dir, alias, expected):
    """Compare only the owned alias on the host, never return config or hashes."""
    path = Path(config_dir) / "config.json"
    if not path.exists():
        return False
    try:
        config = json.loads(path.read_text())
        aliases = config["aliases"]
        if not isinstance(aliases, dict):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise Refused("shared client configuration is unreadable or malformed") from None
    value = aliases.get(alias)
    if value is None:
        return False
    if not isinstance(value, dict):
        raise Refused("owned client alias is malformed")
    return all(value.get(key) == item for key, item in expected.items())


def string_list(value, description):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise Refused(description)
    return value


def user_policies(reply, user):
    result = reply.one().get("result")
    if not isinstance(result, dict):
        raise Refused("user policy inspection is malformed")
    mappings = result.get("userMappings", [])
    if not isinstance(mappings, list):
        raise Refused("user policy mappings are malformed")
    policies = set()
    for mapping in mappings:
        if not isinstance(mapping, dict) or mapping.get("user") != user:
            raise Refused("user policy inspection returned a different identity")
        policies.update(string_list(mapping.get("policies", []), "user policy list is malformed"))
    return policies


def policy_holders(reply, name):
    result = reply.one().get("result")
    if not isinstance(result, dict):
        raise Refused("superseded policy inspection is malformed")
    mappings = result.get("policyMappings", [])
    if not isinstance(mappings, list):
        raise Refused("superseded policy mappings are malformed")
    users, groups = set(), set()
    for mapping in mappings:
        if not isinstance(mapping, dict) or mapping.get("policy") != name:
            raise Refused("superseded policy inspection returned another policy")
        users.update(string_list(mapping.get("users") or [], "policy user list is malformed"))
        groups.update(string_list(mapping.get("groups") or [], "policy group list is malformed"))
    return users, groups


def inspect(client, payload):
    """Read all owned contracts before any IAM mutation; return internal actions.

    This result stays inside the host. Only its action count leaves the process.
    Opaque access keys are required by mc argv, but never emitted or logged here.
    """
    alias = payload["alias"]
    pending = []
    wanted_alias = alias_document(payload["endpoint"], payload["root_user"], payload["root_password"])
    if not alias_current(payload["shared_config"], alias, wanted_alias):
        pending.append(("alias", None))
    for bucket in payload["buckets"]:
        target = alias + "/" + bucket["name"]
        version = client.call("version", "info", target)
        if version.absent("NoSuchBucket"):
            pending.append(("bucket", bucket))
            continue
        versioning = version.one().get("versioning")
        if not isinstance(versioning, dict) or versioning.get("status") not in ("", "Enabled", "Suspended"):
            raise Refused("bucket versioning inspection is malformed")
        if bucket["versioning"] and versioning["status"] != "Enabled":
            pending.append(("version", bucket))
        permission = client.call("anonymous", "get", target).one().get("permission")
        if permission not in ("private", "readonly", "writeonly", "public", "custom"):
            raise Refused("bucket access inspection is malformed")
        if permission != bucket["policy"]:
            pending.append(("anonymous", bucket))
    for policy in payload["policies"]:
        info = client.call("admin", "policy", "info", alias, policy["name"])
        if info.absent("XMinioAdminNoSuchPolicy"):
            pending.append(("policy", policy))
            continue
        policy_info = info.one().get("policyInfo")
        if not isinstance(policy_info, dict) or not isinstance(policy_info.get("Policy"), dict):
            raise Refused("policy document inspection is malformed")
        if normalized(policy_info["Policy"]) != normalized(policy["document"]):
            if policy["immutable"]:
                raise Refused("immutable versioned policy drift; use a reviewed new policy name or legacy rollback")
            pending.append(("policy", policy))
    for identity in payload["identities"]:
        info = client.call("admin", "user", "info", alias, identity["access"])
        if info.absent("XMinioAdminNoSuchUser"):
            pending.append(("user", identity))
            attached = set()
        else:
            user = info.one()
            if user.get("accessKey") != identity["access"]:
                raise Refused("user inspection returned another identity")
            if user.get("userStatus") != "enabled":
                raise Refused("managed user is disabled or has unknown status; refusing to enable or rotate it")
            groups = string_list(user.get("memberOf") or [], "user membership inspection is malformed")
            attached = user_policies(client.call("admin", "policy", "entities", alias, "--user", identity["access"]), identity["access"])
            if identity["exact"] and (groups or attached - set(identity["policies"])):
                raise Refused("dedicated user has extra policy attachments or group membership")
            if not client.prove_secret(payload["endpoint"], identity["access"], identity["secret"], identity["proof"]):
                pending.append(("user", identity))
        for policy in identity["policies"]:
            if policy not in attached:
                pending.append(("attach", (identity, policy)))
    for old in payload["superseded"]:
        info = client.call("admin", "policy", "info", alias, old["name"])
        if info.absent("XMinioAdminNoSuchPolicy"):
            continue
        info.one()
        users, groups = policy_holders(client.call("admin", "policy", "entities", alias, "--policy", old["name"]), old["name"])
        identity = payload["identities"][old["identity"]]
        if groups or users - {identity["access"]}:
            raise Refused("superseded policy still belongs to another identity or group")
        if identity["access"] in users:
            pending.append(("detach", (identity, old["name"])))
        pending.append(("remove_policy", old["name"]))
    return pending


def write_alias(payload, executable):
    directory = Path(payload["shared_config"])
    path = directory / "config.json"
    before = None
    if path.exists():
        before = json.loads(path.read_text())
    shared = Client(executable, directory)
    shared.import_alias(payload["alias"], alias_document(payload["endpoint"], payload["root_user"], payload["root_password"]))
    after = json.loads(path.read_text())
    if before is not None:
        before["aliases"].pop(payload["alias"], None)
        after["aliases"].pop(payload["alias"], None)
        if before != after:
            raise Refused("alias import changed unrelated client configuration")


def apply(client, payload, pending):
    alias = payload["alias"]
    # inspect() has already validated every existing immutable/exact/disabled
    # contract. Never detach the superseded policy until replacement is proven.
    for action, item in pending:
        if action == "alias":
            write_alias(payload, client.executable)
        elif action == "bucket":
            target = alias + "/" + item["name"]
            client.call("mb", target).one()
            if item["versioning"]:
                client.call("version", "enable", target).one()
            permission = client.call("anonymous", "get", target).one().get("permission")
            if permission not in ("private", "readonly", "writeonly", "public", "custom"):
                raise Refused("new bucket access inspection is malformed")
            if permission != item["policy"]:
                client.call("anonymous", "set", item["policy"], target).one()
        elif action == "version":
            client.call("version", "enable", alias + "/" + item["name"]).one()
        elif action == "anonymous":
            client.call("anonymous", "set", item["policy"], alias + "/" + item["name"]).one()
        elif action == "policy":
            client.call("admin", "policy", "create", alias, item["name"], "/dev/stdin", stdin=json.dumps(item["document"])).one()
            live = client.call("admin", "policy", "info", alias, item["name"]).one()
            if normalized(live.get("policyInfo", {}).get("Policy")) != normalized(item["document"]):
                raise Refused("policy update failed exact document verification")
        elif action == "user":
            client.call("admin", "user", "add", alias, stdin=item["access"] + "\n" + item["secret"] + "\n").one()
        elif action == "attach":
            identity, policy = item
            client.call("admin", "policy", "attach", alias, policy, "--user", identity["access"]).one()
        elif action in ("detach", "remove_policy"):
            # Prove all current policies for the designated identity before the
            # first removal, including when another process changed mappings.
            for old in payload["superseded"]:
                identity = payload["identities"][old["identity"]]
                current = user_policies(client.call("admin", "policy", "entities", alias, "--user", identity["access"]), identity["access"])
                if not set(identity["policies"]) <= current:
                    raise Refused("replacement policy attachments are not proven; refusing removal")
            if action == "detach":
                identity, policy = item
                client.call("admin", "policy", "detach", alias, policy, "--user", identity["access"]).one()
            else:
                users, groups = policy_holders(client.call("admin", "policy", "entities", alias, "--policy", item), item)
                if users or groups:
                    raise Refused("superseded policy has remaining holders; refusing removal")
                client.call("admin", "policy", "remove", alias, item).one()
        else:
            raise Refused("unknown planned action")


def main():
    import sys

    os.umask(0o077)
    try:
        action = sys.argv[1]
        if action not in ("check", "apply", "inspect-current", "recovery"):
            raise Refused("unknown requested action")
        payload = json.load(sys.stdin)
        if action == "recovery":
            print(json.dumps(recovery_state(payload)))
            return
        access, root = (current_credentials(payload) if action == "inspect-current" else
                        (payload["root_user"], payload["root_password"]))
        # root access is verified through scoped operations below; imported alias
        # config only lives in this private temporary directory.
        with tempfile.TemporaryDirectory(prefix="ops-minio-admin-") as directory:
            client = Client([payload["mc"]], directory)
            client.import_alias(payload["alias"], alias_document(payload["endpoint"], access, root))
            pending = inspect(client, payload)
            if action == "apply" and pending:
                apply(client, payload, pending)
                if inspect(client, payload):
                    raise Refused("owned IAM configuration did not converge")
            print(json.dumps({"pending": len(pending), "changed": action == "apply" and bool(pending)}))
    except Refused as error:
        print("refused: " + str(error))
        sys.exit(1)
    except Exception:
        # Includes malformed payload/schema/OS failures. Never print exception
        # details: json/subprocess errors may contain credentials or CLI output.
        print("refused: unexpected client or request failure")
        sys.exit(1)


if __name__ == "__main__":
    main()
