"""Host-local RustFS bucket/IAM convergence; standard library only.

Reads the payload (endpoint, root and identity credentials, declarations) from
stdin and talks SigV4 to the loopback S3 API and the native admin API
(``/rustfs/admin/v3``, plain JSON bodies). Credentials and server responses
never leave this process: it prints only a pending count or a constant refusal.
Only exact, recognized server answers decide that something is absent.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import http.client
import json
import re
import sys
import urllib.parse

ADMIN = "/rustfs/admin/v3/"
LIMIT = 1 << 20
VERSIONING_ON = (
    b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Status>Enabled</Status></VersioningConfiguration>"
)


class Refused(RuntimeError):
    """A constant, non-sensitive diagnostic safe to return to the controller."""


def quote(value, safe="-_.~"):
    return urllib.parse.quote(value, safe=safe)


class Api:
    def __init__(self, endpoint, region):
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
            raise Refused("endpoint must be loopback HTTP")
        self.host, self.port, self.region = parsed.hostname, parsed.port, region

    def request(self, method, path, access, secret, query=(), body=b"", headers=None):
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        payload = hashlib.sha256(body).hexdigest()
        signed = {"host": f"{self.host}:{self.port}", "x-amz-date": now, "x-amz-content-sha256": payload}
        signed.update(headers or {})
        canonical_path = quote(path, safe="/-_.~")
        canonical_query = "&".join(f"{quote(key)}={quote(value)}" for key, value in sorted(query))
        names = sorted(signed)
        canonical = "\n".join(
            [method, canonical_path, canonical_query, "".join(f"{name}:{signed[name]}\n" for name in names),
             ";".join(names), payload]
        )
        scope = f"{now[:8]}/{self.region}/s3/aws4_request"
        text = "\n".join(["AWS4-HMAC-SHA256", now, scope, hashlib.sha256(canonical.encode()).hexdigest()])
        key = ("AWS4" + secret).encode()
        for part in (now[:8], self.region, "s3", "aws4_request"):
            key = hmac.new(key, part.encode(), hashlib.sha256).digest()
        signature = hmac.new(key, text.encode(), hashlib.sha256).hexdigest()
        signed["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={';'.join(names)}, Signature={signature}"
        )
        connection = http.client.HTTPConnection(self.host, self.port, timeout=30)
        try:
            target = canonical_path + ("?" + canonical_query if canonical_query else "")
            connection.request(method, target, body=body, headers=signed)
            response = connection.getresponse()
            data = response.read(LIMIT + 1)
            if len(data) > LIMIT:
                raise Refused("server response exceeds the inspection limit")
            return response.status, data
        except (OSError, http.client.HTTPException):
            raise Refused("server request failed or timed out") from None
        finally:
            connection.close()


def error_code(data):
    match = re.search(rb"<Code>([A-Za-z]+)</Code>", data)
    return match.group(1).decode() if match else None


def parse_json(data, description):
    try:
        value = json.loads(data)
    except ValueError:
        raise Refused(description) from None
    if not isinstance(value, dict):
        raise Refused(description)
    return value


def string_set(value):
    items = [value] if isinstance(value, str) else value
    if isinstance(items, list) and all(isinstance(item, str) for item in items):
        return sorted(set(items))
    return value


def normalized(policy):
    """Statement order and set-valued Action/Resource fields carry no meaning."""
    if not isinstance(policy, dict) or not isinstance(policy.get("Statement"), list):
        return policy
    result = []
    for statement in policy["Statement"]:
        if isinstance(statement, dict):
            statement = dict(statement)
            for field in ("Action", "NotAction", "Resource", "NotResource"):
                if field in statement:
                    statement[field] = string_set(statement[field])
            # The server stores a one-element condition value as a bare string.
            condition = statement.get("Condition")
            if isinstance(condition, dict):
                statement["Condition"] = {
                    operator: {key: string_set(value) for key, value in keys.items()} if isinstance(keys, dict) else keys
                    for operator, keys in condition.items()
                }
        result.append(statement)
    result.sort(key=lambda value: json.dumps(value, sort_keys=True))
    return {**policy, "Statement": result}


class Server:
    def __init__(self, payload):
        self.api = Api(payload["endpoint"], payload["region"])
        self.root = payload["root_access"], payload["root_secret"]

    def call(self, method, path, query=(), body=b""):
        status, data = self.api.request(method, path, *self.root, query=query, body=body)
        if status == 403 and error_code(data) in ("InvalidAccessKeyId", "SignatureDoesNotMatch"):
            raise Refused("the server rejects the declared root credentials")
        return status, data

    def ok(self, method, path, query=(), body=b"", description="request failed"):
        status, data = self.call(method, path, query, body)
        if status != 200:
            raise Refused(description)
        return data

    def missing(self, status, data, code):
        return status == 404 and error_code(data) == code

    def versioning(self, bucket):
        data = self.ok("GET", "/" + bucket, [("versioning", "")], description="versioning inspection failed")
        match = re.fullmatch(
            rb'(<\?xml[^>]*\?>)?<VersioningConfiguration[^>]*>(<Status>(Enabled|Suspended)</Status>)?'
            rb"(<MFADelete>[A-Za-z]+</MFADelete>)?</VersioningConfiguration>",
            data.strip(),
        )
        if not match:
            raise Refused("versioning inspection is malformed")
        return (match.group(3) or b"").decode()

    def policy(self, name):
        status, data = self.call("GET", ADMIN + "info-canned-policy", [("name", name)])
        if self.missing(status, data, "NoSuchResource"):
            return None
        if status != 200:
            raise Refused("policy inspection failed")
        document = parse_json(data, "policy inspection is malformed").get("policy")
        if not isinstance(document, dict):
            raise Refused("policy inspection is malformed")
        return document

    def user(self, access):
        status, data = self.call("GET", ADMIN + "user-info", [("accessKey", access)])
        if self.missing(status, data, "NoSuchResource"):
            return None
        if status != 200:
            raise Refused("user inspection failed")
        return parse_json(data, "user inspection is malformed")

    def attached(self, access):
        data = self.ok("GET", ADMIN + "idp/builtin/policy-entities", [("user", access)],
                       description="policy attachment inspection failed")
        mappings = parse_json(data, "policy attachments are malformed").get("userMappings") or []
        policies = set()
        if not isinstance(mappings, list):
            raise Refused("policy attachments are malformed")
        for mapping in mappings:
            if not isinstance(mapping, dict) or mapping.get("user") != access:
                raise Refused("policy attachment inspection returned another identity")
            values = mapping.get("policies") or []
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                raise Refused("policy attachments are malformed")
            policies.update(values)
        return policies

    def secret_matches(self, identity):
        """Recognized S3 answers only: AccessDenied/NoSuchKey prove a valid signature."""
        bucket, _, key = identity["proof"].partition("/")
        if key:
            status, data = self.api.request("GET", f"/{bucket}/{key}", identity["access"], identity["secret"],
                                            headers={"range": "bytes=0-0"})
        else:
            status, data = self.api.request("GET", "/" + bucket, identity["access"], identity["secret"],
                                            query=[("location", "")])
        if status in (200, 206):
            return True
        code = error_code(data)
        if code in ("AccessDenied", "NoSuchKey", "NoSuchBucket"):
            return True
        if code in ("SignatureDoesNotMatch", "InvalidAccessKeyId"):
            return False
        raise Refused("credential proof returned an unrecognized answer")


def inspect(server, payload):
    """Every declared contract, read before any write; returns internal actions."""
    pending = []
    for bucket in payload["buckets"]:
        status, data = server.call("HEAD", "/" + bucket["name"])
        if status == 403:
            # HEAD has no error body; a signed GET names a rejected root key.
            server.call("GET", "/" + bucket["name"], [("location", "")])
        if status == 404:
            pending.append(("bucket", bucket))
            continue
        if status != 200:
            raise Refused("bucket inspection failed")
        if bucket["versioning"] and server.versioning(bucket["name"]) != "Enabled":
            pending.append(("versioning", bucket))
    for policy in payload["policies"]:
        current = server.policy(policy["name"])
        if current is None or normalized(current) != normalized(policy["document"]):
            pending.append(("policy", policy))
    for identity in payload["identities"]:
        user = server.user(identity["access"])
        if user is None:
            pending.append(("user", identity))
            pending.append(("attach", identity))
            continue
        if user.get("status") != "enabled":
            raise Refused("managed user is disabled or has unknown status; refusing to enable or rotate it")
        if user.get("memberOf"):
            raise Refused("managed user is a group member; groups are outside this deployment")
        if not server.secret_matches(identity):
            pending.append(("user", identity))
        if server.attached(identity["access"]) != set(identity["policies"]):
            pending.append(("attach", identity))
    return pending


def apply(server, pending):
    for action, item in pending:
        if action == "bucket":
            server.ok("PUT", "/" + item["name"], description="bucket creation failed")
            if item["versioning"]:
                server.ok("PUT", "/" + item["name"], [("versioning", "")], VERSIONING_ON, "versioning failed")
        elif action == "versioning":
            server.ok("PUT", "/" + item["name"], [("versioning", "")], VERSIONING_ON, "versioning failed")
        elif action == "policy":
            body = json.dumps(item["document"]).encode()
            server.ok("PUT", ADMIN + "add-canned-policy", [("name", item["name"])], body, "policy write failed")
        elif action == "user":
            body = json.dumps({"secretKey": item["secret"], "status": "enabled"}).encode()
            server.ok("PUT", ADMIN + "add-user", [("accessKey", item["access"])], body, "user write failed")
        elif action == "attach":
            query = [("policyName", ",".join(sorted(item["policies"]))), ("userOrGroup", item["access"]),
                     ("isGroup", "false")]
            server.ok("PUT", ADMIN + "set-user-or-group-policy", query, description="policy attachment failed")
        else:
            raise Refused("unknown planned action")


def main():
    try:
        action = sys.argv[1] if len(sys.argv) == 2 else ""
        if action not in ("check", "apply"):
            raise Refused("unknown requested action")
        payload = json.load(sys.stdin)
        server = Server(payload)
        pending = inspect(server, payload)
        if action == "apply" and pending:
            apply(server, pending)
            if inspect(server, payload):
                raise Refused("declared configuration did not converge")
        print(json.dumps({"pending": len(pending), "changed": action == "apply" and bool(pending)}))
    except Refused as error:
        print("refused: " + str(error))
        sys.exit(1)
    except Exception:
        # Never print exception details: they may contain credentials or responses.
        print("refused: unexpected request or payload failure")
        sys.exit(1)


if __name__ == "__main__":
    main()
