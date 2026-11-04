"""Host-local RustFS bucket/IAM convergence; standard library only.

Reads the payload (endpoint, root and identity credentials, declarations) from
stdin and talks SigV4 to the server's own S3 API and the native admin API
(``/rustfs/admin/v3``, plain JSON bodies). Credentials and server responses
never leave this process: it prints only a pending count or a constant refusal.
Only exact, recognized server answers decide that something is absent.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ElementTree

ADMIN = "/rustfs/admin/v3/"
LIMIT = 1 << 20
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"
VERSIONING_ON = (
    b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Status>Enabled</Status></VersioningConfiguration>"
)
LIFECYCLE_RULE = "replicated-noncurrent-expiry"


class Refused(RuntimeError):
    """A constant, non-sensitive diagnostic safe to return to the controller."""


def quote(value, safe="-_.~"):
    return urllib.parse.quote(value, safe=safe)


class Api:
    """SigV4 client; by default only for the server's own address literal.

    ``remote=True`` admits a peer's host name (the replica monitor's counts).
    """

    def __init__(self, endpoint, region, remote=False):
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "http" or not parsed.hostname or not parsed.port or not local_address(parsed.hostname):
            if not (remote and parsed.scheme == "http" and parsed.hostname and parsed.port):
                raise Refused("endpoint must be the server's own HTTP address")
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


def local_address(hostname):
    """Loopback or an IPv4 literal: the configured listen address of this host."""
    try:
        address = ipaddress.IPv4Address(hostname)
    except ValueError:
        return False
    return not (address.is_unspecified or address.is_multicast) and str(address) == hostname


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


def parse_xml(data, description):
    """The document with namespaces dropped; the server's own XML only."""
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        raise Refused(description) from None
    for element in root.iter():
        element.tag = element.tag.rpartition("}")[2]
    return root


def text(element, path):
    found = element.find(path)
    return None if found is None else (found.text or "")


def everything(rule):
    """No filter, or one that selects every key (an empty prefix)."""
    found = rule.find("Filter")
    if found is None:
        return rule.find("Prefix") is None or not text(rule, "Prefix")
    return [child.tag for child in found] in ([], ["Prefix"]) and not text(found, "Prefix")


def lifecycle_rule(days):
    return (
        f"<Rule><ID>{LIFECYCLE_RULE}</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>"
        "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>"
        f"<NoncurrentVersionExpiration><NoncurrentDays>{int(days)}</NoncurrentDays></NoncurrentVersionExpiration>"
        "</Rule>"
    )


def lifecycle_current(rules, days):
    """Exactly the managed rule; anything else is outside this deployment."""
    if len(rules) != 1:
        return False
    rule = rules[0]
    return (
        text(rule, "ID") == LIFECYCLE_RULE
        and text(rule, "Status") == "Enabled"
        and everything(rule)
        and text(rule, "Expiration/ExpiredObjectDeleteMarker") == "true"
        and text(rule, "NoncurrentVersionExpiration/NoncurrentDays") == str(int(days))
        and {child.tag for child in rule} <= {"ID", "Status", "Filter", "Expiration", "NoncurrentVersionExpiration"}
    )


REPLICATED = ("DeleteMarkerReplication", "DeleteReplication", "ExistingObjectReplication",
              "SourceSelectionCriteria/ReplicaModifications")  # fmt: skip


def replication_document(rule_id, arn):
    flags = "".join(
        f"<{name}><Status>Enabled</Status></{name}>"
        for name in ("DeleteMarkerReplication", "DeleteReplication", "ExistingObjectReplication")
    )
    return (
        f'<ReplicationConfiguration xmlns="{S3_NS}"><Role></Role><Rule><ID>{rule_id}</ID><Status>Enabled</Status>'
        f"<Priority>1</Priority>{flags}<SourceSelectionCriteria><ReplicaModifications><Status>Enabled</Status>"
        "</ReplicaModifications></SourceSelectionCriteria><Filter><Prefix></Prefix></Filter>"
        f"<Destination><Bucket>{arn}</Bucket></Destination></Rule></ReplicationConfiguration>"
    ).encode()


def replication_current(root, rule_id, arn):
    """One enabled rule replicating everything, deletes included, to ``arn``."""
    rules = root.findall("Rule")
    if len(rules) != 1 or (text(root, "Role") or "").strip():
        return False
    rule = rules[0]
    return (
        text(rule, "ID") == rule_id
        and text(rule, "Status") == "Enabled"
        and (text(rule, "Destination/Bucket") or "").strip() == arn
        and everything(rule)
        and all(text(rule, name + "/Status") == "Enabled" for name in REPLICATED)
    )


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

    def lifecycle_rules(self, bucket):
        status, data = self.call("GET", "/" + bucket, [("lifecycle", "")])
        if self.missing(status, data, "NoSuchLifecycleConfiguration"):
            return []
        if status != 200:
            raise Refused("lifecycle inspection failed")
        return parse_xml(data, "lifecycle inspection is malformed").findall("Rule")

    def targets(self, bucket):
        data = self.ok("GET", ADMIN + "list-remote-targets", [("bucket", bucket)],
                       description="remote target inspection failed")
        try:
            value = json.loads(data)
        except ValueError:
            raise Refused("remote target inspection is malformed") from None
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise Refused("remote target inspection is malformed")
        return value

    def target(self, replication):
        """The bucket's replication target for the declared endpoint and bucket, or None."""
        matches = [
            item for item in self.targets(replication["bucket"])
            if item.get("type") == "replication"
            and item.get("endpoint") == replication["endpoint"]
            and item.get("targetbucket") == replication["target_bucket"]
            and item.get("secure") is replication["secure"]
        ]  # fmt: skip
        if len(matches) > 1 or (matches and not isinstance(matches[0].get("arn"), str)):
            raise Refused("remote target inspection is ambiguous")
        return matches[0] if matches else None

    def replication(self, bucket):
        status, data = self.call("GET", "/" + bucket, [("replication", "")])
        if self.missing(status, data, "ReplicationConfigurationNotFoundError"):
            return None
        if status != 200:
            raise Refused("replication inspection failed")
        return parse_xml(data, "replication inspection is malformed")

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
    for bucket in payload["buckets"]:
        days = bucket.get("noncurrent_expiry_days")
        if days is None:
            continue
        rules = [] if ("bucket", bucket) in pending else server.lifecycle_rules(bucket["name"])
        if any(text(rule, "ID") != LIFECYCLE_RULE for rule in rules):
            raise Refused("bucket has lifecycle rules outside this deployment; refusing to replace them")
        if not lifecycle_current(rules, days):
            pending.append(("lifecycle", bucket))
    access = (payload.get("replication") or {}).get("access")
    for replication in payload.get("replications", ()):
        fresh = any(action == "bucket" and item["name"] == replication["bucket"] for action, item in pending)
        target = None if fresh else server.target(replication)
        if target is None:
            pending.append(("target", replication))
        elif (target.get("credentials") or {}).get("accessKey") != access:
            pending.append(("target_credentials", replication))
        document = None if fresh else server.replication(replication["bucket"])
        if document is not None:
            ids = [text(rule, "ID") for rule in document.findall("Rule")]
            if ids != [replication["rule_id"]]:
                raise Refused("bucket has replication rules outside this deployment; refusing to replace them")
        if target is None or document is None or not replication_current(document, replication["rule_id"], target["arn"]):
            pending.append(("replication", replication))
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


def apply(server, pending, replication=None):
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
        elif action == "lifecycle":
            body = f'<LifecycleConfiguration xmlns="{S3_NS}">{lifecycle_rule(item["noncurrent_expiry_days"])}'
            body = (body + "</LifecycleConfiguration>").encode()
            md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
            status, _ = server.api.request("PUT", "/" + item["name"], *server.root, query=[("lifecycle", "")],
                                           body=body, headers={"content-md5": md5})
            if status != 200:
                raise Refused("lifecycle write failed")
        elif action in ("target", "target_credentials"):
            # The server checks the remote bucket (reachable, versioned) with
            # these credentials before it stores the target.
            target = {
                "sourcebucket": item["bucket"], "endpoint": item["endpoint"], "targetbucket": item["target_bucket"],
                "secure": item["secure"], "type": "replication", "region": server.api.region,
                "credentials": {"accessKey": replication["access"], "secretKey": replication["secret"]},
            }  # fmt: skip
            query = [("bucket", item["bucket"])]
            if action == "target_credentials":
                current = server.target(item)
                if current is None:
                    raise Refused("remote target disappeared during apply")
                target["arn"] = current["arn"]
                query += [("update", "true"), ("creds", "true")]
            server.ok("PUT", ADMIN + "set-remote-target", query, json.dumps(target).encode(),
                      "remote target write failed (remote bucket absent, unversioned or credentials rejected)")
        elif action == "replication":
            target = server.target(item)
            if target is None:
                raise Refused("remote target missing before the replication rule")
            server.ok("PUT", "/" + item["bucket"], [("replication", "")],
                      replication_document(item["rule_id"], target["arn"]), "replication rule write failed")
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
            apply(server, pending, payload.get("replication"))
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
