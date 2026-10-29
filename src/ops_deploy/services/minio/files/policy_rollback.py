"""Explicit named-policy rollback, matching the original tagged maintenance block.

Loaded with the qualified iam_host boundary in its namespace. No full IAM
reconciliation, shared alias write, document/replacement admission or root rotation.
Only fixed status fields leave this process; credentials stay on protected stdin.
"""


def policy_present(client, payload):
    reply = client.call("admin", "policy", "info", payload["alias"], payload["policy"])
    if reply.absent("XMinioAdminNoSuchPolicy"):
        return False
    reply.one()
    return True


def rollback_policy(client, payload, progress):
    progress["phase"] = "inspect"
    if not policy_present(client, payload):
        progress["phase"] = "verify-absence"
        if policy_present(client, payload):
            raise Refused("named policy appeared during rollback verification")
        progress["phase"] = "complete"
        return False
    progress["phase"] = "detach"
    progress["detach_attempted"] = True
    try:
        reply = client.call("admin", "policy", "detach", payload["alias"], payload["policy"],
                            "--user", payload["access"])
        progress["detach_failed"] = not reply.successful
    except Refused:
        # The original command ignores its failure only until the independent
        # entities query proves the declared identity detached. Never assume it.
        progress["detach_failed"] = True
    progress["phase"] = "verify-detachment"
    users, _groups = policy_holders(
        client.call("admin", "policy", "entities", payload["alias"], "--policy", payload["policy"]),
        payload["policy"],
    )
    if payload["access"] in users:
        raise Refused("declared identity remains attached; refusing policy removal")
    # Original rollback does not require a particular policy document or refuse
    # other holders here. Preserve the server's actual remove behavior/errors.
    progress["phase"] = "remove"
    progress["remove_attempted"] = True
    client.call("admin", "policy", "remove", payload["alias"], payload["policy"]).one()
    progress["phase"] = "verify-absence"
    if policy_present(client, payload):
        raise Refused("named policy remains after rollback")
    progress["phase"] = "complete"
    return True


def rollback_main():
    import sys

    os.umask(0o077)
    progress = {"phase": "input", "detach_attempted": False, "detach_failed": False,
                "remove_attempted": False}
    try:
        action = sys.argv[1]
        if action not in ("check", "apply", "verify"):
            raise Refused("unknown policy rollback action")
        payload = json.load(sys.stdin)
        with tempfile.TemporaryDirectory(prefix="ops-minio-policy-rollback-") as directory:
            client = Client([payload["mc"]], directory)
            client.import_alias(payload["alias"], alias_document(
                payload["endpoint"], payload["root_user"], payload["root_password"]))
            progress["phase"] = "inspect"
            if action == "check":
                print(json.dumps({"pending": policy_present(client, payload)}))
            elif action == "verify":
                if policy_present(client, payload):
                    raise Refused("named policy remains before local document removal")
                print(json.dumps({"absent": True}))
            else:
                changed = rollback_policy(client, payload, progress)
                print(json.dumps({"changed": changed, **progress}))
    except Refused as error:
        print(json.dumps({"failed": True, "reason": str(error), **progress}))
        sys.exit(1)
    except Exception:
        print(json.dumps({"failed": True, "reason": "unexpected rollback boundary failure", **progress}))
        sys.exit(1)


if __name__ == "__main__":
    rollback_main()
