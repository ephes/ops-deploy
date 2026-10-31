"""Remove listed MinIO users, prove absence, change nothing else.

Loaded with the qualified iam_host boundary in its namespace. It reads the admin
credentials from protected stdin into a disposable client alias and never writes
root's shared alias config. Only fixed reasons and counts leave this process: no
credential, no access key and no client output.
"""

USER_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{2,62}"


def admit(payload):
    """Refuse a bad list before talking to the server."""
    users = payload["users"]
    if not isinstance(users, list) or not users:
        raise Refused("the user list is empty")
    if any(not isinstance(user, str) or not re.fullmatch(USER_NAME, user) for user in users):
        raise Refused("a listed user name is invalid")
    if len(set(users)) != len(users):
        raise Refused("the user list has duplicates")
    # The server answers NoSuchUser for its root user, so this must come first:
    # otherwise a listed root user would look like an already retired one.
    if {payload["root_user"], *payload["protected"]} & set(users):
        raise Refused("a listed user is protected")


def require_healthy(client, alias):
    # An unreachable server answers status=error with rc 0: only the row decides.
    try:
        info = client.call("admin", "info", alias).one().get("info")
    except Refused:
        raise Refused("the admin alias is not healthy") from None
    if not isinstance(info, dict) or info.get("mode") != "online":
        raise Refused("the admin alias is not healthy")


def listing(client, *args):
    """Rows of a list command; this client answers an empty list with no output and rc 0."""
    try:
        result = subprocess.run(
            [*client.executable, "--json", "--config-dir", client.config_dir, *args],
            stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=45,
            env={key: value for key, value in os.environ.items() if not key.startswith("MC_")},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("client could not execute or timed out") from None
    if result.returncode == 0 and not result.stdout.strip() and not result.stderr.strip():
        return []
    reply = Reply(result.returncode, result.stdout, result.stderr)
    if not reply.successful:
        raise Refused("client listing did not succeed")
    return reply.rows


def user_row(client, alias, user):
    """The user's info row, or None only on the precise missing-user response."""
    reply = client.call("admin", "user", "info", alias, user)
    if reply.absent("XMinioAdminNoSuchUser"):
        return None
    row = reply.one()
    if row.get("accessKey") != user:
        raise Refused("user inspection returned a different identity")
    return row


def present_users(client, payload):
    """Listed users still on the server. Removing them must not reach anything else."""
    alias = payload["alias"]
    present = []
    for user in payload["users"]:
        row = user_row(client, alias, user)
        if row is None:
            continue
        # The server would edit the group or delete these credentials along with the user.
        if row.get("memberOf"):
            raise Refused("a listed user belongs to a group; removing it would change the group")
        if listing(client, "admin", "user", "svcacct", "list", alias, user):
            raise Refused("a listed user owns service accounts; removing it would delete them")
        present.append(user)
    return present


def snapshot(client, payload):
    """In-memory state outside the listed users. Compared here, never printed."""
    alias = payload["alias"]
    users = {}
    for row in listing(client, "admin", "user", "list", alias):
        access = row.get("accessKey")
        if not isinstance(access, str) or not access:
            raise Refused("user listing is malformed")
        if access not in payload["users"]:
            users[access] = {key: value for key, value in row.items() if key != "status"}
    policies = {}
    for row in listing(client, "admin", "policy", "list", alias):
        name = row.get("policy")
        if not isinstance(name, str) or not name:
            raise Refused("policy listing is malformed")
        info = client.call("admin", "policy", "info", alias, name).one().get("policyInfo")
        if not isinstance(info, dict):
            raise Refused("policy inspection is malformed")
        # The server returns action lists in a varying order.
        policies[name] = {**info, "Policy": normalized(info.get("Policy"))}
    groups = {}
    names = client.call("admin", "group", "list", alias).one().get("groups") or []
    for name in string_list(names, "group listing is malformed"):
        groups[name] = client.call("admin", "group", "info", alias, name).one()
    buckets = sorted(str(row.get("key")) for row in listing(client, "ls", alias))
    return {"users": users, "policies": policies, "groups": groups, "buckets": buckets}


def retire_users(client, payload, progress):
    alias = payload["alias"]
    progress["phase"] = "inspect"
    require_healthy(client, alias)
    present = present_users(client, payload)
    if not present:
        progress["phase"] = "complete"
        return False
    before = snapshot(client, payload)
    for user in present:
        progress["phase"] = "remove"
        progress["remove_attempted"] = True
        client.call("admin", "user", "remove", alias, user).one()
        progress["phase"] = "verify-absence"
        if user_row(client, alias, user) is not None:
            raise Refused("a listed user remains after removal")
        progress["removed"] += 1
    progress["phase"] = "verify-unchanged"
    if snapshot(client, payload) != before:
        raise Refused("state outside the listed users changed during the removal")
    progress["phase"] = "complete"
    return True


def verify_users_absent(client, payload):
    alias = payload["alias"]
    require_healthy(client, alias)
    listed = {row.get("accessKey") for row in listing(client, "admin", "user", "list", alias)}
    for user in payload["users"]:
        if user in listed or user_row(client, alias, user) is not None:
            raise Refused("a listed user is still present")


def retirement_main():
    import sys

    os.umask(0o077)
    progress = {"phase": "input", "removed": 0, "remove_attempted": False}
    action = None
    try:
        action = sys.argv[1]
        if action not in ("check", "apply", "verify"):
            raise Refused("unknown user retirement action")
        payload = json.load(sys.stdin)
        admit(payload)
        with tempfile.TemporaryDirectory(prefix="ops-minio-user-retirement-") as directory:
            client = Client([payload["mc"]], directory)
            client.import_alias(payload["alias"], alias_document(
                payload["endpoint"], payload["root_user"], payload["root_password"]))
            if action == "check":
                require_healthy(client, payload["alias"])
                present = present_users(client, payload)
                if present:
                    snapshot(client, payload)  # A plan must not promise what apply would refuse.
                print(json.dumps({"pending": bool(present)}))
            elif action == "verify":
                verify_users_absent(client, payload)
                print(json.dumps({"absent": True}))
            else:
                changed = retire_users(client, payload, progress)
                print(json.dumps({"changed": changed, **progress}))
    except Refused as error:
        fail(action, str(error), progress)
    except Exception:
        fail(action, "unexpected user retirement failure", progress)


def fail(action, reason, progress):
    import sys

    if action == "check":
        # The plan's answer, so the controller can name the reason; probes drop failed output.
        print(json.dumps({"refused": reason}))
        return
    print(json.dumps({"failed": True, "reason": reason, **progress}))
    sys.exit(1)


if __name__ == "__main__":
    retirement_main()
