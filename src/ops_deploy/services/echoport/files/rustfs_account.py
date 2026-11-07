# The scoped RustFS account of Echoport's own alias, managed through RustFS's
# native admin API (/rustfs/admin/v3). Runs as root on the RustFS host with
# ops_deploy.services.rustfs's files/iam_host.py loaded first (Api, Server,
# Refused, ADMIN, normalized come from it: one SigV4 client for every RustFS
# deploy). The root credentials, address and region are read from RustFS's
# root-only environment file on the host; they never reach the controller or
# a command line.
#
# Arguments: action, environment file, then
#   require
#   probe|verify <policy> <user> <document>
#   create-policy <policy> <policy file>
#   add-user                     (reads "<user>\n<secret>\n" on stdin)
#   attach <policy> <user>
#
# probe prints ``policy=<ok|differs|missing> user=<attached|unattached|missing>``
# like minio_account.py; verify exits non-zero unless the policy holds the
# document and the user is enabled, holds exactly that policy and belongs to no
# group. Failures print one constant line on stderr: never a credential or a
# server response.
import json
import sys


def environment(path):
    """KEY="value" lines of the environment file ops-deploy's RustFS deploy writes."""
    values = {}
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        raise Refused("the RustFS environment file is not readable (is RustFS deployed on this host?)") from None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        values[key.strip()] = value
    for key in ("RUSTFS_ACCESS_KEY", "RUSTFS_SECRET_KEY", "RUSTFS_ADDRESS"):
        if not values.get(key):
            raise Refused("the RustFS environment file lacks the root credentials or the address")
    return values


def connect(path):
    values = environment(path)
    return Server(
        {
            "endpoint": "http://" + values["RUSTFS_ADDRESS"],
            "region": values.get("RUSTFS_REGION") or "us-east-1",
            "root_access": values["RUSTFS_ACCESS_KEY"],
            "root_secret": values["RUSTFS_SECRET_KEY"],
        }
    )


def put(server, path, query, body, description):
    server.ok("PUT", ADMIN + path, query, body, description)


def state(server, policy, user, document):
    stored = server.policy(policy)
    if stored is None:
        policy_state = "missing"
    elif normalized(stored) == normalized(document):
        policy_state = "ok"
    else:
        policy_state = "differs"
    account = server.user(user)
    attached = server.attached(user) if account is not None else set()
    if account is None:
        user_state = "missing"
    else:
        user_state = "attached" if policy in attached else "unattached"
    return policy_state, user_state, account, attached


def run(action, path, args):
    server = connect(path)
    if action == "require" and not args:
        server.ok("GET", ADMIN + "info", description="the RustFS admin API refuses the root credentials")
        return
    if action in ("probe", "verify") and len(args) == 3:
        policy, user, document = args
        policy_state, user_state, account, attached = state(server, policy, user, json.loads(document))
        if action == "probe":
            print(f"policy={policy_state} user={user_state}")
            return
        problems = []
        detach_hint = False
        if policy_state == "differs":
            problems.append(f"policy {policy} differs from the installed document")
        elif policy_state == "missing":
            problems.append(f"policy {policy} is missing")
        if account is None:
            problems.append(f"user {user} is missing")
        else:
            if attached != {policy}:
                problems.append(f"user {user} holds policies {sorted(attached)}, not exactly {policy}")
                detach_hint = True
            if account.get("memberOf"):
                problems.append(f"user {user} belongs to a group")
                detach_hint = True
            if account.get("status") != "enabled":
                problems.append(f"user {user} is not enabled")
        if problems:
            hint = " Detach other policies or groups by hand, then run again." if detach_hint else ""
            raise Refused("RustFS account: " + "; ".join(problems) + "." + hint)
        return
    if action == "create-policy" and len(args) == 2:
        policy, policy_file = args
        try:
            with open(policy_file, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError):
            raise Refused("the installed policy file is not readable JSON") from None
        put(server, "add-canned-policy", [("name", policy)], json.dumps(document).encode(), "policy write failed")
        return
    if action == "add-user" and not args:
        lines = sys.stdin.read().split("\n")
        if len(lines) < 2 or not lines[0] or not lines[1]:
            raise Refused("add-user reads the user name and the secret on stdin")
        user, secret = lines[0], lines[1]
        account = server.user(user)
        # Like the RustFS deploy: a disabled user stays disabled until someone enables it by hand.
        if account is not None and account.get("status") != "enabled":
            raise Refused("the RustFS user is disabled or has an unknown status; refusing to enable or rotate it")
        body = json.dumps({"secretKey": secret, "status": "enabled"}).encode()
        put(server, "add-user", [("accessKey", user)], body, "user write failed")
        return
    if action == "attach" and len(args) == 2:
        policy, user = args
        if server.user(user) is None:
            raise Refused("the RustFS user to attach the policy to is missing")
        # Adds the policy and keeps any other one, as ``mc admin policy attach``
        # does; verify then refuses the extra ones.
        names = ",".join(sorted(server.attached(user) | {policy}))
        query = [("policyName", names), ("userOrGroup", user), ("isGroup", "false")]
        put(server, "set-user-or-group-policy", query, b"", "policy attachment failed")
        return
    raise Refused("unknown requested action")


def main():
    try:
        if len(sys.argv) < 3:
            raise Refused("unknown requested action")
        run(sys.argv[1], sys.argv[2], sys.argv[3:])
    except Refused as error:
        print("refused: " + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Never print exception details: they may contain credentials or responses.
        print("refused: unexpected request or payload failure", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
