# The scoped MinIO account of Echoport's own alias, read through root's MinIO
# admin alias (never the MinIO root credentials). Arguments: mode (``probe`` or
# ``verify``), mc, admin alias, policy name, user name, the policy document
# (JSON) the deploy installs.
#
# probe prints ``policy=<ok|differs|missing> user=<attached|unattached|missing>``;
# mc failing for the policy or the user reads as missing, so the deploy runs the
# steps that create them (and verify runs after them). verify exits non-zero
# unless the policy holds the document and the user is enabled, holds exactly
# that policy and belongs to no group (the role's last assert). Neither prints
# anything secret: the account's secret is not an argument.
import json
import subprocess
import sys

mode, mc, admin, policy, user, document = sys.argv[1:]


def mc_json(*args):
    result = subprocess.run([mc, *args], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    # One JSON document, indented or on one line.
    try:
        found = json.loads(result.stdout)
    except ValueError:
        return None
    return found if isinstance(found, dict) else None


def as_list(value):
    return [value] if isinstance(value, str) else list(value or [])


def normalized_condition(value):
    """Condition maps keep their keys; string values compare as sorted lists."""
    if isinstance(value, dict):
        return {key: normalized_condition(item) for key, item in value.items()}
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return sorted(value)
    return value


def statements(doc):
    return sorted(
        json.dumps(
            [
                s.get("Effect"),
                sorted(as_list(s.get("Action"))),
                sorted(as_list(s.get("Resource"))),
                normalized_condition(s.get("Condition") or {}),
            ],
            sort_keys=True,
        )
        for s in (doc or {}).get("Statement") or []
    )


info = mc_json("admin", "policy", "info", "--json", admin, policy)
stored = ((info or {}).get("policyInfo") or {}).get("Policy")
if info is None or not isinstance(stored, dict):
    policy_state = "missing"
elif statements(stored) == statements(json.loads(document)):
    policy_state = "ok"
else:
    policy_state = "differs"

account = mc_json("admin", "user", "info", "--json", admin, user)
names = [p for p in str((account or {}).get("policyName") or "").split(",") if p]
if account is None:
    user_state = "missing"
else:
    user_state = "attached" if policy in names else "unattached"

if mode == "probe":
    print(f"policy={policy_state} user={user_state}")
    sys.exit(0)

problems = []
detach_hint = False
if policy_state == "differs":
    problems.append(f"policy {policy} differs from the installed document")
elif policy_state == "missing":
    problems.append(f"policy {policy} is missing")
if account is None:
    problems.append(f"user {user} is missing")
else:
    if names != [policy]:
        problems.append(f"user {user} holds policies {names}, not exactly {policy}")
        detach_hint = True
    if account.get("memberOf"):
        problems.append(f"user {user} belongs to a group")
        detach_hint = True
    if account.get("userStatus") != "enabled":
        problems.append(f"user {user} is not enabled")
if problems:
    hint = " Detach other policies or groups by hand, then run again." if detach_hint else ""
    sys.exit("MinIO account: " + "; ".join(problems) + "." + hint)
