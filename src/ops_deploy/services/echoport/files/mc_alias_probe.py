# Reads ``mc --json alias list <alias>`` on stdin; argument: mc's exit status.
# Prints one SHA-256 of the stored URL, access key and secret key (joined by
# newlines), or ``none`` when mc says the alias is not configured. Anything
# else (mc failing for another reason, output that is not mc's JSON) exits
# non-zero, so the deploy's strict probe reports it. The deploy compares the
# digest with the one of the values it would set; the credentials themselves
# are never printed.
import hashlib
import json
import sys

status = int(sys.argv[1])
lines = sys.stdin.read().strip().splitlines()
try:
    stored = json.loads(lines[0])
except (IndexError, ValueError):
    sys.exit(f"mc alias list exited {status} without JSON")
if not isinstance(stored, dict):
    sys.exit("mc alias list printed unexpected JSON")
if status == 0 and stored.get("status") == "success":
    print(hashlib.sha256("\n".join(str(stored.get(key, "")) for key in ("URL", "accessKey", "secretKey")).encode()).hexdigest())
elif status != 0 and "No such alias" in str((stored.get("error") or {}).get("message", "")):
    print("none")
else:
    sys.exit(f"mc alias list exited {status}: {str((stored.get('error') or {}).get('message', ''))[:200]}")
