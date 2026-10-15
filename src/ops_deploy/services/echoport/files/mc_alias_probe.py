# Reads ``mc --json alias list <alias>`` on stdin and prints one SHA-256 of the
# stored URL, access key and secret key (joined by newlines), or ``none`` when
# the alias is not configured. The deploy compares it with the digest of the
# values it would set; the credentials themselves are never printed.
import hashlib
import json
import sys

lines = sys.stdin.read().strip().splitlines()
try:
    stored = json.loads(lines[0])
    print(hashlib.sha256("\n".join(str(stored.get(key, "")) for key in ("URL", "accessKey", "secretKey")).encode()).hexdigest())
except (IndexError, ValueError, AttributeError):
    print("none")
