"""Host-local scanner password comparison; no verifier/credential leaves memory.

Python 3.13+ no longer provides crypt. Ubuntu's libcrypt supports the deployed
yescrypt verifier as well as older hashes. Actual yescrypt behavior is a native
qualification requirement; controller-only tests do not establish it.
"""

import ctypes
import hmac
import json
import re
import subprocess
import sys


class Refusal(ValueError):
    pass


def matches(password, stored):
    if not stored or stored[0] in "!*":
        return False
    library = ctypes.CDLL("libcrypt.so.1")
    library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.crypt.restype = ctypes.c_char_p
    answer = library.crypt(password.encode(), stored.encode())
    if answer is None or answer.startswith(b"*"):
        raise Refusal("scanner verifier cannot be checked by libcrypt")
    return hmac.compare_digest(answer, stored.encode())


def read_verifier(username):
    result = subprocess.run(
        ["getent", "shadow", username], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, check=False,
    )
    if result.returncode == 2 and not result.stdout:
        return None
    rows = result.stdout.splitlines()
    if result.returncode or len(rows) != 1:
        raise Refusal("scanner account lookup failed")
    fields = rows[0].split(":")
    if len(fields) != 9 or fields[0] != username:
        raise Refusal("scanner account lookup was ambiguous")
    return fields[1]


def reconcile(settings):
    if not isinstance(settings, dict) or set(settings) != {"username", "password", "apply"}:
        raise Refusal("invalid scanner password payload")
    username, password, apply = settings["username"], settings["password"], settings["apply"]
    if not isinstance(username, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username) or username == "root":
        raise Refusal("invalid scanner identity")
    if not isinstance(password, str) or any(char in password for char in "\r\n\0") or password == "CHANGEME":
        raise Refusal("invalid scanner password")
    if type(apply) is not bool:
        raise Refusal("invalid scanner apply selector")
    # Original empty-password behavior deliberately leaves the password alone.
    if not password:
        return "unmanaged"
    stored = read_verifier(username)
    if stored is not None and matches(password, stored):
        return "current"
    if not apply:
        return "missing" if stored is None else "pending"
    if stored is None:
        raise Refusal("scanner account must exist before setting its password")
    result = subprocess.run(
        ["chpasswd"], input=username + ":" + password + "\n", stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, text=True, check=False,
    )
    if result.returncode:
        raise Refusal("scanner password update failed")
    actual = read_verifier(username)
    if actual is None or not matches(password, actual):
        raise Refusal("scanner password update verification failed")
    return "changed"


def main():
    try:
        body = sys.stdin.buffer.read(65537)
        if len(body) > 65536:
            raise Refusal("scanner password payload exceeds size limit")
        result = reconcile(json.loads(body))
    except (ValueError, OSError):
        print("Paperless scanner password check/update failed", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
