"""Original recursive default ACL semantics with status-only stdout.

Uses the same setfacl --test predicate as ansible.posix.acl: an unchanged line
ends in '*,*'. The utility necessarily visits descendant filesystem metadata;
its path/ACL output stays inside this process and is never returned or logged.
No document contents are read. There is no separate tree-size/time limit, as in
the original role; the live observer must not repeat this walk for its snapshot.
"""

import json
import os
import re
import stat
import subprocess
import sys


class Refusal(ValueError):
    pass


def command(settings):
    if not isinstance(settings, dict) or set(settings) != {"directory", "username", "apply"}:
        raise Refusal("invalid scanner ACL payload")
    directory, username = settings["directory"], settings["username"]
    if not isinstance(directory, str) or not re.fullmatch(r"(?:/[A-Za-z0-9_.+-]+)+", directory):
        raise Refusal("invalid scanner ACL root")
    if any(part in {".", ".."} for part in directory.split("/")[1:]):
        raise Refusal("invalid scanner ACL root")
    if not isinstance(username, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username) or username == "root":
        raise Refusal("invalid scanner identity")
    if type(settings["apply"]) is not bool:
        raise Refusal("invalid scanner ACL apply selector")
    return ["setfacl", "-d", "-m", "user:" + username + ":rwx", "--recursive", directory]


def would_change(argv):
    changed = False
    count = 0
    # Stream and discard path-bearing lines. Bound each read without building a
    # recursive output/tree inventory in memory or exposing names to callers.
    with subprocess.Popen(
        [argv[0], "--test", *argv[1:]], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ) as process:
        if process.stdout is None:
            raise Refusal("scanner ACL probe has no output pipe")
        while True:
            line = process.stdout.readline(1024 * 1024 + 1)
            if not line:
                break
            if len(line) > 1024 * 1024:
                process.kill()
                process.wait()
                raise Refusal("scanner ACL output line exceeds limit")
            line = line.strip()
            if line and not line.startswith(b"#"):
                count += 1
                if not line.endswith(b"*,*"):
                    changed = True
        if process.wait() or not count:
            raise Refusal("scanner ACL probe failed")
    return changed


def reconcile(settings):
    argv = command(settings)
    try:
        mode = os.lstat(settings["directory"]).st_mode
    except FileNotFoundError:
        if settings["apply"]:
            raise Refusal("scanner consume directory must exist before ACL application") from None
        return "missing"
    if not stat.S_ISDIR(mode):
        raise Refusal("scanner consume root must be a real directory")
    if not would_change(argv):
        return "current"
    if not settings["apply"]:
        return "pending"
    result = subprocess.run(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    if result.returncode:
        raise Refusal("scanner ACL update failed")
    if would_change(argv):
        raise Refusal("scanner ACL remains pending after update")
    return "changed"


def main():
    try:
        payload = sys.stdin.buffer.read(65537)
        if len(payload) > 65536:
            raise Refusal("scanner ACL payload exceeds size limit")
        result = reconcile(json.loads(payload))
    except (ValueError, OSError):
        print("Paperless scanner ACL check/update failed", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
