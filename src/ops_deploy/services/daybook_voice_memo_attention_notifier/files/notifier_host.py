"""Fixed shared-notifier installation; compile only, never import or send.

Private pins and whole authorized_keys stay in RAM. Existing semantically exact
configuration and authorization bytes are retained. Atomic file publication uses
the already shared Daybook filesystem primitives, injected by the component.
"""

import base64
import json
import os
from pathlib import Path
import re
import stat
import sys

import ops_notifier_filesystem as filesystem

ROOT_UID = 0
ROOT_GID = 0
LOCAL = "/usr/local"
SCRIPT = "/usr/local/libexec/daybook-attention-notify.py"
CONFIG = "/etc/daybook-attention-notify.json"
KEYS = "/root/.ssh/authorized_keys"
DIRECTORIES = {"/usr/local": None, "/usr/local/libexec": 0o755, "/root/.ssh": 0o700}
OPTIONS = 'restrict,command="/usr/bin/python3 -I /usr/local/libexec/daybook-attention-notify.py --config /etc/daybook-attention-notify.json"'
FIELDS = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


class Refused(RuntimeError):
    pass


def identity(info):
    return tuple(getattr(info, name) for name in FIELDS)


def validated(request):
    if not isinstance(request, dict) or set(request) != {"public_key", "native_host", "recipient", "container", "script_base64"}:
        raise Refused("invalid_request")
    if (not all(isinstance(value, str) for value in request.values())
        or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}( [A-Za-z0-9._@-]+)?", request["public_key"])
        or request["native_host"] == "CHANGEME"
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", request["native_host"])
        or not re.fullmatch(r"[1-9][0-9]{4,19}", request["recipient"])
        or request["container"] != "openclaw-gateway"):
        raise Refused("invalid_pins")
    body = base64.b64decode(request["script_base64"], validate=True)
    if not body or len(body) > 131072:
        raise Refused("invalid_source")
    # Equivalent syntax validation to the original py_compile task, without
    # bytecode files or executing any module-level source statement.
    compile(body, SCRIPT, "exec", dont_inherit=True)
    return body


def inspect_directory(path):
    try:
        with filesystem.directory_fd(path) as fd:
            info = os.fstat(fd)
            if info.st_uid != ROOT_UID or info.st_gid != ROOT_GID or stat.S_IMODE(info.st_mode) & 0o022:
                raise Refused("unsafe_directory")
            return identity(info)
    except FileNotFoundError:
        return None


def read(path, limit):
    try:
        with filesystem.directory_fd(Path(path).parent) as parent:
            fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit
                    or before.st_uid != ROOT_UID or before.st_gid != ROOT_GID or stat.S_IMODE(before.st_mode) & 0o022):
                    raise Refused("unsafe_file")
                chunks, remaining = [], limit + 1
                while remaining:
                    part = os.read(fd, min(remaining, 65536))
                    if not part:
                        break
                    chunks.append(part)
                    remaining -= len(part)
                body = b"".join(chunks)
                if (len(body) != before.st_size or identity(before) != identity(os.fstat(fd))
                    or identity(before) != identity(os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False))):
                    raise Refused("changed_during_read")
                return identity(before), body
            finally:
                os.close(fd)
    except FileNotFoundError:
        return None, None


def authorization(body, public_key):
    blob = public_key.split()[1]
    exact = re.compile("^" + re.escape(OPTIONS) + r"[ \t]+ssh-ed25519[ \t]+" + re.escape(blob) + r"([ \t]+.*)?$")
    same_key = re.compile(r"(^|[ \t])ssh-ed25519[ \t]+" + re.escape(blob) + r"([ \t]|$)")
    marker = re.compile(r"(^|[ \t])daybook-attention-notifier([ \t]|$)")
    lines = [line.strip() for line in (body or b"").decode("utf-8").splitlines()]
    live = [line for line in lines if line and not line.startswith("#")]
    if any((same_key.search(line) or marker.search(line)) and not exact.fullmatch(line) for line in live):
        raise Refused("authorization_conflict")
    count = sum(bool(exact.fullmatch(line)) for line in live)
    if count:
        return body
    previous = body or b""
    suffix = b"" if not previous or previous.endswith(b"\n") else b"\n"
    return previous + suffix + (OPTIONS + " ssh-ed25519 " + blob + " daybook-attention-notifier\n").encode()


def snapshot(request):
    script = validated(request)
    directories = {path: inspect_directory(path) for path in DIRECTORIES}
    # /usr/local must already exist; only the two original managed leaf
    # directories may be created. No general parent-tree creation is requested.
    if directories[LOCAL] is None:
        raise Refused("missing_original_parent")
    existing = {path: read(path, 8192 if path == CONFIG else 131072) for path in (SCRIPT, CONFIG, KEYS)}
    pins = {name: request[name] for name in ("native_host", "recipient", "container")}
    config = existing[CONFIG][1]
    try:
        same_config = config is not None and json.loads(config) == pins
    except (ValueError, UnicodeError, RecursionError):
        same_config = False
    desired = {SCRIPT: script, CONFIG: config if same_config else json.dumps(pins, indent=4, sort_keys=True).encode(),
               KEYS: authorization(existing[KEYS][1], request["public_key"])}
    modes = {SCRIPT: 0o755, CONFIG: 0o600, KEYS: 0o600}
    state = {"directories": all(info is not None and (mode is None or stat.S_IMODE(info[4]) == mode)
                                  for path, info in directories.items() for mode in [DIRECTORIES[path]])}
    state.update({name: existing[path][0] is not None and existing[path][1] == desired[path]
                 and stat.S_IMODE(existing[path][0][4]) == modes[path]
                 for name, path in (("script", SCRIPT), ("config", CONFIG), ("authorization", KEYS))})
    return state, existing, desired, modes


def apply(request):
    state, existing, desired, modes = snapshot(request)
    changed = not all(state.values())
    for path, mode in DIRECTORIES.items():
        if mode is not None:
            filesystem.ensure_directory({"path": path, "owner": "root", "group": "root", "mode": mode})
    for path in (SCRIPT, CONFIG, KEYS):
        current = read(path, 8192 if path == CONFIG else 131072)
        if current != existing[path]:
            raise Refused("resource_changed_before_publication")
        info, body = current
        if info is not None and body == desired[path] and stat.S_IMODE(info[4]) == modes[path]:
            continue
        filesystem.put_bytes({"path": path, "owner": "root", "group": "root", "mode": modes[path]}, desired[path], replace=info is not None)
    if not all(snapshot(request)[0].values()):
        raise Refused("post_install_mismatch")
    return {"changed": changed, "category": "shared_notifier_installed"}


def main():
    try:
        if os.geteuid() != 0 or os.uname().sysname != "Linux" or sys.argv[1:] not in (["status"], ["install"]):
            raise Refused("original_root_linux_required")
        raw = sys.stdin.buffer.read(196609)
        if len(raw) > 196608:
            raise Refused("input_bound")
        request = json.loads(raw)
        result = snapshot(request)[0] if sys.argv[1] == "status" else apply(request)
    except Exception:
        print(json.dumps({"error": "shared_notifier_installation_refused"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
