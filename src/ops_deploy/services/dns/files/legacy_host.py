"""Remove only the six obsolete DNS-role DNAT rules, never general firewall state."""

import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile


def owned(tokens, family):
    if tokens[:2] != ["-A", "PREROUTING"]:
        return False
    pairs = tokens[2:]
    if len(pairs) % 2:
        return False
    options = {}
    for flag, value in zip(pairs[::2], pairs[1::2]):
        if flag in options or flag not in {"-s", "-p", "-m", "--dport", "-j", "--to-destination"}:
            return False
        options[flag] = value
    proto = options.get("-p")
    if proto not in ("tcp", "udp") or options.get("-m", proto) != proto:
        return False
    if options.get("--dport") != "53" or options.get("-j") != "DNAT":
        return False
    if family == 4:
        return options.get("-s") in (None, "100.64.0.0/10") and options.get("--to-destination") == "127.0.0.1:5335"
    return options.get("-s") == "fd7a:115c:a1e0::/48" and options.get("--to-destination") == "[::1]:5335"


def filter_rules(text, family):
    retained, removed = [], []
    table = None
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("*"):
            table = stripped[1:]
        elif stripped == "COMMIT":
            table = None
        tokens = shlex.split(stripped) if stripped.startswith("-A ") else []
        if table == "nat" and owned(tokens, family):
            removed.append(tokens)
        else:
            retained.append(line)
    return "".join(retained), removed


def runtime(family):
    tool = "iptables" if family == 4 else "ip6tables"
    binary, save = shutil.which(tool), shutil.which(tool + "-save")
    if binary is None and save is None:
        return tool, [], "tools-absent"
    if binary is None or save is None:
        raise ValueError("incomplete firewall tooling")
    result = subprocess.run([save, "-t", "nat"], text=True, capture_output=True)
    if result.returncode:
        # Missing kernel/table support is a known absence, permission/backend
        # failures are not interpreted as an empty ruleset.
        message = result.stderr.lower()
        if "table does not exist" in message or "table `nat' does not exist" in message:
            return tool, [], "nat-table-absent"
        raise ValueError("cannot read firewall NAT table")
    return tool, filter_rules(result.stdout, family)[1], "present"


def main(apply=False):
    plans = []
    for family in (4, 6):
        tool, rules, presence = runtime(family)
        path = Path("/etc/iptables/rules.v" + str(family))
        content = None
        metadata = None
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError("persistent firewall rules must be regular files")
        if path.exists():
            original = path.read_text()
            filtered, removed = filter_rules(original, family)
            if removed:
                content = filtered
                metadata = path.stat()
        plans.append((tool, rules, path, content, metadata, presence))
    changed = any(rules or content is not None for _, rules, _, content, _, _ in plans)
    if not changed or not apply:
        print("changed=" + str(changed).lower())
        return
    # Both families and persistent inputs were admitted before the first mutation.
    for tool, rules, path, content, metadata, _ in plans:
        for rule in rules:
            subprocess.run([tool, "-t", "nat", "-D", *rule[1:]], check=True, capture_output=True)
        if content is not None:
            fd, temporary = tempfile.mkstemp(prefix=".dns-legacy-", dir=path.parent)
            try:
                with os.fdopen(fd, "w") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                    os.fchmod(handle.fileno(), stat.S_IMODE(metadata.st_mode))
                    os.fchown(handle.fileno(), metadata.st_uid, metadata.st_gid)
                os.replace(temporary, path)
            finally:
                Path(temporary).unlink(missing_ok=True)
    print("changed=true")


if __name__ == "__main__":
    try:
        main(json.load(sys.stdin).get("apply", False))
    except Exception:
        print("DNS legacy rule admission/removal failed; unrelated rules were not selected", file=sys.stderr)
        sys.exit(1)
