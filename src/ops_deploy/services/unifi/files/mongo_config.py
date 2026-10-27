"""Preserve MongoDB data/auth settings; reconcile only role-owned logging knobs."""
import datetime
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def desired(text):
    # Existing initialized Ubuntu installation. Reject ambiguous YAML instead
    # of rewriting storage/replication/authorization settings.
    if "\t" in text or re.search(r"[&*][A-Za-z]", text):
        raise ValueError("unsupported MongoDB YAML")
    text = text if text.endswith("\n") else text + "\n"
    sections = {}
    for name in ("security", "net", "systemLog", "setParameter"):
        matches = list(re.finditer(r"^" + name + r":[ \t]*\n((?:[ \t]+[^\n]*\n|\n|#[^\n]*\n)*)", text, re.M))
        if len(matches) != 1:
            raise ValueError("missing or duplicate MongoDB section")
        sections[name] = matches[0]
    for section, field, value in (("security", "authorization", "enabled"), ("net", "bindIp", "127.0.0.1")):
        found = re.findall(r"^  " + field + r":\s*([^\n#]+)", sections[section][1], re.M)
        if len(found) != 1 or found[0].strip() != value:
            raise ValueError("unsafe stored MongoDB authorization/bind settings")
    changes = {"systemLog": {"quiet": "true", "verbosity": "0"},
               "setParameter": {"suppressNoTLSPeerCertificateWarning": "true", "diagnosticDataCollectionEnabled": "false"}}
    for section, fields in changes.items():
        old = sections[section][0]
        new = old
        for field, value in fields.items():
            pattern = r"^  " + field + r":[^\n]*$"
            count = len(re.findall(pattern, new, re.M))
            if count > 1:
                raise ValueError("duplicate MongoDB setting")
            if count:
                new = re.sub(pattern, "  " + field + ": " + value, new, flags=re.M)
            else:
                header = new[:new.index("\n") + 1]
                new = new.replace(header, header + "  " + field + ": " + value + "\n", 1)
        text = text.replace(old, new, 1)
    return text


def pending(path):
    stamp = subprocess.check_output(["systemctl", "show", "--timestamp=us+utc", "-p", "ActiveEnterTimestamp", "--value", "mongod.service"], text=True).strip()
    start = datetime.datetime.strptime(stamp, "%a %Y-%m-%d %H:%M:%S.%f UTC").replace(tzinfo=datetime.timezone.utc)
    return path.stat().st_mtime_ns > int(start.timestamp() * 1_000_000_000)


def main(mode):
    path = Path("/etc/mongod.conf")
    if path.is_symlink() or not path.is_file():
        raise ValueError("invalid MongoDB config file")
    before = path.read_text()
    after = desired(before)
    if mode == "check":
        print("pending" if before != after or pending(path) else "current")
    elif mode == "apply":
        if before != after:
            info = path.stat()
            fd, temporary = tempfile.mkstemp(prefix=".mongod-", dir=path.parent)
            try:
                with os.fdopen(fd, "w") as output:
                    output.write(after)
                    output.flush()
                    os.fsync(output.fileno())
                    os.fchmod(output.fileno(), info.st_mode & 0o777)
                    os.fchown(output.fileno(), info.st_uid, info.st_gid)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    else:
        raise ValueError("invalid mode")


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except Exception as exc:
        print("MongoDB configuration refused: " + type(exc).__name__, file=sys.stderr)
        sys.exit(1)
