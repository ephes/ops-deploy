"""Verified local package install for an initialized controller."""
import hashlib
import json
import pwd
import re
import os
import subprocess
import sys
from pathlib import Path


DATA = Path("/var/lib/unifi")


def initialize_data(password):
    if not re.fullmatch(r"[A-Za-z0-9._~-]+", password) or "CHANGEME" in password:
        raise ValueError("invalid database credential")
    account = pwd.getpwnam("unifi")
    uri = f"mongodb://unifi:{password}@127.0.0.1:27017/"
    content = (
        "db.mongo.local=false\n"
        f"db.mongo.uri={uri}unifi?authSource=admin\n"
        "unifi.db.name=unifi\n"
    )
    # Exclusive creation: never rewrite or adopt any existing controller data.
    DATA.mkdir(mode=0o750)
    os.chown(DATA, account.pw_uid, account.pw_gid)
    fd = os.open(DATA / "system.properties", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        os.fchown(output.fileno(), account.pw_uid, account.pw_gid)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def main(path, version, digest, initial=None):
    package = Path(path)
    if not package.is_file() or package.is_symlink():
        raise ValueError("invalid package file")
    if hashlib.sha256(package.read_bytes()).hexdigest() != digest:
        raise ValueError("package digest mismatch")
    info = subprocess.check_output(["dpkg-deb", "-f", path, "Package", "Version", "Architecture"], text=True)
    if dict(line.split(": ", 1) for line in info.splitlines()) != {
        "Package": "unifi", "Version": version, "Architecture": "all"
    }:
        raise ValueError("package metadata mismatch")
    query = subprocess.run(["dpkg-query", "-W", "-f=${Version}", "unifi"], text=True, capture_output=True)
    if query.returncode not in (0, 1) or (query.returncode == 1 and query.stdout):
        raise ValueError("installed package query failed")
    current = query.stdout.strip()
    initialize = bool(initial and initial["initialize"])
    if initialize and (current or DATA.exists() or DATA.is_symlink()):
        raise ValueError("controller/data appeared after admission")
    if current and subprocess.run(["dpkg", "--compare-versions", version, "lt", current]).returncode == 0:
        raise ValueError("controller downgrades are unsupported")
    # Existing initialized installs already have the custom unit and private
    # MongoDB argfile. The package's normal postinst may start that unit; the
    # deployment subsequently reconciles it and performs the required rollout.
    # No machine-wide policy-rc.d is installed or replaced.
    subprocess.run(["systemctl", "stop", "unifi.service"], check=True)
    if initialize:
        # Digest and dpkg metadata have both passed. Do not create controller
        # data before a failed download/verification can safely be retried.
        initialize_data(initial["mongodb_password"])
    subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", path], check=True,
                   env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
    installed = subprocess.check_output(["dpkg-query", "-W", "-f=${db:Status-Abbrev}|${Version}", "unifi"], text=True)
    if installed != "ii |" + version:
        raise ValueError("package installation verification failed")



if __name__ == "__main__":
    try:
        main(*sys.argv[1:], initial=json.load(sys.stdin))
    except Exception as exc:
        print("UniFi package installation failed: " + type(exc).__name__, file=sys.stderr)
        sys.exit(1)
