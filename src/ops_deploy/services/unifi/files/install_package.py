"""Verified local package install for an initialized controller."""
import hashlib
import os
import subprocess
import sys
from pathlib import Path


def main(path, version, digest):
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
    if current and subprocess.run(["dpkg", "--compare-versions", version, "lt", current]).returncode == 0:
        raise ValueError("controller downgrades are unsupported")
    # Existing initialized installs already have the custom unit and private
    # MongoDB argfile. The package's normal postinst may start that unit; the
    # deployment subsequently reconciles it and performs the required rollout.
    # No machine-wide policy-rc.d is installed or replaced.
    subprocess.run(["systemctl", "stop", "unifi.service"], check=True)
    subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", path], check=True,
                   env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
    installed = subprocess.check_output(["dpkg-query", "-W", "-f=${db:Status-Abbrev}|${Version}", "unifi"], text=True)
    if installed != "ii |" + version:
        raise ValueError("package installation verification failed")



if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except Exception as exc:
        print("UniFi package installation failed: " + type(exc).__name__, file=sys.stderr)
        sys.exit(1)
