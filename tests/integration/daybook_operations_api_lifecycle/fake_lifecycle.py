"""Synthetic stand-in for Daybook's services/operations_api/lifecycle.py (same CLI, no database).

It keeps the contract the deploys rely on: it must run as the owner of the
0600 config, ``backup`` refuses an existing archive and writes a 0600 tar,
``validate`` reads it, ``restore`` needs --clients-quiesced and both units
stopped and disabled, writes a safety backup and never starts a unit. Every
call is appended to ``<backup_root>/calls.log`` with the effective user.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import subprocess
import tarfile
import uuid
from pathlib import Path

UNITS = ("daybook-operations", "daybook-operations-reconcile")


def log(root: str, *words: str) -> None:
    with open(Path(root) / "calls.log", "a") as stream:
        stream.write(" ".join([pwd.getpwuid(os.geteuid()).pw_name, *words]) + "\n")


def backup(config: dict[str, str], target: str | Path) -> None:
    destination = Path(target)
    if destination.exists():
        raise SystemExit("archive_exists")
    payload = Path(config["backup_root"]) / f".payload-{uuid.uuid4()}"
    payload.write_text(Path(config["profiles"]).read_text())
    with tarfile.open(destination, "w") as archive:
        archive.add(payload, arcname="profiles.json")
    payload.unlink()
    destination.chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("backup", "restore", "validate"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--clients-quiesced", action="store_true")
    args = parser.parse_args()
    path = Path(args.config)
    if path.lstat().st_uid != os.geteuid():
        raise SystemExit("config_not_owner_owned")
    config = json.loads(path.read_text())
    log(config["backup_root"], args.action, args.archive)
    if args.action == "backup":
        backup(config, args.archive)
        return
    with tarfile.open(args.archive) as archive:
        member = archive.extractfile("profiles.json")
        if member is None:
            raise SystemExit("invalid_archive")
        restored = member.read()
    if args.action == "validate":
        return
    if not args.clients_quiesced:
        raise SystemExit("clients_must_be_quiesced")
    for unit in UNITS:
        if subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode not in (3, 4):
            raise SystemExit("services_must_be_stopped")
        if subprocess.run(["systemctl", "is-enabled", "--quiet", unit]).returncode not in (1, 4):
            raise SystemExit("services_must_be_disabled")
    backup(config, Path(config["backup_root"]) / f"before-restore-{uuid.uuid4()}.tar")
    Path(config["profiles"]).write_bytes(restored)


if __name__ == "__main__":
    main()
