"""Own one bounded offline KVM child and collect only its synthetic evidence."""

from __future__ import annotations

import json
import os
import re
import resource
import socket
import stat
import subprocess
import time
from pathlib import Path
from typing import Protocol


class QmpStream(Protocol):
    def readline(self) -> bytes: ...
    def write(self, data: bytes, /) -> int: ...
    def flush(self) -> None: ...


def query_kvm(stream: QmpStream) -> dict[str, bool]:
    greeting = json.loads(stream.readline())
    if "QMP" not in greeting:
        raise RuntimeError("missing QMP greeting")
    for identifier, command in (("capabilities", "qmp_capabilities"), ("native", "query-kvm")):
        stream.write((json.dumps({"execute": command, "id": identifier}) + "\n").encode())
        stream.flush()
        for _ in range(32):
            reply = json.loads(stream.readline())
            if reply.get("id") == identifier:
                break
        else:
            raise RuntimeError("QMP command did not return its identified result")
        if "error" in reply or "return" not in reply:
            raise RuntimeError("QMP command failed")
    result = reply["return"]
    if result != {"enabled": True, "present": True} or any(type(value) is not bool for value in result.values()):
        raise RuntimeError("KVM is not both present and enabled")
    return {"enabled": True, "present": True}


def evidence_entries(table: str) -> dict[str, int]:
    """debugfs ls -p metadata: admit only bounded flat regular receipt files."""
    entries = {}
    for line in table.splitlines():
        if not line:
            continue
        fields = line.split("/")
        if len(fields) != 8 or fields[0] or fields[-1]:
            raise RuntimeError("malformed guest evidence metadata")
        if fields[1] == "0" or fields[5] in (".", ".."):
            continue
        name = fields[5]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
            raise RuntimeError("unsafe guest evidence filename")
        if not stat.S_ISREG(int(fields[2], 8)) or name in entries:
            raise RuntimeError("guest evidence is not a unique flat regular file")
        size = int(fields[6])
        if size < 0:
            raise RuntimeError("invalid guest evidence size")
        entries[name] = size
    if len(entries) > 1024 or sum(entries.values()) > 192 * 1024 * 1024:
        raise RuntimeError("guest evidence exceeds its pre-extraction bound")
    return entries


def extract_evidence(evidence: Path) -> None:
    def limit_table() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))

    disk = "/work/rootfs.raw"
    table = evidence / "guest-directory.txt"
    with table.open("wb") as output, (evidence / "extract.log").open("wb") as errors:
        subprocess.run(
            ["debugfs", "-R", "ls -p /var/tmp/minio-evidence", disk],
            stdout=output,
            stderr=errors,
            timeout=30,
            check=True,
            preexec_fn=limit_table,
        )
    entries = evidence_entries(table.read_text())
    guest = evidence / "guest/minio-evidence"
    guest.mkdir(parents=True, exist_ok=True)
    for name, size in entries.items():

        def limit_dump(bound: int = max(size, 1024 * 1024)) -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (bound, bound))

        target = guest / name
        with (evidence / "extract.log").open("ab") as errors:
            subprocess.run(
                ["debugfs", "-R", f"dump /var/tmp/minio-evidence/{name} {target}", disk],
                stdout=errors,
                stderr=errors,
                timeout=30,
                check=True,
                preexec_fn=limit_dump,
            )
        if target.is_symlink() or not target.is_file() or target.stat().st_size != size:
            raise RuntimeError("extracted guest receipt differs from admitted metadata")


def main() -> None:
    owned = os.environ["MINIO_OWNED_ID"]
    if len(owned) != 16 or any(char not in "0123456789abcdef" for char in owned):
        raise RuntimeError("invalid owned identifier")
    evidence = Path("/evidence")
    command = [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-smp",
        "2",
        "-m",
        "4096",
        "-nodefaults",
        "-no-user-config",
        "-no-reboot",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "file:/evidence/serial.log",
        "-nic",
        "none",
        "-qmp",
        "unix:/work/qmp.sock,server=on,wait=off",
        "-kernel",
        "/work/vmlinuz",
        "-initrd",
        "/work/initrd",
        "-append",
        f"root=/dev/vda rootfstype=ext4 rw console=ttyS0 panic=1 ops_minio_owned={owned}",
        "-drive",
        "file=/work/rootfs.raw,format=raw,if=none,id=root,cache=none",
        "-device",
        "virtio-blk-pci,drive=root",
        "-device",
        "virtio-scsi-pci,id=scsi",
        "-drive",
        "file=/work/input.iso,format=raw,if=none,id=input,media=cdrom,readonly=on",
        "-device",
        "scsi-cd,drive=input",
    ]
    started = time.monotonic()
    with (evidence / "qemu.log").open("wb") as log:
        child = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                for _ in range(60):
                    try:
                        connection.connect("/work/qmp.sock")
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        if child.poll() is not None:
                            raise RuntimeError("QEMU exited before KVM query") from None
                        time.sleep(0.5)
                else:
                    raise RuntimeError("QMP connection timed out")
                with connection.makefile("rwb") as stream:
                    native = query_kvm(stream)
            (evidence / "kvm.json").write_text(json.dumps(native))
            while child.poll() is None:
                if time.monotonic() - started > 45 * 60:
                    raise RuntimeError("owned KVM runtime exceeded 45 minutes")
                for name in ("serial.log", "qemu.log"):
                    path = evidence / name
                    if path.exists() and path.stat().st_size > 16 * 1024 * 1024:
                        raise RuntimeError("owned KVM log exceeded 16 MiB")
                time.sleep(1)
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=10)
            (evidence / "qemu-exit").write_text(str(child.returncode) + "\n")
            extract_evidence(evidence)
        if child.returncode != 0:
            raise RuntimeError("owned KVM guest failed")
    guest = evidence / "guest/minio-evidence"
    if json.loads((guest / "guest-exit.json").read_text())["exit"] != 0:
        raise RuntimeError("owned guest entry failed")
    if json.loads((guest / "summary.json").read_text())["success"] is not True:
        raise RuntimeError("owned MinIO fixture failed")
    if sum(path.stat().st_size for path in evidence.rglob("*") if path.is_file()) > 256 * 1024 * 1024:
        raise RuntimeError("owned evidence exceeded 256 MiB")


if __name__ == "__main__":
    main()
