"""Owned native qualification of encrypted_volume, never inventory traffic.

Runs as root on a disposable GitHub-hosted Ubuntu 24.04 x86 VM (see run.sh) with
the immutable installed ops-deploy package. Every secret is generated here.
Phases: encrypted_volume fresh / repeat / closed->open / restored lines / option
change (remount) / keyfile drift / eight refusals / recovery / Ansible role after
pyinfra. Repeats and refusals run every command under strace and fail on any
write. (The open_webui phases went with ops_deploy.services.open_webui when
Open WebUI was retired on 2026-11-09.)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import traceback
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest.mock import patch

EVIDENCE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/var/tmp/linuxev-evidence")
WORK = Path("/var/tmp/linuxev")
MOUNT = "/mnt/cryptdata"
KEYFILE = "/root/.luks-key-cryptdata"
PASSPHRASE = secrets.token_hex(24)
UNRELATED_CRYPTTAB = "fixture-unrelated UUID=00000000-0000-4000-8000-000000000000 none luks,noauto\n"
OPS_LIBRARY_SHA = "cf3a0c74b10ed83a43fa79c4d1f3a57fffc89641"
ANSIBLE_PACKAGE = "ansible==14.5.0"
SUMMARY: dict[str, Any] = {"phases": []}


def sh(*args: str, stdin: str | None = None, check: bool = True, timeout: int = 900, cwd: str | None = None) -> str:
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=timeout, cwd=cwd)
    if check and result.returncode:
        raise RuntimeError(f"fixture command failed ({result.returncode}): {args[0]} {result.stderr[-2000:]}")
    return result.stdout.strip()


def record(name: str, data: Any) -> None:
    (EVIDENCE / name).write_text(json.dumps(data, indent=2, default=str))


def file_state(path: str) -> list[Any] | None:
    p = Path(path)
    if not os.path.lexists(p):
        return None
    st = p.lstat()
    digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink() else None
    link = os.readlink(p) if p.is_symlink() else None
    return [digest, link, st.st_mode, st.st_uid, st.st_gid, st.st_mtime_ns, st.st_ino]


def mounted_line() -> str:
    line = mountinfo()
    assert line is not None, f"{MOUNT} is not mounted"
    return line


def mountinfo() -> str | None:
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        if line.split()[4] == MOUNT:
            return line
    return None


def ev_snapshot() -> dict[str, Any]:
    paths = ["/etc/crypttab", "/etc/fstab", KEYFILE, "/root", MOUNT, f"{MOUNT}/fixture-marker"]
    return {
        **{path: file_state(path) for path in paths},
        "mountinfo": mountinfo(),
        "mapper": os.path.exists("/dev/mapper/cryptdata"),
    }


WRITE_SYSCALL = re.compile(
    r"^(?:[0-9]+\s+)?(?:open|openat|openat2|creat)\(.*(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)|"
    r"^(?:[0-9]+\s+)?(?:mkdir|mkdirat|unlink|unlinkat|rename|renameat|renameat2|chmod|fchmod|fchmodat|fchmodat2|chown|"
    r"lchown|fchown|fchownat|utime|utimes|utimensat|symlink|symlinkat|link|linkat|truncate|ftruncate|mount|umount2)\("
)


def trace_writes(text: str) -> list[str]:
    writes = []
    for line in text.splitlines():
        if not WRITE_SYSCALL.search(line):
            continue
        if '"/dev/null"' in line:
            continue
        if re.search(r'openat\(AT_FDCWD, "/dev/tty", O_RDWR\|O_NONBLOCK\) = -1 ENXIO', line):
            continue
        writes.append(line)
    return writes


def executed(text: str) -> list[list[str]]:
    """argv of every successful execve in a trace (also when strace split the call)."""

    found = []
    pending: dict[str, list[str]] = {}
    for line in text.splitlines():
        call = re.match(r'^(\d+) execve\("[^"]+", \[(.*?)\], ', line)
        if call:
            argv = re.findall(r'"((?:[^"\\]|\\.)*)"', call.group(2))
            if line.endswith(" = 0"):
                found.append(argv)
            elif line.endswith("<unfinished ...>"):
                pending[call.group(1)] = argv
            continue
        resumed = re.match(r"^(\d+) <\.\.\. execve resumed>.* = (-?\d+)", line)
        if resumed and resumed.group(1) in pending:
            argv = pending.pop(resumed.group(1))
            if resumed.group(2) == "0":
                found.append(argv)
    return found


def run_deploy(
    label: str,
    fn: Any,
    *,
    zero: bool = False,
    trace: bool = False,
    error: str | None = None,
    snapshot: Any = ev_snapshot,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run one deploy on @local. ``zero``: every command traced, no write, no mutation, nothing changed."""

    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.command import QuoteString, StringCommand
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops
    from pyinfra.connectors.local import LocalConnector

    from ops_deploy.testing.harness import collect_ops

    before = snapshot()
    original = LocalConnector.run_shell_command
    counter = 0
    traces: list[str] = []

    def traced(self: Any, command: Any, **kw: Any) -> Any:
        nonlocal counter
        counter += 1
        path = EVIDENCE / "traces" / f"{label}-{counter}.strace"
        raw = command if isinstance(command, str) else str(command.get_raw_value())
        wrapped = StringCommand(
            "strace", "-f", "-s", "4096", "-e", "trace=file,process,fchmod,fchown,ftruncate,mount,umount2",
            "-o", str(path), "sh", "-c", QuoteString(raw),
        )  # fmt: skip
        result = original(self, wrapped, **kw)
        traces.append(path.read_text())
        return result

    def no_upload(*args: Any, **kw: Any) -> None:
        raise AssertionError("a zero-write run uploaded a file")

    patches = []
    if zero or trace:
        patches.append(patch.object(LocalConnector, "run_shell_command", traced))
    if zero:
        patches.append(patch.object(LocalConnector, "put_file", no_upload))
    for item in patches:
        item.start()
    state = State(Inventory(([("@local", {})], {})), Config())
    failure = None
    started = time.monotonic()
    try:
        connect_all(state)
        add_deploy(state, fn, **kwargs)
        run_ops(state)
    except Exception:
        failure = traceback.format_exc()
    finally:
        ops = collect_ops(state, "@local")
        disconnect_all(state)
        for item in reversed(patches):
            item.stop()
    writes = [w for t in traces for w in trace_writes(t)]
    entry = {
        "label": label,
        "seconds": round(time.monotonic() - started, 1),
        "error": failure,
        "operations": [asdict(o) for o in ops],
        "mutations": [o.name for o in ops if o.changed and not o.read_only],
        "failed": [o.name for o in ops if not o.succeeded],
        "state_unchanged": before == snapshot(),
        "traced_commands": len(traces),
        "trace_writes": writes if (zero or trace) else None,
    }
    record(f"{label}.json", entry)
    SUMMARY["phases"].append({k: entry[k] for k in ("label", "seconds", "mutations", "state_unchanged")})
    entry["traces"] = traces
    if error is None:
        assert failure is None, entry
        assert all(o.succeeded for o in ops), entry
    else:
        assert failure is not None, entry
        assert error in failure or any(error in name for name in entry["failed"]), entry
    if zero:
        assert not entry["mutations"], entry
        assert entry["state_unchanged"], entry
        assert not writes, writes
    return entry


# -- encrypted volume fixture ---------------------------------------------------------------


def luks_image(name: str, size: str, fs: bool) -> tuple[str, str]:
    image = WORK / f"{name}.img"
    sh("truncate", "-s", size, str(image))
    loop = sh("losetup", "--find", "--show", str(image))
    args = ["--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"]
    sh("cryptsetup", "luksFormat", *args, "--key-file", "-", loop, stdin=PASSPHRASE)
    if fs:
        sh("cryptsetup", "open", "--key-file", "-", loop, "fixture-setup", stdin=PASSPHRASE)
        sh("mkfs.ext4", "-q", "/dev/mapper/fixture-setup")
        staging = WORK / "staging"
        staging.mkdir()
        sh("mount", "/dev/mapper/fixture-setup", str(staging))
        (staging / "fixture-marker").write_text(secrets.token_hex(32))
        sh("umount", str(staging))
        staging.rmdir()
        sh("cryptsetup", "close", "fixture-setup")
    return loop, sh("cryptsetup", "luksUUID", loop)


def setup_volume() -> dict[str, str]:
    WORK.mkdir(mode=0o700)
    (EVIDENCE / "traces").mkdir(mode=0o700)
    loop, uuid = luks_image("cryptdata", "512M", fs=True)
    other, other_uuid = luks_image("other", "32M", fs=False)
    plain_image = WORK / "plain.img"
    sh("truncate", "-s", "32M", str(plain_image))
    sh("mkfs.ext4", "-q", str(plain_image))
    plain = sh("losetup", "--find", "--show", str(plain_image))
    crypttab = Path("/etc/crypttab")
    crypttab.write_text((crypttab.read_text() if crypttab.exists() else "") + UNRELATED_CRYPTTAB)
    os.chmod(crypttab, 0o644)
    fstab = Path("/etc/fstab")
    fstab.write_text(fstab.read_text() + "# fixture: unrelated comment kept as is\n")
    # The deploy installs cryptsetup itself.
    sh("apt-get", "remove", "-y", "cryptsetup-bin", "cryptsetup")
    assert shutil.which("cryptsetup") is None
    return {"loop": loop, "uuid": uuid, "other": other, "other_uuid": other_uuid, "plain": plain}


def ev_config(dev: dict[str, str], **fields: Any) -> Any:
    from ops_deploy.infra import EncryptedVolumeConfig

    return EncryptedVolumeConfig(**{"device": dev["loop"], "expected_luks_uuid": dev["uuid"], **fields})


def ev(label: str, cfg: Any, **options: Any) -> dict[str, Any]:
    from pydantic import SecretStr

    from ops_deploy.infra import deploy_encrypted_volume

    options.setdefault("snapshot", ev_snapshot)
    return run_deploy(label, deploy_encrypted_volume, cfg=cfg, passphrase=SecretStr(PASSPHRASE), **options)


def our_lines(dev: dict[str, str]) -> tuple[str, str]:
    fs_uuid = sh("blkid", "-p", "-s", "UUID", "-o", "value", "/dev/mapper/cryptdata")
    return (
        f"cryptdata {dev['loop']} {KEYFILE} luks\n",
        f"UUID={fs_uuid} {MOUNT} ext4 defaults,noatime 0 0\n",
    )


def without(path: str, line: str) -> None:
    text = Path(path).read_text()
    assert text.count(line) == 1, (path, line)
    Path(path).write_text(text.replace(line, ""))


def apply_name(entry: dict[str, Any]) -> list[str]:
    return [m for m in entry["mutations"] if "Open, record and mount" in m]


def mount_execs(entry: dict[str, Any]) -> list[list[str]]:
    return [argv for t in entry["traces"] for argv in executed(t) if argv and Path(argv[0]).name in ("mount", "umount")]


def shell_transport(label: str, command: str) -> None:
    """The wire command (``sh -c '...'``) gives the same answer through fish (root's shell on macmini) and bash."""

    from pyinfra.api.command import StringCommand
    from pyinfra.connectors.util import make_unix_command

    wire = make_unix_command(StringCommand(command)).get_raw_value()
    answers = {
        shell: subprocess.run([shell, "-c", wire], capture_output=True, text=True, timeout=120)
        for shell in ("bash", "fish")
    }
    assert all(a.returncode == 0 for a in answers.values()), {k: v.stderr for k, v in answers.items()}
    assert answers["bash"].stdout == answers["fish"].stdout, {k: v.stdout for k, v in answers.items()}
    record(f"{label}-transport.json", {"bash": answers["bash"].stdout, "fish_equal": True})


def encrypted_volume_phases(dev: dict[str, str]) -> None:
    from ops_deploy.infra.encrypted_volume import host_command

    cfg = ev_config(dev)
    fstab_before = Path("/etc/fstab").read_text()
    crypttab_before = Path("/etc/crypttab").read_text()

    fresh = ev("ev-fresh", cfg)
    for name in (
        "Install cryptsetup",
        "Write the keyfile",
        f"Ensure the mount point {MOUNT}",
        "Open, record and mount",
    ):
        assert any(name in m for m in fresh["mutations"]), (name, fresh["mutations"])
    crypt_line, fstab_line = our_lines(dev)
    assert Path("/etc/crypttab").read_text() == crypttab_before + crypt_line
    assert Path("/etc/fstab").read_text() == fstab_before + fstab_line
    assert Path(KEYFILE).read_bytes() == PASSPHRASE.encode()
    assert oct(Path(KEYFILE).stat().st_mode & 0o7777) == "0o400"
    assert oct(Path("/etc/crypttab").stat().st_mode & 0o7777) == "0o640"
    assert " rw," in mounted_line() + ","
    assert "noatime" in mounted_line()
    marker = Path(f"{MOUNT}/fixture-marker").read_text()
    ev("ev-repeat", cfg, zero=True)
    shell_transport("ev-check", host_command(cfg, "check"))

    # Closed mapper: opened and mounted again, recorded lines untouched.
    sh("umount", MOUNT)
    sh("cryptsetup", "close", "cryptdata")
    files = {p: file_state(p) for p in ("/etc/crypttab", "/etc/fstab", KEYFILE)}
    reopen = ev("ev-reopen", cfg, trace=True)
    assert len(apply_name(reopen)) == 1, reopen["mutations"]
    assert len(reopen["mutations"]) == 1, reopen["mutations"]
    assert {p: file_state(p) for p in files} == files
    assert Path(f"{MOUNT}/fixture-marker").read_text() == marker
    assert [a[:2] for a in mount_execs(reopen)] == [["mount", MOUNT]], mount_execs(reopen)
    ev("ev-reopen-repeat", cfg, zero=True)

    # Lost lines: restored next to the unrelated ones, without a remount.
    without("/etc/crypttab", crypt_line)
    without("/etc/fstab", fstab_line)
    mounted = mountinfo()
    restore = ev("ev-restore-lines", cfg, trace=True)
    assert len(apply_name(restore)) == 1, restore["mutations"]
    assert Path("/etc/crypttab").read_text() == crypttab_before + crypt_line
    assert Path("/etc/fstab").read_text() == fstab_before + fstab_line
    assert mount_execs(restore) == []
    assert mountinfo() == mounted
    ev("ev-restore-repeat", cfg, zero=True)

    # Changed options: the entry is rewritten and only remounted (same mount, new options).
    Path("/etc/fstab").write_text(
        Path("/etc/fstab").read_text().replace(fstab_line, fstab_line.replace("defaults,noatime", "defaults"))
    )
    sh("mount", "-o", "remount,relatime", MOUNT)
    mount_id = mounted_line().split()[0]
    remount = ev("ev-remount", cfg, trace=True)
    assert Path("/etc/fstab").read_text() == fstab_before + fstab_line
    assert [a[:3] for a in mount_execs(remount)] == [["mount", "-o", "remount"]], mount_execs(remount)
    assert mounted_line().split()[0] == mount_id
    assert "noatime" in mounted_line()
    ev("ev-remount-repeat", cfg, zero=True)

    # Keyfile drift: only the keyfile is rewritten.
    Path(KEYFILE).chmod(0o600)
    Path(KEYFILE).write_text("drifted")
    Path(KEYFILE).chmod(0o644)
    keyfile = ev("ev-keyfile", cfg)
    assert keyfile["mutations"] == [m for m in keyfile["mutations"] if "Write the keyfile" in m]
    assert keyfile["mutations"]
    assert Path(KEYFILE).read_bytes() == PASSPHRASE.encode()
    assert oct(Path(KEYFILE).stat().st_mode & 0o7777) == "0o400"
    ev("ev-keyfile-repeat", cfg, zero=True)

    # Refusals: nothing written, nothing executed beyond read-only probes.
    refusals = []

    def refuse(label: str, reason: str, config: Any = cfg) -> None:
        ev(label, config, zero=True, error=reason)
        refusals.append({"label": label, "reason": reason})

    refuse("ev-refuse-uuid", "LUKS UUID mismatch", ev_config(dev, expected_luks_uuid=dev["other_uuid"]))
    refuse("ev-refuse-not-luks", "is not a LUKS container", ev_config(dev, device=dev["plain"]))
    refuse("ev-refuse-missing", "is missing", ev_config(dev, device="/dev/linuxev-missing"))
    sh("mount", "-o", "remount,ro", MOUNT)
    refuse("ev-refuse-read-only", "is mounted read-only")
    sh("mount", "-o", "remount,rw", MOUNT)
    Path("/etc/fstab").write_text(Path("/etc/fstab").read_text() + fstab_line)
    refuse("ev-refuse-duplicate-fstab", "has 2 entries")
    Path("/etc/fstab").write_text(fstab_before + fstab_line)
    sh("umount", MOUNT)
    sh("cryptsetup", "close", "cryptdata")
    sh("cryptsetup", "open", "--key-file", "-", dev["other"], "cryptdata", stdin=PASSPHRASE)
    refuse("ev-refuse-mapper-elsewhere", "is open on")
    sh("cryptsetup", "close", "cryptdata")
    sh("cryptsetup", "open", "--key-file", "-", dev["loop"], "fixture-conflict", stdin=PASSPHRASE)
    refuse("ev-refuse-mapped-elsewhere", "is already mapped as /dev/mapper/fixture-conflict")
    sh("cryptsetup", "close", "fixture-conflict")
    Path("/etc/fstab").write_text(fstab_before + fstab_line + fstab_line)
    refuse("ev-refuse-duplicate-fstab-closed", "has 2 entries")
    Path("/etc/fstab").write_text(fstab_before + fstab_line)
    sh("mount", "-t", "tmpfs", "-o", "size=1m", "linuxev-foreign", MOUNT)
    refuse("ev-refuse-foreign-mount", "while /dev/mapper/cryptdata is closed")
    sh("umount", MOUNT)
    record("ev-refusals.json", refusals)

    recovery = ev("ev-recovery", cfg)
    assert len(apply_name(recovery)) == 1
    assert Path(f"{MOUNT}/fixture-marker").read_text() == marker
    ev("ev-final-repeat", cfg, zero=True)


# -- the Ansible role after pyinfra -----------------------------------------------------------


def ansible_setup() -> dict[str, str]:
    uv = os.environ["UV_BIN"]
    venv = WORK / "ansible"
    sh(uv, "venv", "--python", "3.12", str(venv))
    sh(uv, "pip", "install", "--python", str(venv), ANSIBLE_PACKAGE)
    archive = WORK / "ops-library.tar.gz"
    sh("curl", "-fsSL", "-o", str(archive), f"https://codeload.github.com/ephes/ops-library/tar.gz/{OPS_LIBRARY_SHA}")
    target = WORK / "collections" / "ansible_collections" / "local" / "ops_library"
    target.mkdir(parents=True)
    with tarfile.open(archive) as bundle:
        top = f"ops-library-{OPS_LIBRARY_SHA}/"
        members = [m for m in bundle.getmembers() if m.name.startswith(top) and "/rust/" not in m.name]
        for member in members:
            member.name = member.name[len(top) :]
        bundle.extractall(target, members=[m for m in members if m.name], filter="data")
    version = sh(str(venv / "bin" / "ansible-playbook"), "--version").splitlines()[0]
    info = {
        "ansible": ANSIBLE_PACKAGE,
        "ansible_playbook": version,
        "ops_library": OPS_LIBRARY_SHA,
        "ops_library_tarball_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    }
    record("ansible.json", info)
    return info


def ansible(label: str, play: list[dict[str, Any]], extra: dict[str, Any]) -> dict[str, Any]:
    play_path = WORK / f"{label}.yml"
    vars_path = WORK / f"{label}.vars.json"
    play_path.write_text(json.dumps(play))
    fd = os.open(vars_path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(extra, stream)
    env = {
        **os.environ,
        "ANSIBLE_COLLECTIONS_PATH": str(WORK / "collections"),
        "ANSIBLE_STDOUT_CALLBACK": "json",
        "ANSIBLE_LOCALHOST_WARNING": "False",
        "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
        "ANSIBLE_RETRY_FILES_ENABLED": "False",
        "ANSIBLE_HOME": str(WORK / "ansible-home"),
        "ANSIBLE_LOCAL_TEMP": str(WORK / "ansible-tmp"),
        "ANSIBLE_REMOTE_TEMP": str(WORK / "ansible-tmp"),
        "ANSIBLE_PYTHON_INTERPRETER": "/usr/bin/python3",
    }
    playbook = str(WORK / "ansible" / "bin" / "ansible-playbook")
    argv = [playbook, "-i", "localhost,", "-c", "local", str(play_path), "-e", f"@{vars_path}"]
    result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=1200)
    vars_path.unlink()
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    out = json.loads(result.stdout)
    tasks = [
        {"task": task["task"]["name"], "changed": bool(task["hosts"]["localhost"].get("changed"))}
        for play_result in out["plays"]
        for task in play_result["tasks"]
        if "localhost" in task["hosts"]
    ]
    summary = {"stats": out["stats"]["localhost"], "changed_tasks": [t["task"] for t in tasks if t["changed"]]}
    record(f"{label}.json", summary)
    return summary


def ansible_after_pyinfra(dev: dict[str, str]) -> None:
    before = ev_snapshot()
    play = [
        {
            "hosts": "localhost",
            "gather_facts": True,
            "roles": [{"role": "local.ops_library.encrypted_volume_prepare"}],
        }
    ]
    extra = {
        "encrypted_volume_device": dev["loop"],
        "encrypted_volume_expected_luks_uuid": dev["uuid"],
        "encrypted_volume_passphrase": PASSPHRASE,
        "encrypted_volume_use_keyfile": True,
        "encrypted_volume_allow_format": False,
    }
    result = ansible("ev-ansible-after-pyinfra", play, extra)
    assert result["stats"]["changed"] == 0, result
    assert ev_snapshot() == before
    ev("ev-pyinfra-after-ansible-repeat", ev_config(dev), zero=True)


DEV: dict[str, str] = {}


def main() -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        DEV.update(setup_volume())
        record("volume.json", {k: v for k, v in DEV.items()})
        encrypted_volume_phases(DEV)
        SUMMARY["ansible"] = ansible_setup()
        ansible_after_pyinfra(DEV)
        SUMMARY["result"] = "passed"
    except BaseException:
        SUMMARY["result"] = "failed"
        SUMMARY["failure"] = traceback.format_exc()
        raise
    finally:
        SUMMARY["seconds"] = round(time.monotonic() - started, 1)
        record("summary.json", SUMMARY)


if __name__ == "__main__":
    main()
