#!/usr/bin/env python3
"""Layer 3 (PLAN.md 7.6): the guards end to end through sshd, inside the
distribution containers (Ubuntu 24.04 with Python 3.12 and OpenSSH 9.6,
Debian 13 with Python 3.13 and OpenSSH 10.0).

Runs as root inside ``parity/e2e/Dockerfile`` (target ``layer3``). It starts
a syslog receiver on ``/dev/log`` and sshd on 127.0.0.1, and gives root an
``authorized_keys`` line per implementation and fixture policy, with
``restrict`` and the forced command of PLAN.md 6.2:

- ``python``: ``/usr/bin/python3 -I /usr/local/sbin/echoport-remote-command-guard <policy>``
- ``rust``:   ``<bin> <policy>``
- ``shadow``: ``<bin> --shadow <policy> /usr/bin/python3 -I /usr/local/sbin/echoport-remote-command-guard <policy>``

with ``<bin>`` at ``/usr/local/lib/echoport-command-guard/<version>/echoport-command-guard``.
Then, for each scenario and each implementation, from the same fresh state
(the policies' roots and temp files, built by ``world()``):

- every command the runners send (``fixtures/corpus/runner.jsonl``),
  sent with ``ssh``, against stub ``systemctl``/``sudo``/``pg_*``/
  ``sqlite3``/``curl`` (``stub-tool.sh``) that record argv, environment,
  fds, ignored signals and umask; the other tools are the real ones;
- real ``scp -O`` downloads and uploads, the three rsync forms, ``cat >``
  and the snapshot ``cat`` with data, ``tar`` with the umask, ``mkdir -p``
  as the owner, the guard's own mutations through symlinks it refuses (H1),
  refused commands, an interactive session, SFTP, the environment with and
  without a client ``LANG``, a failing redirect and a missing tool.

Compared between ``python`` and ``rust``: exit code, stdout, stderr, the
resulting files (kind, content, owner, group, mode) on both sides, the stub
records and the syslog lines (identifier, facility and priority, message
with the PID removed). ``shadow`` must give exactly what ``python`` gives,
plus one record under ``echoport-remote-command-guard-shadow`` whose
verdict is Python's (a redirect that fails to open, or a mutation the guard
cannot make, is ``allowed`` there: the record covers ``check()`` only).
Every runner command must be allowed by the Python guard in its state, so
the comparison covers the allowed path, not only refusals.

Usage (``parity/e2e/run-layer3.sh`` does this)::

    python3 -I layer3_sshd.py --guard /e2e/guard.py --binary /usr/local/bin/echoport-command-guard \
        --policies /e2e/policies --runner /e2e/runner.jsonl

Exits 1 on any difference. Stdlib only.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

PY_GUARD = "/usr/local/sbin/echoport-remote-command-guard"
INSTALL_ROOT = "/usr/local/lib/echoport-command-guard"
VERSION = "0.0.0"
RUST_BIN = f"{INSTALL_ROOT}/{VERSION}/echoport-command-guard"
POLICY_DIR = "/etc/echoport"
PROBE_DIR = "/var/lib/e2e-probe"
CLIENT = "/e2e-client"
STUB_TOOLS = ["systemctl", "sudo", "pg_dump", "pg_restore", "psql", "createdb", "dropdb", "sqlite3", "curl"]
IMPLS = ["python", "rust", "shadow"]
IDENT = "echoport-remote-command-guard"
SHADOW_IDENT = "echoport-remote-command-guard-shadow"
NON_ASCII = "non-ASCII or control characters in command"
UNSUPPORTED = "unsupported character in command"
FIXED_MTIME = 1_760_000_000

GTS = "/var/lib/gotosocial"
SITE = "/home/marina/site"
DATA = "/home/villakunterbunt/data"
MEDIA = "/home/python-podcast/site/private_media"
SNAP = "/var/tmp/gotosocial-echoport.Ab12Cd"
PRIVATE = "/tmp/echoport-pp-private-media.Ab12Cd34"
DJANGO = "/var/tmp/django-chat-db-restore.Ab12Cd34"
STAMP = "2026-10-15T02-00-00"
RSTAMP = "20261015020000"
# Everything a scenario may change, on the server and the client side.
WATCHED = [GTS, SITE, DATA, MEDIA, "/etc/gotosocial", "/tmp", "/var/tmp", f"{CLIENT}/out"]
RANDOM_NAME = re.compile(r"((?:gotosocial-echoport|django-chat-db-restore|echoport-pp-private-media)\.)[A-Za-z0-9]{6,8}")
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"]
SYSLOG_LINE = re.compile(r"^<(\d+)>(?:\w{3} [ \d]\d \d\d:\d\d:\d\d )?([^\[:]+)\[(\d+)\]: (.*)$", re.DOTALL)


# --- setup --------------------------------------------------------------------


class SyslogReceiver:
    """/dev/log as a datagram socket; keeps every record."""

    def __init__(self) -> None:
        if os.path.lexists("/dev/log"):
            os.unlink("/dev/log")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind("/dev/log")
        os.chmod("/dev/log", 0o666)
        self.records: list[tuple[int, str, int, str]] = []
        self.lock = threading.Lock()
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self) -> None:
        while True:
            data = self.sock.recv(65536)
            match = SYSLOG_LINE.match(data.decode("utf-8", "surrogateescape"))
            if match:
                with self.lock:
                    self.records.append((int(match.group(1)), match.group(2), int(match.group(3)), match.group(4)))

    def mark(self) -> int:
        with self.lock:
            return len(self.records)

    def since(self, mark: int) -> list[tuple[int, str, int, str]]:
        # The guard has exited when ssh returns; give the datagrams a moment.
        time.sleep(0.05)
        with self.lock:
            return [r for r in self.records[mark:] if r[1] in (IDENT, SHADOW_IDENT)]


def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=True, **kwargs)


def forced_command(impl: str, policy: str) -> str:
    if impl == "python":
        return f"/usr/bin/python3 -I {PY_GUARD} {policy}"
    if impl == "rust":
        return f"{RUST_BIN} {policy}"
    return f"{RUST_BIN} --shadow {policy} /usr/bin/python3 -I {PY_GUARD} {policy}"


def install(args: argparse.Namespace) -> None:
    shutil.copyfile(args.guard, PY_GUARD)
    os.chmod(PY_GUARD, 0o755)
    os.makedirs(os.path.dirname(RUST_BIN), mode=0o755, exist_ok=True)
    shutil.copyfile(args.binary, RUST_BIN)
    os.chmod(RUST_BIN, 0o755)
    os.makedirs(POLICY_DIR, exist_ok=True)
    for name in ("production", "staging"):
        target = f"{POLICY_DIR}/remote-command-guard-{name}.json"
        shutil.copyfile(f"{args.policies}/{name}.json", target)
        os.chmod(target, 0o644)
        run(["/usr/bin/python3", "-I", PY_GUARD, "--check-policy", target])
        run([RUST_BIN, "--check-policy", target])
    stub = "/usr/local/lib/e2e-stub-tool"
    shutil.copyfile(args.stub, stub)
    os.chmod(stub, 0o755)
    for tool in STUB_TOOLS:
        path = f"/usr/local/bin/{tool}"
        if os.path.lexists(path):
            os.unlink(path)
        os.symlink(stub, path)
    os.makedirs(PROBE_DIR, exist_ok=True)
    os.chmod(PROBE_DIR, 0o1777)
    # Client keys, one per implementation and policy.
    reset(CLIENT)
    os.makedirs(f"{CLIENT}/keys", mode=0o700)
    lines = []
    for impl in IMPLS:
        for name in ("production", "staging"):
            key = f"{CLIENT}/keys/{impl}-{name}"
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"e2e-{impl}-{name}", "-f", key])
            with open(f"{key}.pub") as handle:
                public = handle.read().strip()
            policy = f"{POLICY_DIR}/remote-command-guard-{name}.json"
            lines.append(f'restrict,command="{forced_command(impl, policy)}" {public}\n')
    os.makedirs("/root/.ssh", mode=0o700, exist_ok=True)
    with open("/root/.ssh/authorized_keys", "w") as handle:
        handle.writelines(lines)
    os.chmod("/root/.ssh/authorized_keys", 0o600)
    # sshd: the hosts' logging, the distribution's sftp server, LANG and
    # LC_* accepted as on Debian and Ubuntu; no PAM in a container.
    run(["ssh-keygen", "-A"], stdout=subprocess.DEVNULL)
    os.makedirs("/run/sshd", mode=0o755, exist_ok=True)
    with open("/etc/ssh/sshd_e2e_config", "w") as handle:
        handle.write("ListenAddress 127.0.0.1\nPort 22\nPermitRootLogin prohibit-password\n"
                     "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n"
                     "AcceptEnv LANG LC_*\nSyslogFacility AUTH\nLogLevel INFO\n"
                     "Subsystem sftp /usr/lib/openssh/sftp-server\n")
    run(["/usr/sbin/sshd", "-f", "/etc/ssh/sshd_e2e_config", "-E", "/var/log/sshd-e2e.log"])
    for _ in range(50):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", 22)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError("sshd did not start")


def reset(path: str) -> None:
    if os.path.lexists(path):
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)


def chown(path: str, user: str) -> None:
    entry = pwd.getpwnam(user)
    os.lchown(path, entry.pw_uid, entry.pw_gid)


def put(path: str, content: str, user: str = "root", mode: int = 0o600) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(content)
    os.chmod(path, mode)
    chown(path, user)
    os.utime(path, (FIXED_MTIME, FIXED_MTIME))


def mkdir(path: str, user: str = "root", mode: int = 0o755) -> None:
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)
    chown(path, user)


def world(command: str = "") -> None:
    """The state every scenario starts from, with what this command needs."""
    for path in (GTS, SITE, DATA, MEDIA, "/etc/gotosocial", f"{CLIENT}/out", f"{CLIENT}/in", PROBE_DIR):
        reset(path)
    for entry in os.listdir("/tmp"):
        reset(f"/tmp/{entry}")
    for entry in os.listdir("/var/tmp"):
        reset(f"/var/tmp/{entry}")
    os.makedirs(PROBE_DIR)
    os.chmod(PROBE_DIR, 0o1777)
    for root, user in ((GTS, "gotosocial"), (SITE, "marina"), (DATA, "villakunterbunt"), (MEDIA, "python-podcast")):
        mkdir(root, user)
    put(f"{GTS}/sqlite.db", "gotosocial db\n", "gotosocial")
    put(f"{GTS}/sqlite.db-wal", "wal\n", "gotosocial")
    put(f"{GTS}/sqlite.db-shm", "shm\n", "gotosocial")
    put(f"{GTS}/sqlite.db.restore-tmp", "restored db\n", "gotosocial")
    put(f"{GTS}/.ops-domain-layout", "layout\n", "gotosocial", 0o644)
    mkdir(f"{GTS}/storage", "gotosocial", 0o750)
    put(f"{GTS}/storage/attachment.bin", "attachment\n", "gotosocial", 0o640)
    for root, user in ((SITE, "marina"), (DATA, "villakunterbunt")):
        put(f"{root}/db.sqlite3", "site db\n", user, 0o644)
        put(f"{root}/db.sqlite3.tmp", "uploaded db\n", user, 0o644)
        put(f"{root}/db.sqlite3-wal", "wal\n", user)
        put(f"{root}/db.sqlite3-shm", "shm\n", user)
        mkdir(f"{root}/media", user)
        put(f"{root}/media/image.jpg", "jpeg\n", user, 0o644)
        mkdir(f"{root}/media/sub", user)
        put(f"{root}/media/sub/old.txt", "old\n", user, 0o644)
    mkdir(f"{DATA}/private_media", "villakunterbunt", 0o750)
    put(f"{DATA}/private_media/secret.pdf", "secret\n", "villakunterbunt", 0o640)
    put(f"{MEDIA}/episode.mp3", "mp3\n", "python-podcast", 0o644)
    for path in (f"{MEDIA}/episode.mp3", MEDIA):
        os.utime(path, (FIXED_MTIME, FIXED_MTIME))
    put("/etc/gotosocial/config.yaml", "host: example.org\n", "root", 0o644)
    for prefix in ("pp", "homepage"):
        put(f"/tmp/echoport_{prefix}_dump_{STAMP}.dump", f"{prefix} dump\n", "postgres")
    mkdir(PRIVATE, "root", 0o700)
    if "scp -f" in command:
        put(f"{PRIVATE}/private_media.tar.gz", "archive\n")
    mkdir(DJANGO, "root", 0o700)
    if "cat >" not in command:
        put(f"{DJANGO}/django-chat.dump", "django dump\n")
    if command.startswith("chown gotosocial") or command.startswith("rm -rf"):
        mkdir(SNAP, "root", 0o700)
    else:
        mkdir(SNAP, "gotosocial", 0o700)
        put(f"{SNAP}/sqlite.db", "snapshot\n", "gotosocial")
    # `mv a b` (not `b.tmp` into place) needs a new name.
    parts = command.split()
    if len(parts) == 3 and parts[0] == "mv" and parts[1] != parts[2] + ".tmp":
        reset(parts[2])
    mkdir(f"{CLIENT}/out", "root", 0o700)
    mkdir(f"{CLIENT}/in", "root", 0o700)
    put(f"{CLIENT}/in/db.sqlite3", "client db\n", "root", 0o640)
    put(f"{CLIENT}/in/restore.dump", "client restore dump\n", "root", 0o600)
    mkdir(f"{CLIENT}/in/media", "root")
    put(f"{CLIENT}/in/media/image.jpg", "new jpeg\n", "root", 0o644)
    put(f"{CLIENT}/in/media/added.png", "png\n", "root", 0o644)
    os.symlink("image.jpg", f"{CLIENT}/in/media/link.jpg")


# --- observation --------------------------------------------------------------


def normalize(text: str) -> str:
    text = RANDOM_NAME.sub(r"\1<R>", text)
    # sshd runs the forced command with the user's shell (`bash -c`), which
    # sets `_` to the program it starts: the guard's path, not the guard's doing.
    text = re.sub(r"(?m)^_=.*\n", "", text)
    text = re.sub(r"(pipe|socket|anon_inode):\[\d+\]", r"\1:[N]", text)
    return re.sub(r"(127\.0\.0\.1) \d+ ", r"\1 <port> ", text)


def file_entry(path: str) -> dict[str, Any]:
    st = os.lstat(path)
    entry: dict[str, Any] = {"mode": oct(st.st_mode), "uid": st.st_uid, "gid": st.st_gid}
    if stat.S_ISREG(st.st_mode):
        with open(path, "rb") as handle:
            data = handle.read()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)  # the gzip header carries a time
        entry["sha256"] = hashlib.sha256(data).hexdigest()
        entry["nlink"] = st.st_nlink
    elif stat.S_ISLNK(st.st_mode):
        entry["target"] = os.readlink(path)
    return entry


def snapshot() -> list[tuple[str, dict[str, Any]]]:
    out = []
    for top in WATCHED:
        if not os.path.lexists(top):
            out.append((top, {"absent": True}))
            continue
        out.append((normalize(top), file_entry(top)))
        for directory, dirs, files in os.walk(top):
            for name in sorted(dirs + files):
                path = os.path.join(directory, name)
                out.append((normalize(path), file_entry(path)))
    # Random names are normalised, so two entries can share a name.
    return sorted(out, key=lambda item: (item[0], json.dumps(item[1], sort_keys=True)))


def probes() -> list[dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    for name in sorted(os.listdir(PROBE_DIR)):
        stem, _, part = name.rpartition(".")
        tool = stem.rsplit(".", 1)[0]
        with open(f"{PROBE_DIR}/{name}", errors="surrogateescape") as handle:
            records.setdefault(stem, {"tool": tool})[part] = normalize(handle.read())
    return list(records.values())


@dataclass
class Observation:
    exit: int
    stdout: str
    stderr: str
    probes: list[dict[str, str]]
    syslog: list[tuple[int, str, str]]
    shadow: list[dict[str, Any]]
    files: list[tuple[str, dict[str, Any]]]

    def comparable(self) -> dict[str, Any]:
        return {"exit": self.exit, "stdout": self.stdout, "stderr": self.stderr, "probes": self.probes,
                "syslog": self.syslog, "files": self.files}


@dataclass
class Scenario:
    name: str
    policy: str  # production | staging
    # (key, environment) -> argv of the client
    client: Callable[[str], list[str]]
    command: str | None = None  # what reaches SSH_ORIGINAL_COMMAND, for world() and the log check
    stdin: bytes = b""
    lang: str | None = None
    prepare: Callable[[], None] | None = None
    expect_allowed: bool | None = None
    # A PLAN.md 4.1 case: Rust refuses it in the prefilter (Python may allow).
    p3: bool = False


def observe(scenario: Scenario, impl: str, receiver: SyslogReceiver) -> Observation:
    world(scenario.command or "")
    if scenario.prepare is not None:
        scenario.prepare()
    key = f"{CLIENT}/keys/{impl}-{scenario.policy}"
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"}
    if scenario.lang is not None:
        env["LANG"] = scenario.lang
    mark = receiver.mark()
    result = subprocess.run(scenario.client(key), input=scenario.stdin, capture_output=True, env=env, timeout=120,
                            cwd=CLIENT)
    records = receiver.since(mark)
    syslog = [(pri, ident, normalize(message)) for pri, ident, _pid, message in records if ident == IDENT]
    shadow = [json.loads(message) for _pri, ident, _pid, message in records if ident == SHADOW_IDENT]
    pids = {pid for _pri, _ident, pid, _message in records}
    if len(pids) > 1:
        raise RuntimeError(f"{scenario.name} {impl}: log lines from several PIDs {records}")
    return Observation(result.returncode, normalize(result.stdout.decode("utf-8", "surrogateescape")),
                       normalize(result.stderr.decode("utf-8", "surrogateescape")), probes(), syslog, shadow,
                       snapshot())


# --- scenarios ----------------------------------------------------------------


def ssh(command: str | None, *extra: str) -> Callable[[str], list[str]]:
    def argv(key: str) -> list[str]:
        out = ["ssh", "-T", "-i", key, *SSH_OPTS, *extra, "root@127.0.0.1"]
        return out + (["--", command] if command is not None else [])
    return argv


def via(tool: str, *args: str) -> Callable[[str], list[str]]:
    """scp/rsync/sftp with the key; `H:` in an argument is the server."""
    def argv(key: str) -> list[str]:
        ssh_command = " ".join(["ssh", "-i", key, *SSH_OPTS])
        resolved = [a.replace("H:", "root@127.0.0.1:") for a in args]
        if tool == "rsync":
            return ["rsync", "-e", ssh_command, *resolved]
        return [tool, "-i", key, *SSH_OPTS, *resolved]
    return argv


def scenarios(runner_commands: list[tuple[str, str]]) -> list[Scenario]:
    out = [Scenario(f"runner {policy}: {command}", policy, ssh(command), command, expect_allowed=True)
           for policy, command in runner_commands]
    dump = f"/tmp/echoport_pp_dump_{STAMP}.dump"
    restore = f"/tmp/echoport_pp_restore_{RSTAMP}.dump"

    def remove_curl() -> None:
        os.unlink("/usr/local/bin/curl")

    out += [
        # Real transfers.
        Scenario("scp -O download dump", "production", via("scp", "-O", f"H:{dump}", f"{CLIENT}/out/"),
                 f"scp -f {dump}", expect_allowed=True),
        Scenario("scp -O download read file", "production",
                 via("scp", "-O", "H:/etc/gotosocial/config.yaml", f"{CLIENT}/out/"),
                 "scp -f /etc/gotosocial/config.yaml", expect_allowed=True),
        Scenario("scp -O download private media archive", "production",
                 via("scp", "-O", f"H:{PRIVATE}/private_media.tar.gz", f"{CLIENT}/out/"),
                 f"scp -f {PRIVATE}/private_media.tar.gz", expect_allowed=True),
        Scenario("scp -O upload into a root", "staging",
                 via("scp", "-O", f"{CLIENT}/in/db.sqlite3", f"H:{SITE}/db.sqlite3.tmp"),
                 f"scp -t {SITE}/db.sqlite3.tmp", expect_allowed=True),
        Scenario("scp -O upload restore dump", "staging",
                 via("scp", "-O", f"{CLIENT}/in/restore.dump", f"H:{restore}"), f"scp -t {restore}",
                 expect_allowed=True),
        Scenario("scp -O upload through a symlink", "staging",
                 via("scp", "-O", f"{CLIENT}/in/db.sqlite3", f"H:{SITE}/link.tmp"), f"scp -t {SITE}/link.tmp",
                 prepare=lambda: os.symlink("/etc/passwd", f"{SITE}/link.tmp"), expect_allowed=False),
        Scenario("rsync download", "staging",
                 via("rsync", "-a", "--safe-links", f"H:{SITE}/media/", f"{CLIENT}/out/media/"),
                 f"rsync --server --sender -logDtpre.iLsfxCIvu --safe-links . {SITE}/media/", expect_allowed=True),
        Scenario("rsync upload", "staging",
                 via("rsync", "-a", "--no-D", f"{CLIENT}/in/media/", f"H:{SITE}/media/"),
                 f"rsync --server -logtpre.iLsfxCIvu . {SITE}/media/", expect_allowed=True),
        Scenario("rsync upload --delete", "staging",
                 via("rsync", "-a", "--no-D", "--delete", f"{CLIENT}/in/media/", f"H:{DATA}/media/"),
                 f"rsync --server -logtpre.iLsfxCIvu --delete . {DATA}/media/", expect_allowed=True),
        Scenario("rsync with -L is refused", "staging",
                 via("rsync", "-aL", f"H:{SITE}/media/", f"{CLIENT}/out/media/"), None, expect_allowed=False),
        Scenario("cat > with data", "staging", ssh(f"umask 077 && cat > {DJANGO}/django-chat.dump"),
                 f"umask 077 && cat > {DJANGO}/django-chat.dump", b"a restore dump\n" * 1000, expect_allowed=True),
        Scenario("cat > onto an existing file", "staging", ssh(f"umask 077 && cat > {DJANGO}/django-chat.dump"),
                 "umask 077 && cat > (exists)", b"x",
                 prepare=lambda: put(f"{DJANGO}/django-chat.dump", "old\n"), expect_allowed=False),
        Scenario("snapshot cat", "production", ssh(f"cat {SNAP}/sqlite.db"), f"cat {SNAP}/sqlite.db",
                 expect_allowed=True),
        Scenario("snapshot cat of a link", "production", ssh(f"cat {SNAP}/sqlite.db"), f"cat {SNAP}/sqlite.db",
                 prepare=lambda: (os.unlink(f"{SNAP}/sqlite.db"), os.symlink("/etc/shadow", f"{SNAP}/sqlite.db")),
                 expect_allowed=False),
        Scenario("pg_restore from the stdin file", "staging",
                 ssh("runuser -u postgres -- pg_restore --no-owner --no-privileges --exit-on-error "
                     f"--dbname=django_chat_restore_42 < {DJANGO}/django-chat.dump"),
                 "pg_restore <", expect_allowed=True),
        Scenario("tar with umask", "production",
                 ssh(f"umask 077 && tar -C /home/python-podcast/site -czf {PRIVATE}/private_media.tar.gz "
                     "-- private_media"), "umask 077 && tar", expect_allowed=True),
        # The guard's own mutations (H1): made on file descriptors, never through
        # a symlink, also one check() allowed because it resolves inside the root.
        Scenario("chmod of a symlink inside the root", "staging", ssh(f"chmod 0600 {SITE}/alias"),
                 f"chmod 0600 {SITE}/alias", prepare=lambda: os.symlink(f"{SITE}/db.sqlite3", f"{SITE}/alias"),
                 expect_allowed=False),
        Scenario("chown through a symlinked directory inside the root", "staging",
                 ssh(f"chown marina:marina {SITE}/dir/db.sqlite3"), f"chown marina:marina {SITE}/dir/db.sqlite3",
                 prepare=lambda: os.symlink(SITE, f"{SITE}/dir"), expect_allowed=False),
        Scenario("chown -R leaves a symlink out of the root alone", "staging",
                 ssh(f"chown -R marina:marina {SITE}/media"), f"chown -R marina:marina {SITE}/media",
                 prepare=lambda: os.symlink("/etc/gotosocial/config.yaml", f"{SITE}/media/out"),
                 expect_allowed=True),
        Scenario("mv of a missing file", "staging", ssh(f"mv {SITE}/gone {SITE}/gone2"),
                 f"mv {SITE}/gone {SITE}/gone2", expect_allowed=False),
        Scenario("rm -f of missing side files", "staging", ssh(f"rm -f {SITE}/none-wal {SITE}/none-shm"),
                 f"rm -f {SITE}/none-wal {SITE}/none-shm", expect_allowed=True),
        # chmod, mv and rm run as the root's owner: no chmod of root's files, no
        # mv/rm in a directory that user cannot write.
        Scenario("chmod of a root-owned file inside the root", "staging", ssh(f"chmod 0600 {SITE}/root-owned"),
                 f"chmod 0600 {SITE}/root-owned", prepare=lambda: put(f"{SITE}/root-owned", "root\n", "root", 0o644),
                 expect_allowed=False),
        Scenario("mv into a root-owned directory inside the root", "staging",
                 ssh(f"mv {SITE}/db.sqlite3 {SITE}/root-dir/db.sqlite3"),
                 f"mv {SITE}/db.sqlite3 {SITE}/root-dir/db.sqlite3", prepare=lambda: mkdir(f"{SITE}/root-dir"),
                 expect_allowed=False),
        Scenario("mkdir -p as owner", "staging", ssh(f"mkdir -p {SITE}/media/new/deeper"),
                 f"mkdir -p {SITE}/media/new/deeper", expect_allowed=True),
        # Refusals.
        Scenario("refused id", "production", ssh("id"), "id", expect_allowed=False),
        Scenario("refused shell metacharacters", "production", ssh("systemctl stop gotosocial; id"),
                 "systemctl stop gotosocial; id", expect_allowed=False),
        Scenario("refused /etc/shadow", "production", ssh("scp -f /etc/shadow"), "scp -f /etc/shadow",
                 expect_allowed=False),
        Scenario("prefilter: backslash (Python allows)", "staging", ssh("systemctl start marina\\.service"),
                 "systemctl start marina\\.service", expect_allowed=True, p3=True),
        Scenario("prefilter: hash", "staging", ssh("systemctl start marina.service #x"), "x",
                 expect_allowed=False, p3=True),
        Scenario("refused tab and quotes", "staging", ssh("systemctl\tstart\t'marina.service' ;"), "x",
                 expect_allowed=False),
        Scenario("refused unbalanced quote", "staging", ssh("systemctl start 'marina.service"), "x",
                 expect_allowed=False),
        Scenario("prefilter: non-ASCII", "staging", ssh("systemctl start marina.servicé"), "x",
                 expect_allowed=False, p3=True),
        Scenario("interactive session", "production", ssh(None), None, expect_allowed=False),
        Scenario("sftp", "staging", via("sftp", "-b", "-", "H:"), None, b"ls\n", expect_allowed=False),
        # Environment: with and without a client LANG (PEP 538 coercion).
        Scenario("environment without LANG", "staging",
                 ssh("systemctl show --property=LoadState --value homepage-db-worker"),
                 "systemctl show", expect_allowed=True),
        Scenario("environment with LANG=C.UTF-8", "staging",
                 ssh("systemctl show --property=LoadState --value homepage-db-worker", "-o", "SendEnv=LANG"),
                 "systemctl show", lang="C.UTF-8", expect_allowed=True),
        Scenario("environment with LANG=C", "staging",
                 ssh("systemctl show --property=LoadState --value homepage-db-worker", "-o", "SendEnv=LANG"),
                 "systemctl show", lang="C", expect_allowed=True),
        # A missing tool: exit 127 with `cannot run`.
        Scenario("missing tool", "production", ssh("curl -fsS -o /dev/null http://127.0.0.1:10070/readyz"),
                 "curl", prepare=remove_curl, expect_allowed=True),
    ]
    return out


# --- comparison ---------------------------------------------------------------


def log_verdict(obs: Observation) -> tuple[str, str | None]:
    """The Python/Rust guard's verdict from its log line: allowed, refused
    (with the reason), interactive or policy-error."""
    for _pri, _ident, message in obs.syslog:
        if message.startswith("allowed from "):
            return "allowed", None
        if message.startswith("refused interactive session"):
            return "interactive", None
        if message.startswith("refused from "):
            return "refused", message.split(": ", 1)[1].rsplit(": ", 1)[0]
        if message.startswith("policy error"):
            return "policy-error", None
    return "none", None


def restore_stubs(stub: str) -> None:
    for tool in STUB_TOOLS:
        path = f"/usr/local/bin/{tool}"
        if not os.path.lexists(path):
            os.symlink(stub, path)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--guard", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--policies", required=True)
    parser.add_argument("--runner", required=True, help="fixtures/corpus/runner.jsonl")
    parser.add_argument("--stub", required=True, help="stub-tool.sh")
    parser.add_argument("--only", help="run the scenarios whose name contains this")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("layer3_sshd.py runs as root inside the e2e container", file=sys.stderr)
        return 2
    receiver = SyslogReceiver()
    install(args)
    runner: list[tuple[str, str]] = []
    with open(args.runner) as handle:
        for line in handle:
            record = json.loads(line)
            item = (record["policy"], record["command"])
            if item not in runner:
                runner.append(item)
    failures: list[str] = []
    counts = {"scenarios": 0, "allowed": 0, "refused": 0, "interactive": 0}
    for scenario in scenarios(runner):
        if args.only and args.only not in scenario.name:
            continue
        counts["scenarios"] += 1
        seen = {}
        for impl in IMPLS:
            seen[impl] = observe(scenario, impl, receiver)
            restore_stubs("/usr/local/lib/e2e-stub-tool")
        python, rust, shadow = seen["python"], seen["rust"], seen["shadow"]
        verdict, reason = log_verdict(python)
        counts[verdict] = counts.get(verdict, 0) + 1
        if scenario.expect_allowed is not None and (verdict == "allowed") != scenario.expect_allowed:
            failures.append(f"{scenario.name}: Python's verdict is {verdict} ({reason}), the scenario expects "
                            f"{'allowed' if scenario.expect_allowed else 'a refusal'}")
        if scenario.p3:
            # PLAN.md 4.1/4.4: the prefilter refuses, nothing runs.
            reasons = [m.split(": ", 1)[1].rsplit(": ", 1)[0] for _p, _i, m in rust.syslog]
            if (rust.exit, rust.stderr, rust.probes) != (1, "echoport-remote-command-guard: command not allowed\n", []) \
                    or reasons not in ([NON_ASCII], [UNSUPPORTED]):
                failures.append(f"{scenario.name}: Rust {rust.exit} {rust.stderr!r} {rust.syslog} {rust.probes}")
        compared = (("shadow", shadow),) if scenario.p3 else (("rust", rust), ("shadow", shadow))
        for impl, other in compared:
            want, got = python.comparable(), other.comparable()
            for key in want:
                if want[key] != got[key]:
                    failures.append(f"{scenario.name}: {impl} {key} differs:\n  python {want[key]!r}\n"
                                    f"  {impl:6} {got[key]!r}")
        # The shadow record: one, with Python's verdict.
        if python.shadow or rust.shadow or len(shadow.shadow) != 1:
            failures.append(f"{scenario.name}: shadow records python={python.shadow} rust={rust.shadow} "
                            f"shadow={shadow.shadow}")
        else:
            record = shadow.shadow[0]
            ok = record.get("verdict") == verdict and (verdict != "refused" or record.get("reason") == reason)
            ok = ok or (scenario.p3 and record.get("reason") in (NON_ASCII, UNSUPPORTED))
            # check() only: a redirect that fails to open, or a mutation the
            # guard cannot make (H1), is allowed there.
            redirect_failure = verdict == "refused" and record.get("verdict") == "allowed" and (
                record.get("stdin") or record.get("stdout") or record.get("mutation"))
            if not ok and not redirect_failure and not (verdict == "none" and record.get("verdict") == "refused"):
                failures.append(f"{scenario.name}: shadow record {record}, Python {verdict} {reason!r}")
    print(json.dumps({"python": sys.version.split()[0], "ssh": subprocess.run(
        ["ssh", "-V"], capture_output=True, text=True).stderr.strip(), **counts, "failures": len(failures)}))
    for failure in failures[:60]:
        print("FAIL", failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
