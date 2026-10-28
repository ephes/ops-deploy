"""Owned disposable Darwin fixture resources, never inventory-host utilities.

Cleanup only touches what this fixture provably created: processes it spawned
in their own sessions (plus their exact descendants, identified by PID and
start time), jobs under its unique labels, processes running as its unique
accounts, those accounts, and its private root. It never signals by name or
pattern and claims no whole-host cleanup.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.resources
import json
import os
import platform
import pwd
import re
import shutil
import signal
import socket
import subprocess
import time
import traceback
from collections.abc import Sequence, Set
from contextlib import suppress
from pathlib import Path
from typing import Any


def command(*argv: str, check: bool = True, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=check, capture_output=True, text=True, **kwargs)


def port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def file_state(paths: list[Path]) -> dict[str, dict[str, Any]]:
    result = {}
    for path in paths:
        info = path.lstat()
        result[str(path)] = {
            "dev": info.st_dev,
            "ino": info.st_ino,
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "ctime_ns": info.st_ctime_ns,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": info.st_mode,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    return result


def processes() -> dict[int, dict[str, Any]]:
    """Live (non-zombie) processes: PID to parent, group, UID and start time."""

    table = {}
    for line in command("/bin/ps", "-Aww", "-o", "pid=,ppid=,pgid=,uid=,stat=,lstart=").stdout.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and not fields[4].startswith("Z"):
            table[int(fields[0])] = {
                "ppid": int(fields[1]),
                "pgid": int(fields[2]),
                "uid": int(fields[3]),
                "start": fields[5].strip(),
            }
    return table


def tree(roots: set[int], groups: Set[int] = frozenset()) -> dict[int, str]:
    """Exact PIDs (with start times) of ``roots``, their descendants and owned groups."""

    table = processes()
    found = {
        pid: table[pid]["start"] for pid in roots | {p for p, e in table.items() if e["pgid"] in groups} if pid in table
    }
    grown = True
    while grown:
        grown = False
        for pid, entry in table.items():
            if pid not in found and entry["ppid"] in found:
                found[pid] = entry["start"]
                grown = True
    return found


def job_pid(service: str) -> int | None:
    result = command("/bin/launchctl", "print", service, check=False)
    match = re.search(r"^\s*pid = ([1-9][0-9]*)$", result.stdout, re.M)
    return int(match[1]) if result.returncode == 0 and match else None


def stop_exact(owned: dict[int, str], popen: Sequence[subprocess.Popen[bytes]] = ()) -> list[int]:
    """Terminate exactly these PID/start pairs; return the ones that survive."""

    def live() -> list[int]:
        for process in popen:
            process.poll()  # reap our own direct children so they are not zombies
        table = processes()
        return [pid for pid, start in owned.items() if pid in table and table[pid]["start"] == start]

    for sig, seconds in [(signal.SIGTERM, 10.0), (signal.SIGKILL, 5.0)]:
        remaining = live()
        if not remaining:
            return []
        for pid in remaining:
            with suppress(ProcessLookupError, PermissionError):
                os.kill(pid, sig)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and live():
            time.sleep(0.1)
    return live()


class OwnedMac:
    """Named resources and cleanup confined to one disposable hosted runner."""

    def __init__(self, name: str):
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        self.evidence = Path(os.environ["MAC_APPS_EVIDENCE_DIR"])
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.report: dict[str, Any] = {
            "implementation": os.environ.get("IMPLEMENTATION_SHA", ""),
            "fixture": name,
            "arch": platform.machine(),
            "status": "failed",
            "repeats": {},
            "scope": "owned disposable VM; no inventory addresses, keys, audio or user models",
            "limitations": ["Selected managed metadata is observed; no whole-host syscall trace is claimed."],
        }
        self.processes: list[subprocess.Popen[bytes]] = []
        self.labels: list[str] = []
        self.users: list[str] = []
        self.residue: list[Path] = []
        self._root: Path | None = None
        if not (
            os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("SUDO_USER") == "runner"
            and platform.system() == "Darwin"
            and platform.machine() == "arm64"
            and os.geteuid() == 0
            and re.fullmatch(r"[0-9]+", run_id)
            and re.fullmatch(r"[0-9a-f]{40}", self.report["implementation"])
            and not Path("/Users/jochen").exists()
        ):
            self.report["failure_type"] = "RefusedHost"
            self.receipt()
            raise RuntimeError("requires an owned disposable ARM GitHub runner")
        self.suffix = run_id[-10:] + "-" + str(os.getpid())
        root = Path("/private/var/tmp") / ("ops-mac-apps-" + name + "-" + self.suffix)
        assert not root.exists()
        root.mkdir(mode=0o755)
        self._root = root

    @property
    def root(self) -> Path:
        assert self._root is not None, "owned root exists only on an accepted runner"
        return self._root

    def fail(self, error: BaseException) -> None:
        """Record the first failure's type and code location, never its message."""

        if "failure_type" in self.report:
            return
        self.report["failure_type"] = type(error).__name__
        self.report["failure_location"] = [
            Path(frame.filename).name + ":" + str(frame.lineno) + ":" + frame.name
            for frame in traceback.extract_tb(error.__traceback__)[-8:]
        ]

    def verify_implementation(self) -> None:
        source = Path(__file__).resolve().parents[1]
        assert command("git", "-C", str(source), "rev-parse", "HEAD").stdout.strip() == os.environ["IMPLEMENTATION_SHA"]
        distribution = importlib.metadata.distribution("ops-deploy")
        assert not json.loads(distribution.read_text("direct_url.json") or "{}").get("dir_info", {}).get("editable")
        installed = Path(str(importlib.resources.files("ops_deploy")))
        assert installed.is_relative_to(Path("/private/var/tmp/mac-apps-controller"))
        tracked = command("git", "-C", str(source), "ls-files", "src/ops_deploy").stdout.splitlines()
        resources = {}
        for name in tracked:
            relative = Path(name).relative_to("src/ops_deploy")
            actual = (installed / relative).read_bytes()
            assert actual == (source / name).read_bytes()
            resources[str(relative)] = hashlib.sha256(actual).hexdigest()
        self.report["installed_resources"] = resources
        self.report["host_python"] = command("/usr/bin/python3", "--version").stdout.strip()

    def spawn(self, argv: list[str], log: Path | None = None) -> subprocess.Popen[bytes]:
        """Start an owned helper in its own session, so its group is ours alone."""

        stream = log.open("ab") if log is not None else None
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stream or subprocess.DEVNULL,
                stderr=stream or subprocess.DEVNULL,
                start_new_session=True,
            )
        finally:
            if stream is not None:
                stream.close()
        self.processes.append(process)
        return process

    def label(self, name: str) -> str:
        label = "com.example.ops-mac-apps." + name + "." + self.suffix
        assert command("/bin/launchctl", "print", "system/" + label, check=False).returncode != 0
        self.labels.append("system/" + label)
        return label

    def adopt_gui_label(self, uid: int, label: str) -> None:
        """Back-stop cleanup of a GUI job an unprivileged owner child creates."""

        assert label.startswith("com.example.ops-mac-apps.")
        assert label.endswith(self.suffix)
        service = "gui/" + str(uid) + "/" + label
        assert command("/bin/launchctl", "print", service, check=False).returncode != 0
        self.labels.append(service)

    def created_outside_root(self, path: Path) -> None:
        """Declare a path a service will create outside the owned root.

        It must not exist yet, so removing it later cannot touch prior state.
        """

        assert not os.path.lexists(path), "declared fixture residue already exists"
        self.residue.append(path)

    def pid(self, label: str) -> int:
        pid = job_pid("system/" + label)
        assert pid is not None, "owned job has no process"
        return pid

    def user(self, name: str) -> str:
        user = ("opsm_" + name + self.suffix.replace("-", ""))[-30:]
        assert command("/usr/bin/dscl", ".", "-read", "/Users/" + user, check=False).returncode != 0
        assert command("/usr/bin/dscl", ".", "-read", "/Groups/" + user, check=False).returncode != 0
        self.users.append(user)
        return user

    def create_existing_user(self, name: str) -> tuple[str, Path]:
        user = self.user(name)
        home = self.root / ("home-" + name)
        listing = command("/usr/bin/dscl", ".", "-list", "/Users", "UniqueID").stdout
        values = [int(line.split()[-1]) for line in listing.splitlines() if line.split()[-1].lstrip("-").isdigit()]
        uid = max([500, *values]) + 1
        command("/usr/bin/dscl", ".", "-create", "/Users/" + user)
        for key, value in {
            "UniqueID": str(uid),
            "PrimaryGroupID": "20",
            "NFSHomeDirectory": str(home),
            "UserShell": "/bin/zsh",
            "RealName": "Owned native fixture",
            "IsHidden": "1",
        }.items():
            command("/usr/bin/dscl", ".", "-create", "/Users/" + user, key, value)
        home.mkdir(mode=0o750)
        os.chown(home, uid, 20)
        return user, home

    def source(self, name: str, revision: str) -> Path:
        path = self.root / (name + "-source")
        command("git", "init", str(path))
        command("git", "-C", str(path), "fetch", "--depth=1", "https://github.com/ephes/" + name + ".git", revision)
        command("git", "-C", str(path), "checkout", "--detach", "FETCH_HEAD")
        assert command("git", "-C", str(path), "rev-parse", "HEAD").stdout.strip() == revision
        return path

    def ssh_transport(self) -> dict[str, Any]:
        """Owned high-port loopback sshd mirroring the inventory root SSH transport.

        Production reaches Studio as root with a key; this sshd accepts only the
        fixture's own key for root, on loopback, with its own host key and
        authorized-keys file. The system SSH service, the runner's keys and
        sudoers are untouched. rsync is the real Homebrew binary at the default
        ``remote_rsync_path``.
        """
        key = self.root / "transport-key"
        host_key = self.root / "transport-host-key"
        for path in [key, host_key]:
            command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path))
        # StrictModes requires an authorized-keys path whose ancestors up to the
        # account home are owned by root/the account and not group/world
        # writable (/private/var/tmp is 1777), so it lives in a unique directory
        # in root's actual home, removed on cleanup.
        keys = Path(pwd.getpwnam("root").pw_dir) / (".ops-mac-apps-transport-" + self.suffix)
        self.created_outside_root(keys)
        keys.mkdir(mode=0o700)
        authorized = keys / "authorized_keys"
        authorized.write_text(key.with_suffix(".pub").read_text())
        authorized.chmod(0o600)
        selected_port = port()
        config = self.root / "transport-sshd.conf"
        config.write_text(
            f"Port {selected_port}\nListenAddress 127.0.0.1\nHostKey {host_key}\n"
            f"PidFile {self.root}/transport-sshd.pid\nAuthorizedKeysFile {authorized}\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n"
            "PermitRootLogin prohibit-password\nAllowUsers root\nStrictModes yes\nLogLevel INFO\n"
            "Subsystem sftp internal-sftp\n"
        )
        command("/usr/sbin/sshd", "-t", "-f", str(config))
        process = self.spawn(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], self.evidence / "transport-sshd.log")
        known = self.root / "transport-known-hosts"
        known.write_text(
            "[127.0.0.1]:"
            + str(selected_port)
            + " "
            + " ".join(host_key.with_suffix(".pub").read_text().split()[:2])
            + "\n"
        )
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", selected_port), 0.1):
                    break
            except OSError:
                assert process.poll() is None, "owned sshd exited; see sanitized fixture log"
                time.sleep(0.1)
        else:
            raise RuntimeError("owned high-port sshd did not listen")
        binary = "/opt/homebrew/bin/rsync"
        if not Path(binary).is_file():
            # Inventory Macs already have modern Homebrew rsync; the hosted image
            # ships only openrsync, so the fixture installs the public formula.
            command(
                "/usr/bin/sudo",
                "-H",
                "-u",
                "runner",
                "--",
                "/usr/bin/env",
                "HOMEBREW_NO_AUTO_UPDATE=1",
                "/opt/homebrew/bin/brew",
                "install",
                "rsync",
            )
            self.report["limitations"].append("Homebrew rsync was installed as a fixture prerequisite.")
        version = command(binary, "--version").stdout.splitlines()[0]
        parsed = re.search(r"version ([0-9]+)\.([0-9]+)\.([0-9]+)", version)
        assert parsed is not None
        assert tuple(int(part) for part in parsed.groups()) >= (3, 1, 0)
        probe = command(
            "/usr/bin/ssh",
            "-p",
            str(selected_port),
            "-i",
            str(key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(known),
            "root@127.0.0.1",
            binary + " --version",
            check=False,
        )
        # Client diagnostics name hosts, users and key types only; no secret is involved.
        self.report["transport_probe"] = {"returncode": probe.returncode, "stderr": probe.stderr[-2000:]}
        if probe.returncode:
            raise RuntimeError("owned transport sshd refused the fixture key; see transport_probe")
        self.report["transport"] = {
            "address": "127.0.0.1",
            "port": selected_port,
            "user": "root",
            "remote_rsync": binary,
            "version": version,
            "auth_changes": False,
            "scope": "owned loopback sshd and key only; system SSH, runner keys and sudoers untouched",
        }
        return {
            "ssh_hostname": "127.0.0.1",
            "ssh_user": "root",
            "ssh_port": selected_port,
            "ssh_key": str(key),
            "ssh_known_hosts_file": str(known),
            "ssh_strict_host_key_checking": "yes",
            "remote_rsync_path": binary,
        }

    def cleanup(self) -> None:
        """Remove every owned resource; record each failure and keep going."""

        errors: list[str] = []

        def step(name: str, action: Any) -> None:
            try:
                action()
            except Exception as error:
                errors.append(name + ": " + type(error).__name__)

        def labels() -> None:
            for service in reversed(self.labels):
                pid = job_pid(service)
                tracked = tree({pid}) if pid is not None else {}
                command("/bin/launchctl", "bootout", service, check=False)
                for _ in range(100):
                    if command("/bin/launchctl", "print", service, check=False).returncode:
                        break
                    time.sleep(0.1)
                else:
                    errors.append("owned label still loaded")
                # launchd normally ends the job's processes itself; this waits
                # for exactly those PIDs and only signals them if they remain.
                if stop_exact(tracked):
                    errors.append("owned job process survived bootout")

        def spawned() -> None:
            roots = {process.pid for process in self.processes if process.poll() is None}
            # Each helper leads its own session/group (start_new_session), so
            # the group IDs below are ours alone; descendants that moved to a
            # new session (sshd connection children) are matched by ancestry.
            tracked = tree(roots, groups={process.pid for process in self.processes})
            for process in self.processes:
                if process.poll() is None:
                    with suppress(ProcessLookupError, PermissionError):
                        os.killpg(process.pid, signal.SIGTERM)
            if stop_exact(tracked, self.processes):
                errors.append("owned helper process survived")
            for process in self.processes:
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
                if process.returncode is None:
                    errors.append("owned helper was not reaped")

        def accounts() -> None:
            for user in reversed(self.users):
                read = command("/usr/bin/dscl", ".", "-read", "/Users/" + user, "UniqueID", check=False)
                match = re.search(r"UniqueID:\s*([0-9]+)", read.stdout)
                if match:
                    uid = int(match[1])
                    # A unique fixture-created account runs only our processes.
                    owned = {pid: entry["start"] for pid, entry in processes().items() if entry["uid"] == uid}
                    if stop_exact(owned):
                        errors.append("owned account process survived")
                command("/usr/bin/dscl", ".", "-delete", "/Users/" + user, check=False)
                command("/usr/sbin/dseditgroup", "-o", "delete", "-L", user, check=False)
                if not command("/usr/bin/dscl", ".", "-read", "/Users/" + user, check=False).returncode:
                    errors.append("owned account remains")
                if not command("/usr/bin/dscl", ".", "-read", "/Groups/" + user, check=False).returncode:
                    errors.append("owned group remains")

        def files() -> None:
            for path in self.residue:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                elif os.path.lexists(path):
                    path.unlink()
            if self._root is not None:
                assert self._root.parent == Path("/private/var/tmp")
                assert self._root.name.startswith("ops-mac-apps-")
                if self._root.exists():
                    shutil.rmtree(self._root)

        step("labels", labels)
        step("helpers", spawned)
        step("accounts", accounts)
        step("files", files)
        self.report["cleanup"] = not errors and (self._root is None or not self._root.exists())
        self.report["cleanup_errors"] = errors
        if not self.report["cleanup"]:
            raise RuntimeError("owned fixture cleanup failed")

    def receipt(self) -> None:
        (self.evidence / (str(self.report["fixture"]) + "-proof.json")).write_text(
            json.dumps(self.report, indent=2) + "\n"
        )

    def finish(self, failure: BaseException | None) -> BaseException | None:
        """Always clean up and write the receipt; return the first failure."""

        if failure is not None:
            self.fail(failure)
        try:
            self.cleanup()
        except BaseException as error:
            self.report["cleanup_error_type"] = type(error).__name__
            failure = failure or error
        if failure is not None:
            self.report["status"] = "failed"
        self.receipt()
        return failure
