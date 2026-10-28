"""Pure local runtime observation; stdlib only, JSON stdin, bounded metadata out.

No application imports/CLI, Journal construction, HTTP, record-body reads,
signals, mkdir, config writes or launchctl mutation. All credential equality is
in memory; no static credential digest is emitted or used as an argument.
"""

import grp
import hashlib
import hmac
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import sys

MAX_FILE = 1024 * 1024
MAX_INPUT = 8 * 1024 * 1024
GIT_ENV = {"GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}


class ObservationError(RuntimeError):
    pass


def safe_file(path):
    target = pathlib.Path(path)
    if not target.is_absolute() or ".." in target.parts:
        raise ObservationError("runtime_observer_path_invalid")
    for parent in target.parents:
        if parent.is_symlink():
            raise ObservationError("runtime_observer_linked_parent")
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            raise ObservationError("runtime_observer_file_invalid")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(MAX_FILE + 1)
        if len(body) > MAX_FILE:
            raise ObservationError("runtime_observer_file_too_large")
        return info, body
    finally:
        os.close(fd)


def resource_current(resource):
    result = safe_file(resource["path"])
    if result is None:
        return False
    info, body = result
    return (
        info.st_uid == pwd.getpwnam(resource["owner"]).pw_uid
        and info.st_gid == grp.getgrnam(resource["group"]).gr_gid
        and stat.S_IMODE(info.st_mode) == resource["mode"]
        and hmac.compare_digest(body, resource["content"].encode())
    )


def store_count(path, user, group):
    root = pathlib.Path(path)
    for parent in (root, *root.parents):
        if parent.is_symlink():
            raise ObservationError("runtime_observer_store_linked")
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != pwd.getpwnam(user).pw_uid
        or info.st_gid != grp.getgrnam(group).gr_gid or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ObservationError("runtime_observer_store_invalid")
    with os.scandir(root) as entries:
        # Every JSON entry, including symlinks and dot names; no record is opened.
        return sum(entry.name.endswith(".json") for entry in entries)


class NativeProbes:
    def __init__(self, data):
        self.data = data
        self.account = pwd.getpwnam(data["user"])

    def run(self, argv, user=False, extra=None):
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": self.account.pw_dir,
               "PYTHONDONTWRITEBYTECODE": "1", **GIT_ENV, **(extra or {})}
        if user and os.geteuid() != self.account.pw_uid:
            # Preserve explicit command env across sudo env_reset. Metadata
            # executes directly, without login profiles or their stdout/side
            # effects. Absolute probes use a public cwd, independent of whether
            # the SSH login user can traverse the target user's home.
            argv = ["/usr/bin/sudo", "-n", "-H", "-u", self.data["user"], "--",
                    "/usr/bin/env", *[key + "=" + value for key, value in env.items()], *argv]
        try:
            return subprocess.run(argv, capture_output=True, env=env,
                                  cwd="/" if user else None, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise ObservationError("runtime_observer_probe_failed") from None

    def git(self, *arguments):
        result = self.run(["/usr/bin/git", "--no-optional-locks", "-C", self.data["checkout"], *arguments],
                          user=self.data["owner"] == "user")
        if result.returncode:
            raise ObservationError("runtime_observer_source_unavailable")
        return result.stdout

    def health(self):
        data = self.data
        label = "gui/" + str(self.account.pw_uid) + "/" + data["label"]
        loaded = self.run(["/bin/launchctl", "print", label])
        if loaded.returncode not in {0, 113}:
            raise ObservationError("runtime_observer_launchd_unavailable")
        if loaded.returncode == 113:
            return False, None
        # Raw launchctl output can contain environment values; never print it.
        listing = loaded.stdout.decode("utf-8", "replace")
        arguments = re.search(r"(?ms)^\s*arguments = \{\n(.*?)^\s*\}", listing)
        command_ok = arguments is not None and [line.strip() for line in arguments[1].splitlines() if line.strip()] == data["expected_argv"]
        pid = re.search(r"(?m)^\s*pid = ([1-9][0-9]*)\s*$", listing)
        serving = self.run(["/usr/bin/pgrep", "-u", data["user"], "-f", "[o]perations serve"])
        if serving.returncode not in {0, 1}:
            raise ObservationError("runtime_observer_supervisor_unavailable")
        session_ok = True
        if data["mode"] == "host":
            session = self.run([data["host_tmux"], "-L", data["host_socket"], "has-session", "-t", "=supervisor"],
                               user=True, extra={"TMUX_TMPDIR": data["host_tmpdir"]})
            session_ok = session.returncode == 0
        return command_ok and pid is not None and serving.returncode == 0 and session_ok, int(pid[1]) if pid else None

    def runtime_current(self):
        data = self.data
        if not pathlib.Path(data["python"]).is_file() or not pathlib.Path(data["uv_bin"]).is_file():
            return False
        environment = pathlib.Path(data["python"]).parent.parent
        if not (environment / "pyvenv.cfg").is_file():
            return False
        interpreter = self.run([data["python"], "-I", "-B", "-S", "-c",
            "import sys;v='%d.%d.%d'%sys.version_info[:3];"
            "raise SystemExit(0 if v==sys.argv[1] and '/uv/python/cpython-'+v+'-' in sys.base_prefix else 1)",
            data["python_version"]], user=True)
        if interpreter.returncode:
            return False
        return self.locked_environment_current()

    def locked_environment_current(self):
        data = self.data
        environment = pathlib.Path(data["python"]).parent.parent
        if not (environment / "pyvenv.cfg").is_file():
            return False
        # --check never synchronizes. Existing lock, no network/download/build;
        # native temporary cache I/O is distinct from service-managed changes.
        synced = self.run([data["uv_bin"], "--directory", data["checkout"], "sync", "--check", "--frozen",
            "--no-dev", "--offline", "--no-python-downloads", "--no-build", "--no-cache",
            "--python", data["python_version"]], user=True)
        return synced.returncode == 0


def observe(data, probes=None):
    probes = probes or NativeProbes(data)
    profile_file = safe_file(data["policy"])
    if profile_file is None:
        return {"installed": False, "enabled": False, "source_current": False, "resources_current": False,
                "healthy": False, "keeper_pid": None, "schema": None, "workers": None,
                "halt_entries": None, "delivery_entries": None}
    try:
        profile = json.loads(profile_file[1])
    except (ValueError, UnicodeError):
        raise ObservationError("runtime_observer_profile_invalid") from None
    if (
        not isinstance(profile, dict) or type(profile.get("schema")) is not int
        or type(profile.get("enabled")) is not bool or not isinstance(profile.get("workers"), dict)
        or set(profile["workers"]) != {"count", "long"}
        or any(type(profile["workers"][key]) is not int for key in ("count", "long"))
        or not 2 <= profile["workers"]["count"] <= 16
        or not 1 <= profile["workers"]["long"] < profile["workers"]["count"]
    ):
        raise ObservationError("runtime_observer_profile_invalid")
    if not profile["enabled"]:
        # Original disabled install needs no Aqua session or running keeper and
        # may not have created its source/store yet. Installation converges those
        # prerequisites; observing must not activate or repair anything here.
        return {"installed": True, "enabled": False, "source_current": False, "resources_current": False,
                "healthy": False, "keeper_pid": None, "schema": profile["schema"], "workers": profile["workers"],
                "halt_entries": None, "delivery_entries": None}
    expected = data["source_hashes"]
    if not expected or len(expected) > 2048:
        raise ObservationError("runtime_observer_source_manifest_invalid")
    current = probes.git("rev-parse", "HEAD").decode().strip() == data["revision"]
    current = not probes.git("status", "--porcelain", "--untracked-files=all").strip() and current
    root = pathlib.Path(data["checkout"])
    for relative, digest in expected.items():
        if (
            pathlib.PurePosixPath(relative).is_absolute() or ".." in pathlib.PurePosixPath(relative).parts
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ObservationError("runtime_observer_source_manifest_invalid")
        result = safe_file(root / relative)
        current = result is not None and hashlib.sha256(result[1]).hexdigest() == digest and current
    current = probes.runtime_current() and current
    if data["policy"] not in {resource["path"] for resource in data["resources"]}:
        raise ObservationError("runtime_observer_policy_resource_missing")
    resources = []
    for resource in data["resources"]:
        resource = dict(resource)
        if resource["path"] == data["policy"] and data.get("preserve_enabled"):
            expected_profile = json.loads(resource["content"])
            expected_profile["enabled"] = profile["enabled"]
            resource["content"] = json.dumps(expected_profile, indent=4, sort_keys=True, ensure_ascii=True) + "\n"
        resources.append(resource)
    resource_match = all(resource_current(resource) for resource in resources)
    store_count(data["journal"], data["user"], data["group"])
    halts = store_count(pathlib.Path(data["journal"]) / "halts", data["user"], data["group"])
    deliveries = store_count(pathlib.Path(data["journal"]) / "deliveries", data["user"], data["group"])
    healthy, pid = probes.health()
    return {"installed": True, "enabled": profile["enabled"], "source_current": current,
            "resources_current": resource_match, "healthy": healthy and halts == 0 and profile["enabled"] and profile["schema"] == 5,
            "keeper_pid": pid, "schema": profile["schema"], "workers": profile["workers"],
            "halt_entries": halts, "delivery_entries": deliveries}


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ObservationError("runtime_observer_request_too_large")
        data = json.loads(raw)
        result = observe(data)
        if len(sys.argv) > 1 and sys.argv[1] == "verify" and not all(result[key] for key in (
            "installed", "enabled", "source_current", "resources_current", "healthy"
        )):
            raise ObservationError("runtime_observer_not_current")
        print(json.dumps(result, sort_keys=True))
    except (KeyError, TypeError, ValueError, OSError, ObservationError):
        # No exception or raw child stdout/stderr/profile/credential body escapes.
        print("runtime_observer_failed", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
