"""macOS publisher on the host: the ops-library ``software_estate_publisher`` role.

Run as ``/usr/bin/python3 -I -B -c <launcher> ACTION`` with the JSON request
on stdin (``deploy.py`` builds both). ACTION is ``status`` (prints
``current`` or ``pending``, changes nothing), ``apply`` (converges, prints
``changed`` or ``unchanged``) or ``verify`` (``status`` that fails unless
``current``).

The connecting user is either the owner (Atlas) or root (Studio). Every file
operation runs as the owner: as root, this program runs its file part again
in a child process with the owner's uid, gid and groups. launchctl runs as
the connecting user against the owner's ``gui/<uid>`` domain.

Files, modes and order are the role's: private 0700 directories, programs,
configuration and plist 0600, ``run`` 0700, ``~/Library/LaunchAgents`` 0755;
a missing writer is provisioned only when the request carries one and an
existing one is never replaced; without one (Studio) the credential must
already exist, and ``status`` and ``verify`` check it as ``publish.py --check``
reads it (private regular file of the owner, single link, at most 4096 bytes,
in a private directory of the owner); the installed configuration is validated
with ``publish.py --check`` (retried while it exits 75, the publisher's busy
lock) before the job is touched. A change of programs, configuration or plist,
or an unloaded job, disables, boots out, enables and bootstraps the job.
``state=absent`` disables and boots out the job and deletes only the plist:
programs, configuration, state, outbox and credentials stay.
"""

import base64
import hashlib
import json
import os
import platform
import plistlib
import pwd
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
# deploy.py's LAUNCHER; SOURCE is this program's text, set by the launcher.
LAUNCHER = (
    "import base64;S=base64.b64decode('%s').decode();"
    "exec(compile(S,'<software-estate-publisher>','exec'),{'__name__':'__main__','SOURCE':S})"
)


CREDENTIAL_UNUSABLE = "the credential %s is missing or not a private regular file of at most 4096 bytes"


class Refused(Exception):
    pass


def estate_run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, timeout=kwargs.pop("timeout", 60), **kwargs)


# ----------------------------------------------------------------- file part (owner)


def estate_require_safe(home, raw):
    """The role's path check: below home, no symlink, owner's, private, no hard links."""

    path = Path(raw)

    def estate_require(condition, reason):
        if not condition:
            raise Refused("unsafe path " + raw + ": " + reason)

    estate_require(path.is_absolute() and home in path.parents, "must be below current home")
    estate_require(".." not in path.parts, "parent traversal")
    estate_require(not any(p.is_symlink() for p in (path, *path.parents)), "symlink")
    if path.exists():
        info = path.stat()
        estate_require(info.st_uid == os.geteuid(), "different owner")
        estate_require(not info.st_mode & 0o077, "not private")
        estate_require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), "not a regular file or directory")
        if stat.S_ISREG(info.st_mode):
            estate_require(info.st_nlink == 1, "hard links")


def estate_checked_paths(data):
    program, release = data["program"], data["release"]
    credential = data["credential_file"] if data["state"] == "present" else program
    paths = [program, release, *(release + "/" + name for name in data["programs"])]
    paths += [data["directory"], data["directory"] + "/outbox", data["config"], data["plist"], program + "/run"]
    return paths + [str(Path(credential).parent) if data["state"] == "present" else program, credential]


def estate_directories(data):
    """Directories the role creates, in order, with their modes."""

    private = [data["program"], data["release"], data["directory"], data["directory"] + "/outbox"]
    return [(path, 0o700) for path in private]


def estate_file_mode(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    return info


def estate_digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def estate_files_current(data):
    home = Path(data["home"])
    for raw in estate_checked_paths(data):
        estate_require_safe(home, raw)
    if data["state"] == "absent":
        return estate_file_mode(data["plist"]) is None
    wanted = estate_directories(data) + [(data["launch_agents"], 0o755)]
    if data["provision_writer"]:
        wanted.append((str(Path(data["credential_file"]).parent), 0o700))
    for path, mode in wanted:
        info = estate_file_mode(path)
        if info is None or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != mode:
            return False
    for path, spec in data["files"].items():
        info = estate_file_mode(path)
        if info is None or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != spec["mode"]:
            return False
        if estate_digest(path) != spec["sha256"]:
            return False
    return estate_credential_ready(data)


def estate_credential_ready(data):
    """What ``publish.py --check`` reads: a private credential in a private parent.

    The writer is provisioned only when the request carries one; otherwise
    (Studio) the credential must already exist, so a missing one is never
    reported as current.
    """

    parent = estate_file_mode(str(Path(data["credential_file"]).parent))
    info = estate_file_mode(data["credential_file"])
    return (
        parent is not None
        and stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == os.geteuid()
        and not parent.st_mode & 0o077
        and info is not None
        and stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and not info.st_mode & 0o077
        and info.st_nlink == 1
        and info.st_size <= 4096
    )


def estate_ensure_directory(path, mode):
    """Ansible's ``file state=directory``: missing parents too, each with ``mode``."""

    missing = []
    current = Path(path)
    while estate_file_mode(str(current)) is None:
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        os.mkdir(str(directory), mode)
        os.chmod(str(directory), mode)
    info = estate_file_mode(path)
    if not stat.S_ISDIR(info.st_mode):
        raise Refused("not a directory: " + path)
    if stat.S_IMODE(info.st_mode) != mode:
        os.chmod(path, mode)


def estate_write(path, content, mode):
    """Replace ``path`` atomically when its bytes or mode differ; True if it changed."""

    body = content.encode()
    info = estate_file_mode(path)
    if info is not None and stat.S_IMODE(info.st_mode) == mode and estate_digest(path) == hashlib.sha256(body).hexdigest():
        return False
    descriptor, temporary = tempfile.mkstemp(dir=str(Path(path).parent), prefix=".estate-")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
        os.chmod(temporary, mode)
        if path.endswith(".plist"):
            plistlib.loads(body)
            if estate_run(["/usr/bin/plutil", "-lint", temporary]).returncode:
                raise Refused("plist does not pass plutil -lint")
        os.replace(temporary, path)
    except BaseException:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise
    return True


def estate_validate(data):
    """``publish.py --check`` as the job runs it; exit 75 (busy) is retried."""

    argv = [data["python"], data["release"] + "/publish.py", "--config", data["config"], "--check"]
    for attempt in range(61):
        result = estate_run(argv, timeout=300, env={"HOME": data["home"], "PATH": data["job_path"]})
        if result.returncode != 75:
            break
        if attempt < 60:
            time.sleep(5)
    if result.returncode:
        sys.stderr.write(result.stderr[-2000:])
        raise Refused("publish.py --check failed with exit status %d" % result.returncode)


def estate_files_apply(data):
    """The role's file tasks; returns whether programs, configuration or plist changed."""

    home = Path(data["home"])
    for raw in estate_checked_paths(data):
        estate_require_safe(home, raw)
    if data["state"] == "absent":
        return {"changed": False}
    for path, mode in estate_directories(data):
        estate_ensure_directory(path, mode)
    contents = data["contents"]
    changed = {"programs": False, "config": False, "plist": False, "other": False}
    for name in data["programs"]:
        path = data["release"] + "/" + name
        changed["programs"] = estate_write(path, contents[path], 0o600) or changed["programs"]
    writer = data.get("writer_value") or ""
    if data["provision_writer"]:
        if not writer:
            raise Refused("the writer to provision is missing")
        credential = data["credential_file"]
        estate_ensure_directory(str(Path(credential).parent), 0o700)
        if estate_file_mode(credential) is None:
            descriptor = os.open(credential, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(writer + "\n")
            changed["other"] = True
    changed["config"] = estate_write(data["config"], contents[data["config"]], 0o600)
    if not estate_credential_ready(data):
        raise Refused(CREDENTIAL_UNUSABLE % data["credential_file"])
    estate_validate(data)
    run_path = data["program"] + "/run"
    changed["other"] = estate_write(run_path, contents[run_path], 0o700) or changed["other"]
    estate_ensure_directory(data["launch_agents"], 0o755)
    changed["plist"] = estate_write(data["plist"], contents[data["plist"]], 0o600)
    return changed


def estate_remove_plist(data):
    estate_require_safe(Path(data["home"]), data["plist"])
    if estate_file_mode(data["plist"]) is None:
        return False
    os.unlink(data["plist"])
    return True


def estate_file_part(action, data):
    if action == "status":
        current = estate_files_current(data)
        return {"current": current, "credential": data["state"] == "absent" or estate_credential_ready(data)}
    if action == "apply":
        return estate_files_apply(data)
    if action == "remove-plist":
        return {"changed": estate_remove_plist(data)}
    raise Refused("unknown file action")


def estate_as_owner(action, data, account):
    """``file_part`` in a child running as the owner (the caller is root)."""

    request = json.dumps({"action": action, "data": data})
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", LAUNCHER % base64.b64encode(SOURCE.encode()).decode(), "file-part"],
        input=request,
        capture_output=True,
        text=True,
        timeout=3600,
        user=account.pw_uid,
        group=account.pw_gid,
        # No supplementary groups: macOS lists more than setgroups() takes,
        # and the owner's files need none.
        extra_groups=[],
        env={"HOME": account.pw_dir, "PATH": PATH, "USER": account.pw_name, "LOGNAME": account.pw_name},
        cwd=account.pw_dir,
    )
    if result.returncode:
        sys.stderr.write(result.stderr[-4000:])
        raise Refused("the owner's file step failed")
    return json.loads(result.stdout)


# ------------------------------------------------------------- launchd part (caller)


def estate_launchctl(*argv):
    return estate_run(["/bin/launchctl", *argv], timeout=30)


def estate_job(data):
    domain = "gui/" + str(data["uid"])
    return domain, domain + "/" + data["label"]


def estate_loaded(data):
    return estate_launchctl("print", estate_job(data)[1]).returncode == 0


def estate_disabled(data):
    result = estate_launchctl("print-disabled", estate_job(data)[0])
    if result.returncode:
        raise Refused("cannot read the owner's disabled launchd jobs")
    label = '"' + data["label"] + '" => '
    return label + "disabled" in result.stdout or label + "true" in result.stdout


def estate_require_domain(data):
    if estate_launchctl("print", estate_job(data)[0]).returncode:
        raise Refused("the owner's GUI launchd domain is not available")


def estate_stop(data):
    service = estate_job(data)[1]
    was_loaded = estate_loaded(data)
    if estate_launchctl("disable", service).returncode:
        raise Refused("launchctl disable failed")
    if was_loaded:
        estate_launchctl("bootout", service)
    for _ in range(15):
        if not estate_loaded(data):
            return
        time.sleep(1)
    raise Refused("the publisher job did not unload")


def estate_start(data):
    domain, service = estate_job(data)
    if estate_launchctl("enable", service).returncode:
        raise Refused("launchctl enable failed")
    result = estate_launchctl("bootstrap", domain, data["plist"])
    if result.returncode:
        raise Refused("launchctl bootstrap failed: " + result.stderr.strip()[-300:])


def estate_launchd_current(data):
    if data["state"] == "absent":
        return not estate_loaded(data) and estate_disabled(data)
    return estate_loaded(data) and not estate_disabled(data)


# ----------------------------------------------------------------------------- main


def estate_identity(data):
    if platform.system() != "Darwin":
        raise Refused("the macOS publisher needs a Darwin host")
    account = pwd.getpwnam(data["owner"])
    if account.pw_uid == 0 or account.pw_dir != data["home"]:
        raise Refused("the owner must be an unprivileged user with the configured home")
    if socket.gethostname().split(".")[0].lower() not in data["hostnames"]:
        raise Refused("this host is not one of the publisher's hostnames")
    euid = os.geteuid()
    if euid not in (0, account.pw_uid):
        raise Refused("connect as the owner or as root")
    data["uid"] = account.pw_uid
    return account, euid == 0


def estate_main(action):
    os.umask(0o077)
    data = json.loads(sys.stdin.read())
    account, root = estate_identity(data)

    def estate_files(step):
        return estate_as_owner(step, data, account) if root else estate_file_part(step, data)

    estate_require_domain(data)
    if action in ("status", "verify"):
        files = estate_files("status")
        current = files["current"] and estate_launchd_current(data)
        print("current" if current else "pending")
        if action == "verify" and not current:
            if not files["credential"]:
                raise Refused(CREDENTIAL_UNUSABLE % data["credential_file"])
            raise Refused("the publisher is not in its configured state")
        return
    if action != "apply":
        raise Refused("unknown action")
    if data["state"] == "absent":
        changed = not estate_launchd_current(data)
        estate_stop(data)
        changed = estate_files("remove-plist")["changed"] or changed
        print("changed" if changed else "unchanged")
        return
    was_loaded = estate_loaded(data)
    result = estate_files("apply")
    restart = result["programs"] or result["config"] or result["plist"] or not was_loaded
    if restart:
        estate_stop(data)
        estate_start(data)
    if estate_launchctl("enable", estate_job(data)[1]).returncode:
        raise Refused("launchctl enable failed")
    print("changed" if restart or result["other"] else "unchanged")


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["file-part"]:
            request = json.loads(sys.stdin.read())
            os.umask(0o077)
            print(json.dumps(estate_file_part(request["action"], request["data"])))
        else:
            estate_main(sys.argv[1])
    except Refused as error:
        sys.exit("software-estate-publisher: " + str(error))
