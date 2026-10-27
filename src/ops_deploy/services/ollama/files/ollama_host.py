"""Standalone macOS convergence; Python 3.9+, no imports from the controller.

Status and verify never create helpers, markers, temporary files or model data.
Only apply may mutate. No operation enumerates or changes model-store contents.
"""

import base64
import grp
import json
import os
import platform
import plistlib
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from xml.sax.saxutils import escape


def run(args, check=True, cwd=None):
    result = subprocess.run(args, text=True, capture_output=True, cwd=cwd)
    if check and result.returncode:
        raise RuntimeError("Ollama command failed: %s: %s" % (args[0], result.stderr.strip()))
    return result


def record(kind, name):
    result = run(["/usr/bin/dscl", "-plist", ".", "-read", "/%s/%s" % (kind, name)], check=False)
    if result.returncode:
        if "eDSRecordNotFound" in result.stderr:
            return None
        raise RuntimeError("Cannot inspect Ollama %s record" % kind)
    values = plistlib.loads(result.stdout.encode())
    return {key.rsplit(":", 1)[-1]: str(value[0]) for key, value in values.items() if value}


def hidden_users():
    path = Path("/Library/Preferences/com.apple.loginwindow.plist")
    if not path.exists():
        return []
    with path.open("rb") as handle:
        values = plistlib.load(handle).get("HiddenUsersList", [])
    if not isinstance(values, list):
        raise RuntimeError("HiddenUsersList is not an array")
    return values


def brew(cfg, *args, check=True):
    command = [
        "/usr/bin/sudo", "-H", "-u", cfg["brew_user"], "--", "/usr/bin/env",
        "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1", cfg["brew_bin"], *args,
    ]
    return run(command, check=check, cwd=pwd.getpwnam(cfg["brew_user"]).pw_dir)


def prepare(cfg):
    if platform.system() != "Darwin" or os.geteuid() != 0:
        raise RuntimeError("Ollama requires Darwin and the existing privileged connection")
    if not cfg.get("brew_user"):
        raise RuntimeError("Ollama brew_user is required for a privileged connection")
    pwd.getpwnam(cfg["brew_user"])
    if not cfg.get("brew_bin"):
        cfg["brew_bin"] = next((p for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if Path(p).is_file()), None)
    if not cfg["brew_bin"] or not os.access(cfg["brew_bin"], os.X_OK):
        raise RuntimeError("Ollama Homebrew executable is unavailable")
    prefix = brew(cfg, "--prefix").stdout.strip()
    if not prefix.startswith("/"):
        raise RuntimeError("Ollama Homebrew prefix is not absolute")
    binary = cfg.get("binary_path") or str(Path(prefix) / "bin/ollama")
    cfg["resolved_binary"] = binary
    cfg["plist"] = cfg["plist"].replace(
        "<string>__OPS_DEPLOY_OLLAMA_BINARY__</string>", "<string>%s</string>" % escape(binary), 1
    )
    expected = plistlib.loads(cfg["plist"].encode())
    if expected["Label"] != cfg["launchd_label"]:
        raise RuntimeError("Ollama plist label does not match configuration")
    cfg["expected_plist"] = cfg["plist"].encode()
    return cfg


def installed(cfg):
    result = brew(cfg, "list", "--versions", cfg["brew_package"], check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError("Cannot inspect Ollama Homebrew package")
    return bool(result.stdout.strip())


def brew_job(cfg):
    result = brew(cfg, "services", "info", cfg["brew_service_name"], "--json")
    entries = json.loads(result.stdout)
    return any(item.get("loaded") or item.get("running") or item.get("registered") for item in entries)


def foreign_processes(cfg):
    if not cfg["stop_conflicting_processes"]:
        return []
    result = run(["/usr/bin/pgrep", "-f", cfg["conflicting_process_pattern"]], check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError("Cannot inspect conflicting Ollama processes")
    found = []
    for value in result.stdout.split():
        pid = int(value)
        info = run(["/bin/ps", "-p", str(pid), "-o", "user=", "-o", "lstart=", "-o", "command="], check=False)
        if info.returncode == 0 and info.stdout.strip().split()[0] != cfg["user"]:
            found.append((pid, info.stdout))
    return found


def identity_current(cfg):
    user, group = record("Users", cfg["user"]), record("Groups", cfg["group"])
    if not cfg["manage_user"]:
        if not user or not user.get("UniqueID") or not group or not group.get("PrimaryGroupID"):
            raise RuntimeError("Unmanaged Ollama service user and group must already exist")
        return True
    if not user or not user.get("UniqueID") or not group or not group.get("PrimaryGroupID"):
        return False
    desired = {"NFSHomeDirectory": cfg["site_path"], "PrimaryGroupID": group["PrimaryGroupID"], "IsHidden": "1"}
    if cfg["uid"] is not None:
        desired["UniqueID"] = str(cfg["uid"])
    return (
        all(user.get(key) == value for key, value in desired.items())
        and (cfg["gid"] is None or group["PrimaryGroupID"] == str(cfg["gid"]))
    )


def next_id(kind, attribute, system=False):
    listed = run(["/usr/bin/dscl", ".", "-list", "/" + kind, attribute]).stdout
    ids = [int(line.split()[-1]) for line in listed.splitlines() if line.split() and line.split()[-1].lstrip("-").isdigit()]
    systems = [value for value in ids if 0 < value < 500]
    if system and systems and max(systems) < 499:
        return max(systems) + 1
    return max([500, *ids]) + 1


def ensure_identity(cfg):
    if not cfg["manage_user"]:
        identity_current(cfg)
        return
    group = record("Groups", cfg["group"])
    if group is None:
        args = ["/usr/sbin/dseditgroup", "-o", "create"]
        if cfg["gid"] is not None:
            args += ["-i", str(cfg["gid"])]
        run([*args, "-L", cfg["group"]])
    elif not group.get("PrimaryGroupID") or (cfg["gid"] is not None and group["PrimaryGroupID"] != str(cfg["gid"])):
        gid = cfg["gid"] if cfg["gid"] is not None else next_id("Groups", "PrimaryGroupID")
        run(["/usr/sbin/dseditgroup", "-o", "edit", "-i", str(gid), "-L", cfg["group"]])
    group = record("Groups", cfg["group"])
    user = record("Users", cfg["user"])
    incomplete = not user or not user.get("UniqueID") or not user.get("PrimaryGroupID")
    desired = {"NFSHomeDirectory": cfg["site_path"], "PrimaryGroupID": group["PrimaryGroupID"], "IsHidden": "1"}
    if cfg["uid"] is not None:
        desired["UniqueID"] = str(cfg["uid"])
    if cfg["uid"] is None and (not user or not user.get("UniqueID")):
        desired["UniqueID"] = str(next_id("Users", "UniqueID", system=True))
    if user is None:
        desired["RealName"] = cfg["user"]
        run(["/usr/bin/dscl", ".", "-create", "/Users/" + cfg["user"]])
        user = {}
    # Existing native IsHidden is authoritative; preserve existing preferences.
    # Do this before completing a new record: a failed addition leaves
    # an incomplete record that can be recovered on the next run.
    if incomplete and cfg["user"] not in hidden_users():
        run(["/usr/bin/defaults", "write", "/Library/Preferences/com.apple.loginwindow.plist",
             "HiddenUsersList", "-array-add", cfg["user"]])
    for key, value in desired.items():
        if user.get(key) != value:
            run(["/usr/bin/dscl", ".", "-create", "/Users/" + cfg["user"], key, value])


def directory_current(path, uid, gid, manage_owner):
    target = Path(path)
    if not target.is_dir():
        return False
    info = target.stat()
    return stat.S_IMODE(info.st_mode) == 0o750 and (not manage_owner or (info.st_uid, info.st_gid) == (uid, gid))


def directories(cfg, apply=False):
    user, group = record("Users", cfg["user"]), record("Groups", cfg["group"])
    if not user or not user.get("UniqueID") or not group or not group.get("PrimaryGroupID"):
        return False
    uid, gid = int(user["UniqueID"]), int(group["PrimaryGroupID"])
    current = True
    for path in dict.fromkeys((cfg["site_path"], cfg["models_dir"], cfg["log_dir"])):
        if directory_current(path, uid, gid, cfg["manage_user"]):
            continue
        current = False
        if apply:
            Path(path).mkdir(parents=True, exist_ok=True)
            if cfg["manage_user"]:
                os.chown(path, uid, gid)
            os.chmod(path, 0o750)
    return current


def plist_current(cfg):
    target = Path(cfg["launchd_plist_path"])
    if not target.exists():
        return False
    if target.is_symlink() or not target.is_file():
        raise RuntimeError("Ollama plist must be a regular file")
    info = target.stat()
    return target.read_bytes() == cfg["expected_plist"] and (
        info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)
    ) == (0, grp.getgrnam("wheel").gr_gid, 0o644)


def launchd(cfg):
    result = run(["/bin/launchctl", "print", "system/" + cfg["launchd_label"]], check=False)
    return result.returncode == 0, bool(re.search(r"^\s*state = running$", result.stdout, re.MULTILINE))


def unload(cfg):
    run(["/bin/launchctl", "bootout", "system/" + cfg["launchd_label"]], check=False)
    # bootout may report EINPROGRESS while launchd still owns the old job.
    # Bootstrap only once the old label is actually absent.
    for _ in range(30):
        if not launchd(cfg)[0]:
            return
        time.sleep(1)
    raise RuntimeError("Ollama launchd job did not unload before bootstrap")


def current(cfg):
    package = installed(cfg)
    # Evaluate all checks, including config files, before apply is selected.
    identities = identity_current(cfg)
    dirs = directories(cfg)
    plist = plist_current(cfg)
    loaded, running = launchd(cfg)
    foreign = foreign_processes(cfg)
    brew_running = package and cfg["disable_brew_service"] and brew_job(cfg)
    return package and not cfg["brew_update"] and identities and dirs and plist and loaded and running and not foreign and not brew_running


def publish_plist(cfg):
    target = Path(cfg["launchd_plist_path"])
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_bytes() == cfg["expected_plist"]:
        os.chown(target, 0, grp.getgrnam("wheel").gr_gid)
        os.chmod(target, 0o644)
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".ollama-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(cfg["expected_plist"])
            handle.flush()
            os.fsync(handle.fileno())
            os.fchown(handle.fileno(), 0, grp.getgrnam("wheel").gr_gid)
            os.fchmod(handle.fileno(), 0o644)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply(cfg):
    if cfg["brew_update"]:
        brew(cfg, "update")
    if not installed(cfg):
        brew(cfg, "install", cfg["brew_package"])
    if not os.access(cfg["resolved_binary"], os.X_OK):
        raise RuntimeError("Ollama executable is unavailable after package installation")
    if cfg["disable_brew_service"] and brew_job(cfg):
        brew(cfg, "services", "stop", cfg["brew_service_name"])
    for pid, observed in foreign_processes(cfg):
        again = run(["/bin/ps", "-p", str(pid), "-o", "user=", "-o", "lstart=", "-o", "command="], check=False)
        if again.returncode == 0 and again.stdout == observed:
            os.kill(pid, signal.SIGTERM)
    ensure_identity(cfg)
    directories(cfg, apply=True)
    changed = not plist_current(cfg)
    loaded, running = launchd(cfg)
    if changed:
        # Keep the old plist until unload completes. An unload failure must
        # remain detectable as content/metadata drift on the next deploy.
        unload(cfg)
        publish_plist(cfg)
    if changed or not loaded:
        run(["/bin/launchctl", "bootstrap", "system", cfg["launchd_plist_path"]])
        run(["/bin/launchctl", "enable", "system/" + cfg["launchd_label"]])
    if changed or not loaded or not running:
        run(["/bin/launchctl", "kickstart", "-k", "system/" + cfg["launchd_label"]])


def verify(cfg):
    for _ in range(30):
        if launchd(cfg) == (True, True):
            if not cfg.get("health_url"):
                return
            try:
                with urllib.request.urlopen(cfg["health_url"], timeout=3) as response:
                    if response.status == 200:
                        return
            except (OSError, ValueError):
                pass
        time.sleep(1)
    raise RuntimeError("Ollama did not reach launchd/HTTP readiness")


def main():
    action = sys.argv[1]
    cfg = prepare(json.loads(base64.b64decode(sys.argv[2])))
    if action == "status":
        print("current" if current(cfg) else "changed")
    elif action == "apply":
        apply(cfg)
    elif action == "verify":
        verify(cfg)
    else:
        raise ValueError("unknown Ollama operation")


if __name__ == "__main__":
    main()
