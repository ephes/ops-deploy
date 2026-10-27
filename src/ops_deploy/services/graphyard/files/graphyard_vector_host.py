"""Standalone Darwin role convergence, Python3.9+. No credential output.

Status/verify create no helper/staging/marker files. Apply receives the private
fragment on stdin; buffer and log contents are never inspected or rewritten.
"""

import base64
import grp
import hashlib
import json
import os
import platform
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape


class Failure(RuntimeError):
    pass


def run(args, check=True, cwd=None):
    result = subprocess.run(args, text=True, capture_output=True, cwd=cwd)
    if check and result.returncode:
        # Vector can quote credentials in a validation error. Never forward
        # subprocess output, including failures, to controller logs.
        raise Failure("Graphyard Vector command failed: " + Path(args[0]).name)
    return result


def brew(cfg, *args, check=True):
    return run(["/usr/bin/sudo", "-H", "-u", cfg["brew_user"], "--", "/usr/bin/env", "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1", cfg["brew_bin"], *args], check=check, cwd=pwd.getpwnam(cfg["brew_user"]).pw_dir)


def prepare(cfg):
    if platform.system() != "Darwin" or os.geteuid() != 0:
        raise Failure("Graphyard Vector requires Darwin and the existing privileged connection")
    if not cfg.get("brew_user"):
        raise Failure("Graphyard Vector Homebrew owner is required")
    pwd.getpwnam(cfg["brew_user"])
    pwd.getpwnam(cfg["runtime_user"])
    grp.getgrnam(cfg["runtime_group"])
    if not cfg.get("brew_bin"):
        cfg["brew_bin"] = next((p for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if Path(p).is_file()), None)
    if not cfg["brew_bin"] or not os.access(cfg["brew_bin"], os.X_OK):
        raise Failure("Graphyard Vector Homebrew binary is unavailable")
    prefix = brew(cfg, "--prefix").stdout.strip()
    if not prefix.startswith("/"):
        raise Failure("Graphyard Vector Homebrew prefix is not absolute")
    cfg["resolved_binary"] = cfg.get("binary_path") or str(Path(prefix) / "bin/vector")
    cfg["plist_text"] = cfg["plist_template"].replace("<string>__GRAPHYARD_VECTOR_BINARY__</string>", "<string>" + escape(cfg["resolved_binary"]) + "</string>", 1)
    if plistlib.loads(cfg["plist_text"].encode())["Label"] != cfg["launchd_label"]:
        raise Failure("Graphyard Vector plist label mismatch")
    cfg["hashes"][cfg["launchd_plist_path"]] = hashlib.sha256(cfg["plist_text"].encode()).hexdigest()
    return cfg


def installed(cfg):
    result = brew(cfg, "list", "--versions", cfg["brew_package"], check=False)
    if result.returncode not in (0, 1):
        raise Failure("Cannot inspect Graphyard Vector package")
    return bool(result.stdout.strip())


def tap_present(cfg):
    return "vectordotdev/brew" in brew(cfg, "tap").stdout.splitlines()


def duplicate(cfg):
    if not cfg["disable_brew_service"]:
        return False
    entries = json.loads(brew(cfg, "services", "info", cfg["brew_service_name"], "--json").stdout)
    return any(item.get("loaded") or item.get("running") or item.get("registered") for item in entries)


def file_current(cfg, path):
    p = Path(path)
    if not p.exists():
        return False
    if p.is_symlink() or not p.is_file():
        raise Failure("Graphyard Vector managed configuration must be a regular file")
    s = p.stat()
    mode = 0o644 if path in (cfg["launchd_plist_path"], cfg["newsyslog_conf_path"]) else 0o640
    return (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (0, grp.getgrnam(cfg["runtime_group"] if mode == 0o640 else "wheel").gr_gid, mode) and hashlib.sha256(p.read_bytes()).hexdigest() == cfg["hashes"][path]


def directories(cfg, apply=False):
    current = True
    uid = pwd.getpwnam(cfg["runtime_user"]).pw_uid
    gid = grp.getgrnam(cfg["runtime_group"]).gr_gid
    for name, user, group, mode in ((cfg["data_dir"], uid, gid, 0o750), (cfg["config_dir"], 0, gid, 0o750), (cfg["log_dir"], 0, grp.getgrnam("wheel").gr_gid, 0o755)):
        path = Path(name)
        if path.is_dir():
            s = path.stat()
            if (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (user, group, mode):
                continue
        current = False
        if apply:
            path.mkdir(parents=True, exist_ok=True)
            os.chown(path, user, group)
            os.chmod(path, mode)
    return current


def job(cfg):
    result = run(["/bin/launchctl", "print", "system/" + cfg["launchd_label"]], check=False)
    return result.returncode == 0, bool(re.search(r"^\s*state = running$", result.stdout, re.M))


def current(cfg, requested_update=True):
    package = installed(cfg)
    files_match = all([file_current(cfg, path) for path in cfg["hashes"]])
    loaded, running = job(cfg)
    return package and tap_present(cfg) and not (requested_update and cfg["brew_update"]) and directories(cfg) and files_match and not os.path.lexists("/etc/vector/vector.yaml") and loaded and running and not (package and duplicate(cfg))


def publish(cfg, path, text):
    if file_current(cfg, path):
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = 0o644 if path in (cfg["launchd_plist_path"], cfg["newsyslog_conf_path"]) else 0o640
    gid = grp.getgrnam(cfg["runtime_group"] if mode == 0o640 else "wheel").gr_gid
    if target.exists() and target.read_bytes() == text.encode():
        os.chown(target, 0, gid)
        os.chmod(target, mode)
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".graphyard-vector-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(text.encode());output.flush();os.fsync(output.fileno())
            os.fchown(output.fileno(), 0, gid);os.fchmod(output.fileno(), mode)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate_candidate(cfg, contents):
    with tempfile.TemporaryDirectory(prefix="graphyard-vector-validate-") as directory:
        stage = Path(directory)
        for pattern in ("*.yaml", "*.yml", "*.toml", "*.json"):
            for path in Path(cfg["config_dir"]).glob(pattern):
                if path.is_file() and str(path) not in (cfg["config_path"], cfg["global_config_path"]):
                    copied = stage / path.name
                    shutil.copy2(path, copied)
                    os.chown(copied, 0, grp.getgrnam(cfg["validation_group"]).gr_gid)
                    os.chmod(copied, 0o640)
        for path in (cfg["config_path"], cfg["global_config_path"]):
            target = stage / Path(path).name
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            with os.fdopen(descriptor, "w") as output:
                output.write(contents[path])
            os.chown(target, 0, grp.getgrnam(cfg["validation_group"]).gr_gid)
        run([cfg["resolved_binary"], "validate", "--config-dir", directory])


def unload(cfg):
    run(["/bin/launchctl", "bootout", "system/" + cfg["launchd_label"]], check=False)
    for _ in range(30):
        if not job(cfg)[0]:
            return
        time.sleep(1)
    raise Failure("Graphyard Vector job did not unload; configuration retained")


def apply(cfg, payload):
    contents = payload["contents"]
    contents[cfg["launchd_plist_path"]] = cfg["plist_text"]
    if set(contents) != set(cfg["hashes"]) or any(hashlib.sha256(text.encode()).hexdigest() != cfg["hashes"][path] for path, text in contents.items()):
        raise Failure("Graphyard Vector candidate does not match requested hashes")
    if cfg["brew_update"]:
        brew(cfg, "update")
    if not tap_present(cfg):
        brew(cfg, "tap", "vectordotdev/brew")
    if not installed(cfg):
        brew(cfg, "install", cfg["brew_package"])
    if not os.access(cfg["resolved_binary"], os.X_OK):
        raise Failure("Graphyard Vector executable is unavailable")
    directories(cfg, apply=True)
    validate_candidate(cfg, contents)
    # A rejected candidate must not stop the only existing producer. The data
    # directory above is a validation prerequisite; service changes wait.
    if duplicate(cfg):
        brew(cfg, "services", "stop", cfg["brew_service_name"])
    plist_changed = not file_current(cfg, cfg["launchd_plist_path"])
    pipeline_changed = any(not file_current(cfg, p) for p in (cfg["config_path"], cfg["global_config_path"]))
    loaded, _ = job(cfg)
    if plist_changed and loaded:
        unload(cfg)
    for path, text in contents.items():
        publish(cfg, path, text)
    legacy = Path("/etc/vector/vector.yaml")
    if os.path.lexists(legacy):
        legacy.unlink()
    loaded, running = job(cfg)
    if not loaded:
        run(["/bin/launchctl", "bootstrap", "system", cfg["launchd_plist_path"]])
        run(["/bin/launchctl", "enable", "system/" + cfg["launchd_label"]])
    if plist_changed or pipeline_changed or not running:
        run(["/bin/launchctl", "kickstart", "-k", "system/" + cfg["launchd_label"]])


def main():
    cfg = prepare(json.loads(base64.b64decode(sys.argv[2])))
    action = sys.argv[1]
    if action == "status":
        print("current" if current(cfg) else "drift")
    elif action == "apply":
        apply(cfg, json.load(sys.stdin))
    elif action == "verify":
        for _ in range(20):
            if job(cfg)[1]:
                break
            time.sleep(1)
        if not current(cfg, requested_update=False):
            raise Failure("Graphyard Vector did not converge")
        run([cfg["resolved_binary"], "validate", "--config-dir", cfg["config_dir"]])
    else:
        raise Failure("Unknown Graphyard Vector operation")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, Failure) else "Graphyard Vector internal error: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
