"""Owner-local stopped-tunnel convergence, using unchanged role mutation resources."""

import argparse
import base64
import grp
import hashlib
import json
import os
import platform
import plistlib
import pwd
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(argv, check=True, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, **kwargs)
    if check and result.returncode:
        raise RuntimeError("owner-local tunnel command failed")
    return result


def prepare(cfg):
    if platform.system() != "Darwin" or os.geteuid() == 0:
        raise RuntimeError("tunnel deployment requires its actual local non-root Darwin owner")
    account = pwd.getpwnam(cfg["owner"])
    if account.pw_uid != os.geteuid() or account.pw_dir != cfg["home"] or os.environ.get("HOME") != cfg["home"]:
        raise RuntimeError("tunnel deployment requires the configured actual owner and home")
    if cfg.get("expected_hostname") and socket.gethostname().split(".")[0] != cfg["expected_hostname"]:
        raise RuntimeError("tunnel deployment is on another workstation")
    cfg["domain"] = "gui/" + str(os.geteuid())
    cfg["service"] = cfg["domain"] + "/" + cfg["label"]
    if run(["/bin/launchctl", "print", cfg["domain"]], check=False).returncode:
        raise RuntimeError("tunnel deployment requires the owner's existing GUI launchd domain")
    plistlib.loads(cfg["contents"][cfg["plist"]].encode())
    return cfg


def loaded(cfg):
    return run(["/bin/launchctl", "print", cfg["service"]], check=False).returncode == 0


def disabled(cfg):
    out = run(["/bin/launchctl", "print-disabled", cfg["domain"]]).stdout
    return '"' + cfg["label"] + '" => disabled' in out


def identity(cfg):
    return probe_ns["probe_identity"](
        cfg["home"], cfg["identity"], os.geteuid(), cfg["identity_comment"], keygen=cfg["identity_keygen"],
        gid=grp.getgrnam(cfg["identity_group"]).gr_gid, allow_parent_mode_drift=True,
    )


def authorize(cfg, public, check):
    if cfg.get("relay_home") is None:
        return True
    line = 'restrict,port-forwarding,permitopen="' + cfg["target"] + ':' + str(cfg["target_port"]) + '",command="/usr/bin/false" ' + public + " " + cfg["identity_comment"]
    remote = shlex.join(["/usr/bin/python3", "-B", "-c", cfg["relay_script"]])
    result = run([
        "/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "UpdateHostKeys=no", "-o", "ControlMaster=no", "-o", "ControlPath=none",
        "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=" + cfg["known_hosts"],
        "-p", str(cfg["ssh_port"]), cfg["user"] + "@" + cfg["host"], remote,
    ], input=json.dumps({"home": cfg["relay_home"], "line": line, "comment": cfg["identity_comment"], "check": check}) + "\n")
    data = json.loads(result.stdout)
    return data["current"] if check else True


def file_metadata(path, mode):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
        raise RuntimeError("tunnel managed file has an unsafe type or owner")
    return stat.S_IMODE(info.st_mode) == mode


def directory_current(path, mode=None):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError("tunnel managed directory has an unsafe type or owner")
    return mode is None or stat.S_IMODE(info.st_mode) == mode


def mode_for(cfg, path):
    return 0o700 if path == str(Path(cfg["directory"]) / "tunnel_control.py") else 0o600


def current(cfg):
    if cfg["state"] == "absent":
        paths = list(cfg["contents"]) + [str(Path(cfg["directory"]) / "config.lock")]
        return disabled(cfg) and not loaded(cfg) and all(not os.path.lexists(p) for p in paths)
    if cfg["manage_identity"]:
        found = identity(cfg)
        if found["state"] != "current":
            return False
        if not authorize(cfg, found["public_key"], True):
            return False
    for path in [cfg["directory"], cfg["log_directory"]]:
        if not directory_current(path, 0o700):
            return False
    if not directory_current(str(Path(cfg["plist"]).parent)):
        return False
    for path, expected in cfg["hashes"].items():
        if not file_metadata(path, mode_for(cfg, path)) or hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
            return False
    return disabled(cfg) and not loaded(cfg)


def stop(cfg):
    if not disabled(cfg):
        run(["/bin/launchctl", "disable", cfg["service"]])
    was_loaded = loaded(cfg)
    if not was_loaded:
        return
    run(["/bin/launchctl", "bootout", cfg["service"]], check=False)
    for _ in range(100):
        if not loaded(cfg):
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("tunnel did not unload; managed files were retained")
    for _ in range(100):
        with socket.socket() as listener:
            listener.settimeout(0.1)
            if listener.connect_ex(("127.0.0.1", cfg["local_port"])) != 0:
                return
        time.sleep(0.1)
    raise RuntimeError("unloaded tunnel listener did not stop; managed files were retained")


def put(cfg, path, content):
    target = Path(path)
    mode = mode_for(cfg, path)
    if os.path.lexists(target):
        file_metadata(target, mode)
        if target.read_bytes() == content:
            if not file_metadata(target, mode):
                target.chmod(mode)
            return
    fd, temporary = tempfile.mkstemp(prefix=".ssh-tunnel-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        if target.name == "ssh_config":
            run(["/usr/bin/ssh", "-G", "-F", temporary, "managed-tunnel"])
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply(cfg):
    if cfg["state"] == "present" and cfg["manage_identity"]:
        found = identity(cfg)
        if found["state"] != "current":
            # The byte-identical role helper owns all actual key creation and
            # crash reconciliation. Never call it for an already-current key.
            result = ns["manage"](argparse.Namespace(
                state="present", home=cfg["home"], path=cfg["identity"], user=cfg["owner"],
                group=cfg["identity_group"], comment=cfg["identity_comment"], keygen=cfg["identity_keygen"], check=False,
            ))
            public = result["public_key"]
        else:
            public = found["public_key"]
        authorize(cfg, public, False)
    # Match the original ordering: authorization succeeds before the local
    # install-stopped transition. Relay outages do not stop the existing tunnel.
    stop(cfg)
    if cfg["state"] == "absent":
        for path in list(cfg["contents"]) + [str(Path(cfg["directory"]) / "config.lock")]:
            if os.path.lexists(path):
                file_metadata(path, mode_for(cfg, path))
                Path(path).unlink()
        return
    for path in [cfg["directory"], cfg["log_directory"]]:
        if not directory_current(path, 0o700):
            Path(path).mkdir(parents=True, exist_ok=True)
            Path(path).chmod(0o700)
    parent = str(Path(cfg["plist"]).parent)
    if not directory_current(parent):
        Path(parent).mkdir(parents=True, mode=0o755, exist_ok=True)
    for path, content in cfg["contents"].items():
        put(cfg, path, content.encode())


def main():
    cfg = prepare(json.loads(base64.b64decode(sys.argv[2])))
    action = sys.argv[1]
    if action == "status":
        print("current" if current(cfg) else "drift")
    elif action == "apply":
        apply(cfg)
    elif action == "verify":
        if not current(cfg):
            raise RuntimeError("owner-session stopped tunnel verification failed")
        print("Tunnel deployment is converged; automatic start remains disabled.")
    else:
        raise RuntimeError("unknown tunnel operation")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("owner-local tunnel deployment could not satisfy its identity/relay/stopped-state contract", file=sys.stderr)
        sys.exit(1)
